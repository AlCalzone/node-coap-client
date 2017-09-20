import * as crypto from "crypto";
import * as debugPackage from "debug";
import * as dgram from "dgram";
import { dtls } from "node-dtls-client";
import * as nodeUrl from "url";
import { ContentFormats } from "./ContentFormats";
import { createDeferredPromise, DeferredPromise } from "./lib/DeferredPromise";
import { Origin } from "./lib/Origin";
import { SocketWrapper } from "./lib/SocketWrapper";
import { Message, MessageCode, MessageCodes, MessageType } from "./Message";
import { BinaryOption, NumericOption, Option, Options, StringOption } from "./Option";

// initialize debugging
const debug = debugPackage("node-coap-client");

export type RequestMethod = "get" | "post" | "put" | "delete";

/** Options to control CoAP requests */
export interface RequestOptions {
	/** Whether to keep the socket connection alive. Speeds up subsequent requests */
	keepAlive?: boolean;
	/** Whether we expect a confirmation of the request */
	confirmable?: boolean;
	/** Whether this message will be retransmitted on loss */
	retransmit?: boolean;
}

export interface CoapResponse {
	code: MessageCode;
	format: ContentFormats;
	payload?: Buffer;
}

function urlToString(url: nodeUrl.Url): string {
	return `${url.protocol}//${url.hostname}:${url.port}${url.pathname}`;
}

interface ConnectionInfo {
	origin: Origin;
	socket: SocketWrapper;
	lastToken: Buffer;
	lastMsgId: number;
}

interface PendingRequest {
	connection: ConnectionInfo;
	url: string;
	originalMessage: Message; // allows resending the message, includes token and message id
	retransmit: RetransmissionInfo;
	// either (request):
	promise: Promise<CoapResponse>;
	// or (observe)
	callback: (resp: CoapResponse) => void;
	keepAlive: boolean;
	observe: boolean;
}

export interface SecurityParameters {
	psk: { [identity: string]: string };
	// TODO support more
}

interface RetransmissionInfo {
	jsTimeout: any;
	timeout: number;
	counter: number;
}
// TODO: make configurable
const RETRANSMISSION_PARAMS = {
	ackTimeout: 2,
	ackRandomFactor: 1.5,
	maxRetransmit: 4,
};
const TOKEN_LENGTH = 4;

function incrementToken(token: Buffer): Buffer {
	const len = token.length;
	for (let i = len - 1; i >= 0; i--) {
		if (token[i] < 0xff) {
			token[i]++;
			break;
		} else {
			token[i] = 0;
			// continue with the next digit
		}
	}
	return token;
}

function incrementMessageID(msgId: number): number {
	return (++msgId > 0xffff) ? 1 : msgId;
}

function findOption(opts: Option[], name: string): Option {
	for (const opt of opts) {
		if (opt.name === name) return opt;
	}
}

function findOptions(opts: Option[], name: string): Option[] {
	return opts.filter(opt => opt.name === name);
}

/**
 * provides methods to access CoAP server resources
 */
export class CoapClient {

	/** Table of all open connections and their parameters, sorted by the origin "coap(s)://host:port" */
	private static connections: { [origin: string]: ConnectionInfo } = {};
	/** Table of all known security params, sorted by the hostname */
	private static dtlsParams: { [hostname: string]: SecurityParameters } = {};
	/** All pending requests, sorted by the token */
	private static pendingRequestsByToken: { [token: string]: PendingRequest } = {};
	private static pendingRequestsByMsgID: { [msgId: number]: PendingRequest } = {};
	private static pendingRequestsByUrl:   { [url: string]: PendingRequest } = {};

	/**
	 * Sets the security params to be used for the given hostname
	 */
	public static setSecurityParams(hostname: string, params: SecurityParameters) {
		CoapClient.dtlsParams[hostname] = params;
	}

	/**
	 * Closes and forgets about connections, useful if DTLS session is reset on remote end
	 * @param originOrHostname - Origin (protocol://hostname:port) or Hostname to reset,
	 * omit to reset all connections
	 */
	public static reset(originOrHostname?: string | Origin) {
		let predicate: (originString: string) => boolean;
		if (originOrHostname != null) {
			if (typeof originOrHostname === "string") {
				// we were given a hostname, forget the connection if the origin's hostname matches
				predicate = (originString: string) => Origin.parse(originString).hostname === originOrHostname;
			} else {
				// we were given an origin, forget the connection if its string representation matches
				const match = originOrHostname.toString();
				predicate = (originString: string) => originString === match;
			}
		} else {
			// we weren't given a filter, forget all connections
			predicate = (originString: string) => true;
		}

		for (const originString in CoapClient.connections) {
			if (!predicate(originString)) continue;

			if (CoapClient.connections[originString].socket) {
				CoapClient.connections[originString].socket.close();
			}
			delete CoapClient.connections[originString];
		}
	}

	/**
	 * Requests a CoAP resource
	 * @param url - The URL to be requested. Must start with coap:// or coaps://
	 * @param method - The request method to be used
	 * @param payload - The optional payload to be attached to the request
	 * @param options - Various options to control the request.
	 */
	public static async request(
		url: string | nodeUrl.Url,
		method: RequestMethod,
		payload?: Buffer,
		options?: RequestOptions,
	): Promise<CoapResponse> {

		// parse/convert url
		if (typeof url === "string") {
			url = nodeUrl.parse(url);
		}

		// ensure we have options and set the default params
		options = options || {};
		if (options.confirmable == null) options.confirmable = true;
		if (options.keepAlive == null) options.keepAlive = true;
		if (options.retransmit == null) options.retransmit = true;

		// retrieve or create the connection we're going to use
		const origin = Origin.fromUrl(url);
		const originString = origin.toString();
		const connection = await this.getConnection(origin);

		// find all the message parameters
		const type = options.confirmable ? MessageType.CON : MessageType.NON;
		const code = MessageCodes.request[method];
		const messageId = connection.lastMsgId = incrementMessageID(connection.lastMsgId);
		const token = connection.lastToken = incrementToken(connection.lastToken);
		const tokenString = token.toString("hex");
		payload = payload || Buffer.from([]);

		// create message options, be careful to order them by code, no sorting is implemented yet
		const msgOptions: Option[] = [];
		//// [6] observe or not?
		// msgOptions.push(Options.Observe(options.observe))
		// [11] path of the request
		let pathname = url.pathname || "";
		while (pathname.startsWith("/")) { pathname = pathname.slice(1); }
		while (pathname.endsWith("/")) { pathname = pathname.slice(0, -1); }
		const pathParts = pathname.split("/");
		msgOptions.push(
			...pathParts.map(part => Options.UriPath(part)),
		);
		// [12] content format
		msgOptions.push(Options.ContentFormat(ContentFormats.application_json));

		// create the promise we're going to return
		const response = createDeferredPromise<CoapResponse>();

		// create the message we're going to send
		const message = CoapClient.createMessage(type, code, messageId, token, msgOptions, payload);

		// create the retransmission info
		let retransmit: RetransmissionInfo;
		if (options.retransmit && type === MessageType.CON) {
			const timeout = CoapClient.getRetransmissionInterval();
			retransmit = {
				timeout,
				jsTimeout: setTimeout(() => CoapClient.retransmit(messageId), timeout),
				counter: 0,
			};
		}

		// remember the request
		const req: PendingRequest = {
			connection,
			url: urlToString(url), // normalizedUrl
			originalMessage: message,
			retransmit,
			keepAlive: options.keepAlive,
			callback: null,
			observe: false,
			promise: response,
		};
		// remember the request
		CoapClient.rememberRequest(req);

		// now send the message
		CoapClient.send(connection, message);

		return response;

	}

	/**
	 * Pings a CoAP endpoint to check if it is alive
	 * @param target - The target to be pinged. Must be a string, NodeJS.Url or Origin and has to contain the protocol, host and port.
	 * @param timeout - (optional) Timeout in ms, after which the ping is deemed unanswered. Default: 5000ms
	 */
	public static async ping(
		target: string | nodeUrl.Url | Origin,
		timeout: number = 5000,
	): Promise<boolean> {

		// parse/convert url
		if (typeof target === "string") {
			target = Origin.parse(target);
		} else if (!(target instanceof Origin)) { // is a nodeUrl
			target = Origin.fromUrl(target);
		}

		// retrieve or create the connection we're going to use
		const originString = target.toString();
		const connection = await this.getConnection(target);

		// create the promise we're going to return
		const response = createDeferredPromise<CoapResponse>();

		// create the message we're going to send.
		// An empty message with type CON equals a ping and provokes a RST from the server
		const messageId = connection.lastMsgId = incrementMessageID(connection.lastMsgId);
		const message = CoapClient.createMessage(
			MessageType.CON,
			MessageCodes.empty,
			messageId,
		);

		// remember the request
		const req: PendingRequest = {
			connection,
			url: originString,
			originalMessage: message,
			retransmit: null,
			keepAlive: true,
			callback: null,
			observe: false,
			promise: response,
		};
		// remember the request
		CoapClient.rememberRequest(req);

		// now send the message
		CoapClient.send(connection, message);
		// fail the ping after the timeout has passed
		const failTimeout = setTimeout(() => response.reject(), timeout);

		let success: boolean;
		try {
			// now wait for success or failure
			await response;
			success = true;
		} catch (e) {
			success = false;
		} finally {
			// cleanup
			clearTimeout(failTimeout);
			CoapClient.forgetRequest({request: req});
		}

		return success;
	}

	/**
	 * Re-Sends a message in case it got lost
	 * @param msgID
	 */
	private static retransmit(msgID: number) {
		// find the request with all the information
		const request = CoapClient.findRequest({ msgID });
		if (request == null || request.retransmit == null) return;

		// are we over the limit?
		if (request.retransmit.counter > RETRANSMISSION_PARAMS.maxRetransmit) {
			// if this is a one-time request, reject the response promise
			if (request.promise !== null) {
				(request.promise as DeferredPromise<CoapResponse>).reject(new Error("Retransmit counter exceeded"));
			}
			// then stop retransmitting and forget the request
			CoapClient.forgetRequest({ request });
			return;
		}

		debug(`retransmitting message ${msgID.toString(16)}, try #${request.retransmit.counter + 1}`);

		// resend the message
		CoapClient.send(request.connection, request.originalMessage);
		// and increase the params
		request.retransmit.counter++;
		request.retransmit.timeout *= 2;
		request.retransmit.jsTimeout = setTimeout(() => CoapClient.retransmit(msgID), request.retransmit.timeout);
	}
	private static getRetransmissionInterval(): number {
		return Math.round(1000 /*ms*/ * RETRANSMISSION_PARAMS.ackTimeout *
			(1 + Math.random() * (RETRANSMISSION_PARAMS.ackRandomFactor - 1)),
		);
	}
	private static stopRetransmission(request: PendingRequest) {
		if (request.retransmit == null) return;
		clearTimeout(request.retransmit.jsTimeout);
		request.retransmit = null;
	}

	/**
	 * Observes a CoAP resource
	 * @param url - The URL to be requested. Must start with coap:// or coaps://
	 * @param method - The request method to be used
	 * @param payload - The optional payload to be attached to the request
	 * @param options - Various options to control the request.
	 */
	public static async observe(
		url: string | nodeUrl.Url,
		method: RequestMethod,
		callback: (resp: CoapResponse) => void,
		payload?: Buffer,
		options?: RequestOptions,
	): Promise<void> {

		// parse/convert url
		if (typeof url === "string") {
			url = nodeUrl.parse(url);
		}

		// ensure we have options and set the default params
		options = options || {};
		if (options.confirmable == null) options.confirmable = true;
		if (options.keepAlive == null) options.keepAlive = true;
		if (options.retransmit == null) options.retransmit = true;

		// retrieve or create the connection we're going to use
		const origin = Origin.fromUrl(url);
		const originString = origin.toString();
		const connection = await this.getConnection(origin);

		// find all the message parameters
		const type = options.confirmable ? MessageType.CON : MessageType.NON;
		const code = MessageCodes.request[method];
		const messageId = connection.lastMsgId = incrementMessageID(connection.lastMsgId);
		const token = connection.lastToken = incrementToken(connection.lastToken);
		const tokenString = token.toString("hex");
		payload = payload || Buffer.from([]);

		// create message options, be careful to order them by code, no sorting is implemented yet
		const msgOptions: Option[] = [];
		// [6] observe?
		msgOptions.push(Options.Observe(true));
		// [11] path of the request
		let pathname = url.pathname || "";
		while (pathname.startsWith("/")) { pathname = pathname.slice(1); }
		while (pathname.endsWith("/")) { pathname = pathname.slice(0, -1); }
		const pathParts = pathname.split("/");
		msgOptions.push(
			...pathParts.map(part => Options.UriPath(part)),
		);
		// [12] content format
		msgOptions.push(Options.ContentFormat(ContentFormats.application_json));

		// create the promise we're going to return
		const response = createDeferredPromise<CoapResponse>();

		// create the message we're going to send
		const message = CoapClient.createMessage(type, code, messageId, token, msgOptions, payload);

		// create the retransmission info
		let retransmit: RetransmissionInfo;
		if (options.retransmit && type === MessageType.CON) {
			const timeout = CoapClient.getRetransmissionInterval();
			retransmit = {
				timeout,
				jsTimeout: setTimeout(() => CoapClient.retransmit(messageId), timeout),
				counter: 0,
			};
		}

		// remember the request
		const req: PendingRequest = {
			connection,
			url: urlToString(url), // normalizedUrl
			originalMessage: message,
			retransmit,
			keepAlive: options.keepAlive,
			callback,
			observe: true,
			promise: null,
		};
		// remember the request
		CoapClient.rememberRequest(req);

		// now send the message
		CoapClient.send(connection, message);

	}

	/**
	 * Stops observation of the given url
	 */
	public static stopObserving(url: string | nodeUrl.Url) {

		// parse/convert url
		if (typeof url === "string") {
			url = nodeUrl.parse(url);
		}

		// normalize the url
		const urlString = urlToString(url);
		// and forget the request if we have one remembered
		CoapClient.forgetRequest({ url: urlString });
	}

	private static onMessage(origin: string, message: Buffer, rinfo: dgram.RemoteInfo) {
		// parse the CoAP message
		const coapMsg = Message.parse(message);
		debug(`received message: ID=${coapMsg.messageId}${(coapMsg.token && coapMsg.token.length) ? (", token=" + coapMsg.token.toString("hex")) : ""}`);

		if (coapMsg.code.isEmpty()) {
			// ACK or RST
			// see if we have a request for this message id
			const request = CoapClient.findRequest({ msgID: coapMsg.messageId });
			if (request != null) {
				switch (coapMsg.type) {
					case MessageType.ACK:
						debug(`received ACK for ${coapMsg.messageId.toString(16)}, stopping retransmission...`);
						// the other party has received the message, stop resending
						CoapClient.stopRetransmission(request);
						break;

					case MessageType.RST:
						if (
							request.originalMessage.type === MessageType.CON &&
							request.originalMessage.code === MessageCodes.empty
						) { // this message was a ping (empty CON, answered by RST)
							// resolve the promise
							debug(`received response to ping ${coapMsg.messageId.toString(16)}`);
							(request.promise as DeferredPromise<CoapResponse>).resolve();
						} else {
							// the other party doesn't know what to do with the request, forget it
							debug(`received RST for ${coapMsg.messageId.toString(16)}, forgetting the request...`);
							CoapClient.forgetRequest({ request });
						}
						break;
				}
			}
			// TODO handle non-piggybacked messages
		} else if (coapMsg.code.isRequest()) {
			// we are a client implementation, we should not get requests
			// ignore them
		} else if (coapMsg.code.isResponse()) {
			// this is a response, find out what to do with it
			if (coapMsg.token && coapMsg.token.length) {
				// this message has a token, check which request it belongs to
				const tokenString = coapMsg.token.toString("hex");
				const request = CoapClient.findRequest({ token: tokenString });
				if (request) {

					// if the message is an acknowledgement, stop resending
					if (coapMsg.type === MessageType.ACK) {
						debug(`received ACK for ${coapMsg.messageId.toString(16)}, stopping retransmission...`);
						CoapClient.stopRetransmission(request);
					}

					// parse options
					let contentFormat: ContentFormats = null;
					if (coapMsg.options && coapMsg.options.length) {
						// see if the response contains information about the content format
						const optCntFmt = findOption(coapMsg.options, "Content-Format");
						if (optCntFmt) contentFormat = (optCntFmt as NumericOption).value;
					}

					// prepare the response
					const response: CoapResponse = {
						code: coapMsg.code,
						format: contentFormat,
						payload: coapMsg.payload,
					};

					if (request.observe) {
						// call the callback
						request.callback(response);
					} else {
						// resolve the promise
						(request.promise as DeferredPromise<CoapResponse>).resolve(response);
						// after handling one-time requests, delete the info about them
						CoapClient.forgetRequest({ request });
					}

					// also acknowledge the packet if neccessary
					if (coapMsg.type === MessageType.CON) {
						debug(`sending ACK for ${coapMsg.messageId.toString(16)}`);
						const ACK = CoapClient.createMessage(
							MessageType.ACK,
							MessageCodes.empty,
							coapMsg.messageId,
						);
						CoapClient.send(request.connection, ACK);
					}

				} else { // request == null
					// no request found for this token, send RST so the server stops sending

					// try to find the connection that belongs to this origin
					const originString = origin.toString();
					if (CoapClient.connections.hasOwnProperty(originString)) {
						const connection = CoapClient.connections[originString];

						// and send the reset
						debug(`sending RST for ${coapMsg.messageId.toString(16)}`);
						const RST = CoapClient.createMessage(
							MessageType.RST,
							MessageCodes.empty,
							coapMsg.messageId,
						);
						CoapClient.send(connection, RST);
					}
				} // request != null?
			} // (coapMsg.token && coapMsg.token.length)

		} // (coapMsg.code.isResponse())
	}

	/**
	 * Creates a message with the given parameters
	 * @param type
	 * @param code
	 * @param messageId
	 * @param token
	 * @param options
	 * @param payload
	 */
	private static createMessage(
		type: MessageType,
		code: MessageCode,
		messageId: number,
		token: Buffer = null,
		options: Option[] = [], // do we need this?
		payload: Buffer = null,
	): Message {
		return new Message(
			0x01,
			type, code, messageId, token, options, payload,
		);
	}

	/**
	 * Send a CoAP message to the given endpoint
	 * @param connection
	 */
	private static send(
		connection: ConnectionInfo,
		message: Message,
	): void {

		// send the message
		connection.socket.send(message.serialize(), connection.origin);

	}

	/**
	 * Remembers a request for resending lost messages and tracking responses and updates
	 * @param request
	 * @param byUrl
	 * @param byMsgID
	 * @param byToken
	 */
	private static rememberRequest(
		request: PendingRequest,
		byUrl: boolean = true,
		byMsgID: boolean = true,
		byToken: boolean = true,
	) {
		if (byToken) {
			const tokenString = request.originalMessage.token.toString("hex");
			debug(`remembering request with token ${tokenString}`);
			CoapClient.pendingRequestsByToken[tokenString] = request;
		}
		if (byMsgID) {
			CoapClient.pendingRequestsByMsgID[request.originalMessage.messageId] = request;
		}
		if (byUrl) {
			CoapClient.pendingRequestsByUrl[request.url] = request;
		}
	}

	/**
	 * Forgets a pending request
	 * @param request
	 * @param byUrl
	 * @param byMsgID
	 * @param byToken
	 */
	private static forgetRequest(
		which: {
			request?: PendingRequest,
			url?: string,
			msgID?: number,
			token?: string,
		}) {

		// find the request
		const request = CoapClient.findRequest(which);

		// none found, return
		if (request == null) return;

		debug(`forgetting request: token=${request.originalMessage.token.toString("hex")}; msgID=${request.originalMessage.messageId}`);

		// stop retransmission if neccessary
		CoapClient.stopRetransmission(request);

		// delete all references
		const tokenString = request.originalMessage.token.toString("hex");
		if (CoapClient.pendingRequestsByToken.hasOwnProperty(tokenString)) {
			delete CoapClient.pendingRequestsByToken[tokenString];
		}

		const msgID = request.originalMessage.messageId;
		if (CoapClient.pendingRequestsByMsgID.hasOwnProperty(msgID)) {
			delete CoapClient.pendingRequestsByMsgID[msgID];
		}

		if (CoapClient.pendingRequestsByUrl.hasOwnProperty(request.url)) {
			delete CoapClient.pendingRequestsByUrl[request.url];
		}
	}

	/**
	 * Finds a request we have remembered by one of its properties
	 * @param which
	 */
	private static findRequest(
		which: {
			url?: string,
			msgID?: number,
			token?: string,
		},
	): PendingRequest {

		if (which.url != null) {
			if (CoapClient.pendingRequestsByUrl.hasOwnProperty(which.url)) {
				return CoapClient.pendingRequestsByUrl[which.url];
			}
		} else if (which.msgID != null) {
			if (CoapClient.pendingRequestsByMsgID.hasOwnProperty(which.msgID)) {
				return CoapClient.pendingRequestsByMsgID[which.msgID];
			}
		} else if (which.token != null) {
			if (CoapClient.pendingRequestsByToken.hasOwnProperty(which.token)) {
				return CoapClient.pendingRequestsByToken[which.token];
			}
		}

		return null;
	}

	/**
	 * Establishes a new or retrieves an existing connection to the given origin
	 * @param origin - The other party
	 */
	private static async getConnection(origin: Origin): Promise<ConnectionInfo> {
		const originString = origin.toString();
		if (CoapClient.connections.hasOwnProperty(originString)) {
			// return existing connection
			return CoapClient.connections[originString];
		} else {
			// Try a few times to setup a working connection
			const maxTries = 3;
			let socket: SocketWrapper;
			for (let i = 1; i <= maxTries; i++) {
				try {
					socket = await CoapClient.getSocket(origin);
					break; // it worked
				} catch (e) {
					// if we are going to try again, ignore the error
					// else throw it
					if (i === maxTries) throw e;
				}
			}

			// add the event handler
			socket.on("message", CoapClient.onMessage.bind(CoapClient, originString));
			// initialize the connection params
			const ret = CoapClient.connections[originString] = {
				origin,
				socket,
				lastMsgId: 0,
				lastToken: crypto.randomBytes(TOKEN_LENGTH),
			};
			// and return it
			return ret;
		}
	}

	/**
	 * Establishes or retrieves a socket that can be used to send to and receive data from the given origin
	 * @param origin - The other party
	 */
	private static async getSocket(origin: Origin): Promise<SocketWrapper> {

		switch (origin.protocol) {
			case "coap:":
				// simply return a normal udp socket
				return Promise.resolve(new SocketWrapper(dgram.createSocket("udp4")));
			case "coaps:":
				// return a promise we resolve as soon as the connection is secured
				const ret = createDeferredPromise<SocketWrapper>();
				// try to find security parameters
				if (!CoapClient.dtlsParams.hasOwnProperty(origin.hostname)) {
					return Promise.reject(`No security parameters given for the resource at ${origin.toString()}`);
				}
				const dtlsOpts: dtls.Options = Object.assign(
					({
						type: "udp4",
						address: origin.hostname,
						port: origin.port,
					} as dtls.Options),
					CoapClient.dtlsParams[origin.hostname],
				);
				// try connecting
				const onConnection = () => {
					debug("successfully created socket for origin " + origin.toString());
					sock.removeListener("error", onError);
					ret.resolve(new SocketWrapper(sock));
				};
				const onError = (e: Error) => {
					debug("socket creation for origin " + origin.toString() + " failed: " + e);
					sock.removeListener("connected", onConnection);
					ret.reject(e.message);
				};
				const sock = dtls
					.createSocket(dtlsOpts)
					.once("connected", onConnection)
					.once("error", onError)
					;
				return ret;
			default:
				throw new Error(`protocol type "${origin.protocol}" is not supported`);
		}

	}

}
