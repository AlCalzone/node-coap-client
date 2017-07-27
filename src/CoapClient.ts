import { dtls } from "node-dtls-client";
import * as dgram from "dgram";
import { MessageType, MessageCode, MessageCodes, Message } from "./Message";
import { Option, Options, NumericOption, StringOption, BinaryOption } from "./Option";
import { ContentFormats } from "./ContentFormats";
import * as nodeUrl from "url";
import * as crypto from "crypto";
import { createDeferredPromise, DeferredPromise } from "./lib/DeferredPromise";
import { SocketWrapper } from "./lib/SocketWrapper";
import { Origin } from "./lib/Origin";

export type RequestMethod = "get" | "post" | "put" | "delete";

/** Options to control CoAP requests */
export interface RequestOptions {
    /** Whether to keep the socket connection alive. Speeds up subsequent requests */
    keepAlive?: boolean
    /** Whether we expect a confirmation of the request */
    confirmable?: boolean
}

export interface CoapResponse {
	code: MessageCode,
	format: ContentFormats
    payload?: Buffer
}


function urlToString(url: nodeUrl.Url): string {
	return `${url.protocol}//${url.hostname}:${url.port}${url.pathname}`;
}

interface ConnectionInfo {
	origin: Origin,
	socket: SocketWrapper,
	lastToken: Buffer,
	lastMsgId: number
}

interface PendingRequest {
	//origin: string, //obsolete: contained in connection
	connection: ConnectionInfo,
	url: string,
	originalMessage: Message, // allows resending the message, includes token and message id
	retransmit: RetransmissionInfo,
	//token: Buffer,
	// either (request):
	promise: Promise<CoapResponse>,
	// or (observe)
	callback: (resp: CoapResponse) => void,
	keepAlive: boolean,
	observe: boolean,
}

export interface SecurityParameters {
	psk: { [identity: string]: string }
	// TODO support more
}

interface RetransmissionInfo {
	jsTimeout: any,
	timeout: number,
	counter: number
}
// TODO: make configurable
const RetransmissionParams = {
	ackTimeout: 2,
	ackRandomFactor: 1.5,
	maxRetransmit: 4
};

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
	for (let opt of opts) {
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
	static setSecurityParams(hostname: string, params: SecurityParameters) {
		CoapClient.dtlsParams[hostname] = params;
	}

    /**
     * Requests a CoAP resource 
     * @param url - The URL to be requested. Must start with coap:// or coaps://
     * @param method - The request method to be used
     * @param payload - The optional payload to be attached to the request
     * @param options - Various options to control the request.
     */
    static async request(
        url: string | nodeUrl.Url, 
        method: RequestMethod,
        payload?: Buffer, 
        options?: RequestOptions
    ): Promise<CoapResponse> {

		// parse/convert url
		if (typeof url === "string") {
			url = nodeUrl.parse(url);
		}

		// ensure we have options and set the default params
		options = options || {};
		options.confirmable = options.confirmable || true;
		options.keepAlive = options.keepAlive || true;

		// retrieve or create the connection we're going to use
		const
			origin = Origin.fromUrl(url),
			originString = origin.toString()
			;
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
		//msgOptions.push(Options.Observe(options.observe))
		// [11] path of the request
		let pathname = url.pathname || "";
		while (pathname.startsWith("/")) { pathname = pathname.slice(1); }
		while (pathname.endsWith("/")) { pathname = pathname.slice(0, -1); }
		const pathParts = pathname.split("/");
		msgOptions.push(
			...pathParts.map(part => Options.UriPath(part))
		);
		// [12] content format
		msgOptions.push(Options.ContentFormat(ContentFormats.application_json));

		// create the promise we're going to return
		const response = createDeferredPromise<CoapResponse>();

		// create the message we're going to send
		const message = CoapClient.createMessage(type, code, messageId, token, msgOptions, payload);

		// create the retransmission info
		let retransmit: RetransmissionInfo;
		if (type === MessageType.CON) {
			const timeout = CoapClient.getRetransmissionInterval();
			retransmit = {
				timeout,
				jsTimeout: setTimeout(() => CoapClient.retransmit(messageId), timeout),
				counter: 0
			}
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
			promise: response
		}
		// remember the request
		CoapClient.rememberRequest(req);

		// now send the message
		CoapClient.send(connection, message);

		return response;
		
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
		if (request.retransmit.counter > RetransmissionParams.maxRetransmit) {
			// then stop retransmitting and forget the request
			CoapClient.forgetRequest({ request });
			return;
		}

		console.log(`retransmitting message ${msgID.toString(16)}, try #${request.retransmit.counter + 1}`);

		// resend the message
		CoapClient.send(request.connection, request.originalMessage);
		// and increase the params
		request.retransmit.counter++;
		request.retransmit.timeout *= 2;
		request.retransmit.jsTimeout = setTimeout(() => CoapClient.retransmit(msgID), request.retransmit.timeout);
	}
	private static getRetransmissionInterval(): number {
		return Math.round(1000 /*ms*/ * RetransmissionParams.ackTimeout *
			(1 + Math.random() * (RetransmissionParams.ackRandomFactor - 1))
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
	static async observe(
		url: string | nodeUrl.Url,
		method: RequestMethod,
		callback: (resp: CoapResponse) => void,
		payload?: Buffer,
		options?: RequestOptions
	): Promise<void> {

		// parse/convert url
		if (typeof url === "string") {
			url = nodeUrl.parse(url);
		}

		// ensure we have options and set the default params
		options = options || {};
		options.confirmable = options.confirmable || true;
		options.keepAlive = options.keepAlive || true;

		// retrieve or create the connection we're going to use
		const
			origin = Origin.fromUrl(url),
			originString = origin.toString()
			;
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
		msgOptions.push(Options.Observe(true))
		// [11] path of the request
		let pathname = url.pathname || "";
		while (pathname.startsWith("/")) { pathname = pathname.slice(1); }
		while (pathname.endsWith("/")) { pathname = pathname.slice(0, -1); }
		const pathParts = pathname.split("/");
		msgOptions.push(
			...pathParts.map(part => Options.UriPath(part))
		);
		// [12] content format
		msgOptions.push(Options.ContentFormat(ContentFormats.application_json));

		// create the promise we're going to return
		const response = createDeferredPromise<CoapResponse>();

		// create the message we're going to send
		const message = CoapClient.createMessage(type, code, messageId, token, msgOptions, payload);

		// create the retransmission info
		let retransmit: RetransmissionInfo;
		if (type === MessageType.CON) {
			const timeout = CoapClient.getRetransmissionInterval();
			retransmit = {
				timeout,
				jsTimeout: setTimeout(() => CoapClient.retransmit(messageId), timeout),
				counter: 0
			}
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
			promise: null
		}
		// remember the request
		CoapClient.rememberRequest(req);

		// now send the message
		CoapClient.send(connection, message);

	}

	/**
	 * Stops observation of the given url
	 */
	static stopObserving(url: string | nodeUrl.Url) {

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
		console.log(`received message: ID=${coapMsg.messageId}${(coapMsg.token && coapMsg.token.length) ? (", token=" + coapMsg.token.toString("hex")) : ""}`);

		if (coapMsg.code.isEmpty()) {
			// ACK or RST 
			// see if we have a request for this message id
			const request = CoapClient.findRequest({ msgID: coapMsg.messageId });
			if (request != null) {
				switch (coapMsg.type) {
					case MessageType.ACK:
						console.log(`received ACK for ${coapMsg.messageId.toString(16)}, stopping retransmission...`);
						// the other party has received the message, stop resending
						CoapClient.stopRetransmission(request);
						break;
					case MessageType.RST:
						// the other party doesn't know what to do with the request, forget it
						console.log(`received RST for ${coapMsg.messageId.toString(16)}, forgetting the request...`);
						CoapClient.forgetRequest({ request });
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
						console.log(`received ACK for ${coapMsg.messageId.toString(16)}, stopping retransmission...`);
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
						payload: coapMsg.payload
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
						console.log(`sending ACK for ${coapMsg.messageId.toString(16)}`)
						const ACK = CoapClient.createMessage(
							MessageType.ACK,
							MessageCodes.empty,
							coapMsg.messageId
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
						console.log(`sending RST for ${coapMsg.messageId.toString(16)}`)
						const RST = CoapClient.createMessage(
							MessageType.RST,
							MessageCodes.empty,
							coapMsg.messageId
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
        payload: Buffer = null
	): Message {
		return new Message(
			0x01,
			type, code, messageId, token, options, payload
		);
	}

    /**
     * Send a CoAP message to the given endpoint
     * @param connection 
     */
    private static send(
		connection: ConnectionInfo,
		message: Message
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
		byToken: boolean = true
	) {
		if (byToken) {
			const tokenString = request.originalMessage.token.toString("hex");
			console.log(`remembering request with token ${tokenString}`);
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
			token?: string
		}) {

		// find the request
		const request = CoapClient.findRequest(which);

		// none found, return
		if (request == null) return;

		console.log(`forgetting request: token=${request.originalMessage.token.toString("hex")}; msgID=${request.originalMessage.messageId}`);

		// stop retransmission if neccessary
		CoapClient.stopRetransmission(request);

		// delete all references
		const tokenString = request.originalMessage.token.toString("hex");
		if (CoapClient.pendingRequestsByToken.hasOwnProperty(tokenString))
			delete CoapClient.pendingRequestsByToken[tokenString];

		const msgID = request.originalMessage.messageId;
		if (CoapClient.pendingRequestsByMsgID.hasOwnProperty(msgID))
			delete CoapClient.pendingRequestsByMsgID[msgID];

		if (CoapClient.pendingRequestsByUrl.hasOwnProperty(request.url))
			delete CoapClient.pendingRequestsByUrl[request.url];
	}

	/**
	 * Finds a request we have remembered by one of its properties
	 * @param which
	 */
	private static findRequest(
		which: {
			url?: string,
			msgID?: number,
			token?: string
		}
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
			// create new socket
			const socket = await CoapClient.getSocket(origin);
			// add the event handler
			socket.on("message", CoapClient.onMessage.bind(CoapClient, originString));
			// initialize the connection params
			const ret = CoapClient.connections[originString] = {
				origin,
				socket, 
				lastMsgId: 0,
				lastToken: crypto.randomBytes(4)
			}
			// and return it
			return ret;
		}
	}

    /**
     * Establishes or retrieves a socket that can be used to send to and receive data from the given origin
     * @param origin - The other party
     */
	private static getSocket(origin: Origin): Promise<SocketWrapper> {

		switch (origin.protocol) {
			case "coap:":
				// simply return a normal udp socket
				return Promise.resolve(new SocketWrapper(dgram.createSocket("udp4")));
			case "coaps:":
				// return a promise we resolve as soon as the connection is secured
				const ret = createDeferredPromise<SocketWrapper>();
				// try to find security parameters
				if (!CoapClient.dtlsParams.hasOwnProperty(origin.hostname))
					return Promise.reject(`No security parameters given for the resource at ${origin.toString()}`);
				const dtlsOpts: dtls.Options = Object.assign(
					({
						type: "udp4",
						address: origin.hostname,
						port: origin.port,
					} as dtls.Options),
					CoapClient.dtlsParams[origin.hostname]
				);
				// try connecting
				const sock = dtls
					.createSocket(dtlsOpts)
					.on("connected", () => ret.resolve(new SocketWrapper(sock)))
					.on("error", (e: Error) => ret.reject(e.message))
					;
				return ret;
			default:
				throw new Error(`protocol type "${origin.protocol}" is not supported`);
		}

    }

}