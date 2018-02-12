import * as crypto from "crypto";
import * as dgram from "dgram";
import { dtls } from "node-dtls-client";
import * as nodeUrl from "url";
import { ContentFormats } from "./ContentFormats";
import { createDeferredPromise, DeferredPromise } from "./lib/DeferredPromise";
import { Origin } from "./lib/Origin";
import { SocketWrapper } from "./lib/SocketWrapper";
import { Message, MessageCode, MessageCodes, MessageType } from "./Message";
import { BinaryOption, BlockOption, findOption, NumericOption, Option, Options, StringOption } from "./Option";

// initialize debugging
import * as debugPackage from "debug";
import { logMessage } from "./lib/LogMessage";
const debug = debugPackage("node-coap-client");

// print version info
// tslint:disable-next-line:no-var-requires
const npmVersion = require("../package.json").version;
debug(`CoAP client version ${npmVersion}`);

export type RequestMethod = "get" | "post" | "put" | "delete";

/** Options to control CoAP requests */
export interface RequestOptions {
	/** Whether to keep the socket connection alive. Speeds up subsequent requests */
	keepAlive?: boolean;
	/** Whether we expect a confirmation of the request */
	confirmable?: boolean;
	/** Whether this message will be retransmitted on loss */
	retransmit?: boolean;
	/** The preferred block size of partial responses */
	preferredBlockSize?: number;
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

interface IPendingRequest {
	connection: ConnectionInfo;
	url: string;
	originalMessage: Message; // allows resending the message, includes token and message id
	retransmit: RetransmissionInfo;
	partialResponse?: Message;
	// either (request):
	promise: Promise<CoapResponse>;
	// or (observe)
	callback: (resp: CoapResponse) => void;
	keepAlive: boolean;
	observe: boolean;
	concurrency: number;
}
class PendingRequest implements IPendingRequest {

	constructor(initial?: IPendingRequest) {
		if (!initial) return;

		this.connection = initial.connection;
		this.url = initial.url;
		this.originalMessage = initial.originalMessage;
		this.retransmit = initial.retransmit;
		this.promise = initial.promise;
		this.callback = initial.callback;
		this.keepAlive = initial.keepAlive;
		this.observe = initial.observe;
		this._concurrency = initial.concurrency;
	}

	public connection: ConnectionInfo;
	public url: string;
	public originalMessage: Message; // allows resending the message, includes token and message id
	public partialResponse: Message; // allows buffering for block-wise message receipt
	public retransmit: RetransmissionInfo;
	// either (request):
	public promise: Promise<CoapResponse>;
	// or (observe)
	public callback: (resp: CoapResponse) => void;
	public keepAlive: boolean;
	public observe: boolean;

	private _concurrency: number;
	public set concurrency(value: number) {
		const changed = value !== this._concurrency;
		this._concurrency = value;
		if (changed) CoapClient.onConcurrencyChanged(this);
	}
	public get concurrency(): number {
		return this._concurrency;
	}

	public queueForRetransmission(): void {
		if (this.retransmit != null && typeof this.retransmit.action === "function") {
			this.retransmit.jsTimeout = setTimeout(this.retransmit.action, this.retransmit.timeout);
		}
	}
}

interface QueuedMessage {
	connection: ConnectionInfo;
	message: Message;
}

export interface SecurityParameters {
	psk: { [identity: string]: string };
	// TODO support more
}

interface RetransmissionInfo {
	jsTimeout: any;
	action: () => void;
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
/** How many concurrent messages are allowed. Should be 1 */
const MAX_CONCURRENCY = 1;

function incrementToken(token: Buffer): Buffer {
	const len = token.length;
	const ret = Buffer.alloc(len, token);
	for (let i = len - 1; i >= 0; i--) {
		if (ret[i] < 0xff) {
			ret[i]++;
			break;
		} else {
			ret[i] = 0;
			// continue with the next digit
		}
	}
	return ret;
}

function incrementMessageID(msgId: number): number {
	return (++msgId > 0xffff) ? 1 : msgId;
}

function validateBlockSize(size: number): boolean {
	// block size is represented as 2**(4 + X) where X is an integer from 0..6
	const exp = Math.log2(size) - 4;
	// is the exponent an integer?
	if (exp % 1 !== 0) return false;
	// is the exponent in the range of 0..6?
	if (exp < 0 || exp > 6) return false;
	return true;
}

/**
 * provides methods to access CoAP server resources
 */
export class CoapClient {
	private static connections = new Map</* origin: */ string, ConnectionInfo>();
	/** Queue of the connections waiting to be established, sorted by the origin */
	private static pendingConnections = new Map</* origin: */ string, DeferredPromise<ConnectionInfo>>();
	private static isConnecting: boolean = false;
	/** Table of all known security params, sorted by the hostname */
	private static dtlsParams = new Map</* hostname: */ string, SecurityParameters>();
	/** All pending requests, sorted by the token */
	private static pendingRequestsByToken = new Map</* token: */ string, PendingRequest>();
	private static pendingRequestsByMsgID = new Map</* msgId: */ number, PendingRequest>();
	private static pendingRequestsByUrl = new Map</* url: */ string, PendingRequest>();
	/** Queue of the messages waiting to be sent */
	private static sendQueue: QueuedMessage[] = [];
	/** Default values for request options */
	private static defaultRequestOptions: RequestOptions = {
		confirmable: true,
		keepAlive: true,
		retransmit: true,
		preferredBlockSize: null,
	};

	/**
	 * Sets the security params to be used for the given hostname
	 */
	public static setSecurityParams(hostname: string, params: SecurityParameters) {
		CoapClient.dtlsParams.set(hostname, params);
	}

	/**
	 * Sets the default options for requests
	 * @param defaults The default options to use for requests when no options are given
	 */
	public static setDefaultRequestOptions(defaults: RequestOptions): void {
		if (defaults.confirmable != null) this.defaultRequestOptions.confirmable = defaults.confirmable;
		if (defaults.keepAlive != null) this.defaultRequestOptions.keepAlive = defaults.keepAlive;
		if (defaults.retransmit != null) this.defaultRequestOptions.retransmit = defaults.retransmit;
		if (defaults.preferredBlockSize != null) {
			if (!validateBlockSize(defaults.preferredBlockSize)) {
				throw new Error(`${defaults.preferredBlockSize} is not a valid block size. The value must be a power of 2 between 16 and 1024`);
			}
			this.defaultRequestOptions.preferredBlockSize = defaults.preferredBlockSize;
		}
	}

	private static getRequestOptions(options?: RequestOptions): RequestOptions {
		// ensure we have options and set the default params
		options = options || {};
		if (options.confirmable == null) options.confirmable = this.defaultRequestOptions.confirmable;
		if (options.keepAlive == null) options.keepAlive = this.defaultRequestOptions.keepAlive;
		if (options.retransmit == null) options.retransmit = this.defaultRequestOptions.retransmit;
		if (options.preferredBlockSize == null) {
			options.preferredBlockSize = this.defaultRequestOptions.preferredBlockSize;
		} else {
			if (!validateBlockSize(options.preferredBlockSize)) {
				throw new Error(`${options.preferredBlockSize} is not a valid block size. The value must be a power of 2 between 16 and 1024`);
			}
		}
		return options;
	}

	/**
	 * Closes and forgets about connections, useful if DTLS session is reset on remote end
	 * @param originOrHostname - Origin (protocol://hostname:port) or Hostname to reset,
	 * omit to reset all connections
	 */
	public static reset(originOrHostname?: string | Origin) {
		debug(`reset(${originOrHostname || ""})`);
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

		// forget all pending requests matching the predicate
		for (const request of CoapClient.pendingRequestsByMsgID.values()) {
			// check if the request matches the predicate
			const originString = Origin.parse(request.url).toString();
			if (!predicate(originString)) continue;

			// and forget it if so
			if (request.promise != null) (request.promise as DeferredPromise<CoapResponse>).reject("CoapClient was reset");
			CoapClient.forgetRequest({ request });
		}
		debug(`${Object.keys(CoapClient.pendingRequestsByMsgID).length} pending requests remaining...`);

		// cancel all pending connections matching the predicate
		for (const [originString, connection] of CoapClient.pendingConnections) {
			if (!predicate(originString)) continue;

			connection.reject("CoapClient was reset");
			CoapClient.pendingConnections.delete(originString);
		}
		debug(`${Object.keys(CoapClient.pendingConnections).length} pending connections remaining...`);

		// forget all connections matching the predicate
		for (const [originString, connection] of CoapClient.connections) {
			if (!predicate(originString)) continue;

			debug(`closing connection to ${originString}`);
			if (connection.socket != null) {
				connection.socket.close();
			}
			CoapClient.connections.delete(originString);
		}
		debug(`${Object.keys(CoapClient.connections).length} active connections remaining...`);
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
		options = this.getRequestOptions(options);

		// retrieve or create the connection we're going to use
		const origin = Origin.fromUrl(url);
		const connection = await CoapClient.getConnection(origin);

		// find all the message parameters
		const type = options.confirmable ? MessageType.CON : MessageType.NON;
		const code = MessageCodes.request[method];
		const messageId = connection.lastMsgId = incrementMessageID(connection.lastMsgId);
		const token = connection.lastToken = incrementToken(connection.lastToken);
		payload = payload || Buffer.from([]);

		// create message options, be careful to order them by code, no sorting is implemented yet
		const msgOptions: Option[] = [];
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
		// [23] Block2 (preferred response block size)
		if (options.preferredBlockSize != null) {
			msgOptions.push(Options.Block2(0, true, options.preferredBlockSize));
		}

		// create the promise we're going to return
		const response = createDeferredPromise<CoapResponse>();

		// create the message we're going to send
		const message = CoapClient.createMessage(type, code, messageId, token, msgOptions, payload);

		// create the retransmission info
		let retransmit: RetransmissionInfo;
		if (options.retransmit && type === MessageType.CON) {
			retransmit = CoapClient.createRetransmissionInfo(messageId);
		}

		// remember the request
		const req = new PendingRequest({
			connection,
			url: urlToString(url), // normalizedUrl
			originalMessage: message,
			retransmit,
			keepAlive: options.keepAlive,
			callback: null,
			observe: false,
			promise: response,
			concurrency: 0,
		});
		// remember the request
		CoapClient.rememberRequest(req);

		// now send the message
		CoapClient.send(connection, message);

		return response;

	}

	/**
	 * Creates a RetransmissionInfo to use for retransmission of lost packets
	 * @param messageId The message id of the corresponding request
	 */
	private static createRetransmissionInfo(messageId: number): RetransmissionInfo {
		return {
			timeout: CoapClient.getRetransmissionInterval(),
			action: () => CoapClient.retransmit(messageId),
			jsTimeout: null,
			counter: 0,
		};
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
		let connection: ConnectionInfo;
		try {
			connection = await CoapClient.getConnection(target);
		} catch (e) {
			// we didn't even get a connection, so fail the ping
			return false;
		}

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
		const req = new PendingRequest({
			connection,
			url: originString,
			originalMessage: message,
			retransmit: null,
			keepAlive: true,
			callback: null,
			observe: false,
			promise: response,
			concurrency: 0,
		});
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
		CoapClient.send(request.connection, request.originalMessage, "immediate");
		// and increase the params
		request.retransmit.counter++;
		request.retransmit.timeout *= 2;
		request.queueForRetransmission();
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
	 * When the server responds with block-wise responses, this requests the next block.
	 * @param request The original request which resulted in a block-wise response
	 */
	private static requestNextBlock(request: PendingRequest) {
		const message = request.originalMessage;
		const connection = request.connection;

		// requests for the next block are a new message with a new message id
		const oldMsgID = message.messageId;
		message.messageId = connection.lastMsgId = incrementMessageID(connection.lastMsgId);
		// this means we have to update the dictionaries aswell, so the request is still found
		CoapClient.pendingRequestsByMsgID.set(message.messageId, request);
		CoapClient.pendingRequestsByMsgID.delete(oldMsgID);

		// even if the original request was an observe, the partial requests are not
		message.options = message.options.filter(o => o.name !== "Observe");

		// Change the Block2 option, so the server knows which block to send
		const block2Opt = findOption(message.options, "Block2") as BlockOption;
		block2Opt.isLastBlock = true; // not sure if that's necessary, but better be safe
		block2Opt.blockNumber++;

		// enable retransmission for this updated request
		request.retransmit = CoapClient.createRetransmissionInfo(message.messageId);
		// and enqueue it for sending
		CoapClient.send(connection, message, "high");
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
		options = this.getRequestOptions(options);

		// retrieve or create the connection we're going to use
		const origin = Origin.fromUrl(url);
		const connection = await CoapClient.getConnection(origin);

		// find all the message parameters
		const type = options.confirmable ? MessageType.CON : MessageType.NON;
		const code = MessageCodes.request[method];
		const messageId = connection.lastMsgId = incrementMessageID(connection.lastMsgId);
		const token = connection.lastToken = incrementToken(connection.lastToken);
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

		// In contrast to requests, we don't work with a deferred promise when observing
		// Instead, we invoke a callback for *every* response.

		// create the message we're going to send
		const message = CoapClient.createMessage(type, code, messageId, token, msgOptions, payload);

		// create the retransmission info
		let retransmit: RetransmissionInfo;
		if (options.retransmit && type === MessageType.CON) {
			retransmit = CoapClient.createRetransmissionInfo(messageId);
		}

		// remember the request
		const req = new PendingRequest({
			connection,
			url: urlToString(url), // normalizedUrl
			originalMessage: message,
			retransmit,
			keepAlive: options.keepAlive,
			callback,
			observe: true,
			promise: null,
			concurrency: 0,
		});
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
		logMessage(coapMsg);

		if (coapMsg.code.isEmpty()) {
			// ACK or RST
			// see if we have a request for this message id
			const request = CoapClient.findRequest({ msgID: coapMsg.messageId });
			if (request != null) {
				// reduce the request's concurrency, since it was handled on the server
				request.concurrency = 0;
				// handle the message
				switch (coapMsg.type) {
					case MessageType.ACK:
						debug(`received ACK for message 0x${coapMsg.messageId.toString(16)}, stopping retransmission...`);
						// the other party has received the message, stop resending
						CoapClient.stopRetransmission(request);
						break;

					case MessageType.RST:
						if (
							request.originalMessage.type === MessageType.CON &&
							request.originalMessage.code === MessageCodes.empty
						) { // this message was a ping (empty CON, answered by RST)
							// resolve the promise
							debug(`received response to ping with ID 0x${coapMsg.messageId.toString(16)}`);
							(request.promise as DeferredPromise<CoapResponse>).resolve();
						} else {
							// the other party doesn't know what to do with the request, forget it
							debug(`received RST for message 0x${coapMsg.messageId.toString(16)}, forgetting the request...`);
							CoapClient.forgetRequest({ request });
						}
						break;
				}
			}
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
						debug(`received ACK for message 0x${coapMsg.messageId.toString(16)}, stopping retransmission...`);
						CoapClient.stopRetransmission(request);
					}

					// parse options
					let contentFormat: ContentFormats = null;
					if (coapMsg.options && coapMsg.options.length) {
						// see if the response contains information about the content format
						const optCntFmt = findOption(coapMsg.options, "Content-Format");
						if (optCntFmt) contentFormat = (optCntFmt as NumericOption).value;
					}

					let responseIsComplete: boolean = true;
					if (coapMsg.isPartialMessage()) {
						// Check if we expect more blocks
						const blockOption = findOption(coapMsg.options, "Block2") as BlockOption; // we know this is != null
						// TODO: check for outdated partial responses

						// assemble the partial blocks
						if (request.partialResponse == null) {
							request.partialResponse = coapMsg;
						} else {
							// extend the stored buffer
							// TODO: we might have to check if we got the correct fragment
							request.partialResponse.payload = Buffer.concat([request.partialResponse.payload, coapMsg.payload]);
						}
						if (blockOption.isLastBlock) {
							// override the message payload with the assembled partial payload
							// so the full payload gets returned to the listeners
							coapMsg.payload = request.partialResponse.payload;
						} else {
							CoapClient.requestNextBlock(request);
							responseIsComplete = false;
						}
					}

					// Now that we have a response, also reduce the request's concurrency,
					// so other requests can be fired off
					if (coapMsg.type === MessageType.ACK) request.concurrency = 0;

					// while we only have a partial response, we cannot return it to the caller yet
					if (!responseIsComplete) return;

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
						debug(`sending ACK for message 0x${coapMsg.messageId.toString(16)}`);
						const ACK = CoapClient.createMessage(
							MessageType.ACK,
							MessageCodes.empty,
							coapMsg.messageId,
						);
						CoapClient.send(request.connection, ACK, "immediate");
					}

				} else { // request == null
					// no request found for this token, send RST so the server stops sending

					// try to find the connection that belongs to this origin
					const originString = origin.toString();
					if (CoapClient.connections.has(originString)) {
						const connection = CoapClient.connections.get(originString);

						// and send the reset
						debug(`sending RST for message 0x${coapMsg.messageId.toString(16)}`);
						const RST = CoapClient.createMessage(
							MessageType.RST,
							MessageCodes.empty,
							coapMsg.messageId,
						);
						CoapClient.send(connection, RST, "immediate");
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
	 * @param connection The connection to send the message on
	 * @param message The message to send
	 * @param highPriority Whether the message should be prioritized
	 */
	private static send(
		connection: ConnectionInfo,
		message: Message,
		priority: "normal" | "high" | "immediate" = "normal",
	): void {

		const request = CoapClient.findRequest({msgID: message.messageId});

		switch (priority) {
			case "immediate": {
				// Send high-prio messages immediately
				// This is for ACKs, RSTs and retransmissions
				debug(`sending high priority message 0x${message.messageId.toString(16)}`);
				CoapClient.doSend(connection, request, message);
				break;
			}
			case "normal": {
				// Put the message in the queue
				CoapClient.sendQueue.push({connection, message});
				debug(`added message to the send queue with normal priority, new length = ${CoapClient.sendQueue.length}`);
				break;
			}
			case "high": {
				// Put the message in the queue (in first position)
				// This is for subsequent requests to blockwise resources
				CoapClient.sendQueue.unshift({connection, message});
				debug(`added message to the send queue with high priority, new length = ${CoapClient.sendQueue.length}`);
				break;
			}
		}

		// start working it off now (maybe)
		CoapClient.workOffSendQueue();
	}
	/**
	 * Gets called whenever a request's concurrency has changed
	 * @param req The pending request whose concurrency has changed
	 * @internal
	 */
	public static onConcurrencyChanged(req: PendingRequest) {
		// only handle requests with a message (in case there's an edge case without a message)
		const message = req.originalMessage;
		if (message == null) return;
		// only handle requests we haven't forgotten yet
		if (!CoapClient.pendingRequestsByMsgID.has(message.messageId)) return;
		debug(`request 0x${message.messageId.toString(16)}: concurrency changed => ${req.concurrency}`);
		if (req.concurrency === 0) CoapClient.workOffSendQueue();
	}
	private static workOffSendQueue() {

		// check if there are messages to send
		if (CoapClient.sendQueue.length === 0) {
			debug(`workOffSendQueue > queue empty`);
			return;
		}

		// check if we may send a message now
		debug(`workOffSendQueue > concurrency = ${CoapClient.calculateConcurrency()} (MAX ${MAX_CONCURRENCY})`);
		if (CoapClient.calculateConcurrency() < MAX_CONCURRENCY) {
			// get the next message to send
			const { connection, message } = CoapClient.sendQueue.shift();
			debug(`concurrency low enough, sending message 0x${message.messageId.toString(16)}`);
			// update the request's concurrency (it's now being handled)
			const request = CoapClient.findRequest({ msgID: message.messageId });
			CoapClient.doSend(connection, request, message);
		}

		// to avoid any deadlocks we didn't think of, re-call this later
		setTimeout(CoapClient.workOffSendQueue, 1000);
	}

	/**
	 * Does the actual sending of a message and starts concurrency/retransmission handling
	 */
	private static doSend(
		connection: ConnectionInfo,
		request: PendingRequest,
		message: Message,
	): void {
		// handle concurrency/retransmission if neccessary
		if (request != null) {
			request.concurrency = 1;
			request.queueForRetransmission();
		}
		// send the message
		connection.socket.send(message.serialize(), connection.origin);
	}

	/** Calculates the current concurrency, i.e. how many parallel requests are being handled */
	private static calculateConcurrency(): number {
		return [...CoapClient.pendingRequestsByMsgID.values()]		// find all requests
			.map(req => req.concurrency)							// extract their concurrency
			.reduce((sum, item) => sum + item, 0)					// and sum it up
			;
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
		let tokenString: string = "";
		if (byToken && request.originalMessage.token != null) {
			tokenString = request.originalMessage.token.toString("hex");
			CoapClient.pendingRequestsByToken.set(tokenString, request);
		}
		if (byMsgID) {
			CoapClient.pendingRequestsByMsgID.set(request.originalMessage.messageId, request);
		}
		if (byUrl) {
			CoapClient.pendingRequestsByUrl.set(request.url, request);
		}
		debug(`remembering request: msgID=0x${request.originalMessage.messageId.toString(16)}, token=${tokenString}, url=${request.url}`);
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
		const request = which.request || CoapClient.findRequest(which);

		// none found, return
		if (request == null) return;

		let tokenString: string = "";
		if (request.originalMessage.token != null) {
			tokenString = request.originalMessage.token.toString("hex");
		}
		const msgID = request.originalMessage.messageId;

		debug(`forgetting request: token=${tokenString}; msgID=0x${msgID.toString(16)}`);

		// stop retransmission if neccessary
		CoapClient.stopRetransmission(request);

		// delete all references
		if (CoapClient.pendingRequestsByToken.has(tokenString)) {
			CoapClient.pendingRequestsByToken.delete(tokenString);
		}

		if (CoapClient.pendingRequestsByMsgID.has(msgID)) {
			CoapClient.pendingRequestsByMsgID.delete(msgID);
		}

		if (CoapClient.pendingRequestsByUrl.has(request.url)) {
			CoapClient.pendingRequestsByUrl.delete(request.url);
		}

		// Set concurrency to 0, so the send queue can continue
		request.concurrency = 0;

		// If this request doesn't have the keepAlive option,
		// close the connection if it was the last one with the same origin
		if (!request.keepAlive) {
			const origin = Origin.parse(request.url);
			const requestsOnOrigin: number = CoapClient.findRequestsByOrigin(origin).length;
			if (requestsOnOrigin === 0) {
				// this was the last request, close the connection
				CoapClient.reset(origin);
			}
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
			if (CoapClient.pendingRequestsByUrl.has(which.url)) {
				return CoapClient.pendingRequestsByUrl.get(which.url);
			}
		} else if (which.msgID != null) {
			if (CoapClient.pendingRequestsByMsgID.has(which.msgID)) {
				return CoapClient.pendingRequestsByMsgID.get(which.msgID);
			}
		} else if (which.token != null) {
			if (CoapClient.pendingRequestsByToken.has(which.token)) {
				return CoapClient.pendingRequestsByToken.get(which.token);
			}
		}

		return null;
	}

	/**
	 * Finds all pending requests of a given origin
	 */
	private static findRequestsByOrigin(origin: Origin): PendingRequest[] {
		const originString = origin.toString();
		return [...CoapClient.pendingRequestsByMsgID.values()]
			.filter((req: PendingRequest) => Origin.parse(req.url).toString() === originString)
			;
	}

	/**
	 * Tries to establish a connection to the given target. Returns true on success, false otherwise.
	 * @param target The target to connect to. Must be a string, NodeJS.Url or Origin and has to contain the protocol, host and port.
	 */
	public static async tryToConnect(target: string | nodeUrl.Url | Origin): Promise<boolean> {
		// parse/convert url
		if (typeof target === "string") {
			target = Origin.parse(target);
		} else if (!(target instanceof Origin)) { // is a nodeUrl
			target = Origin.fromUrl(target);
		}

		// retrieve or create the connection we're going to use
		try {
			await CoapClient.getConnection(target);
			return true;
		} catch (e) {
			debug(`tryToConnect(${target}) => failed with error: ${e}`);
			return false;
		}
	}

	/**
	 * Establishes a new or retrieves an existing connection to the given origin
	 * @param origin - The other party
	 */
	private static getConnection(origin: Origin): Promise<ConnectionInfo> {
		const originString = origin.toString();
		if (CoapClient.connections.has(originString)) {
			debug(`getConnection(${originString}) => found existing connection`);
			// return existing connection
			return Promise.resolve(CoapClient.connections.get(originString));
		} else if (CoapClient.pendingConnections.has(originString)) {
			debug(`getConnection(${originString}) => connection is pending`);
			// return the pending connection promise
			return CoapClient.pendingConnections.get(originString);
		} else {
			debug(`getConnection(${originString}) => establishing new connection`);
			// create a promise and start the connection queue
			const ret = createDeferredPromise<ConnectionInfo>();
			CoapClient.pendingConnections.set(originString, ret);
			setTimeout(CoapClient.workOffPendingConnections, 0);
			return ret;
		}
	}

	private static async workOffPendingConnections(): Promise<void> {

		if (CoapClient.pendingConnections.size === 0) {
			// no more pending connections, we're done
			CoapClient.isConnecting = false;
			return;
		} else if (CoapClient.isConnecting) {
			// we're already busy
			return;
		}
		CoapClient.isConnecting = true;

		// Get the connection to establish
		const originString = CoapClient.pendingConnections.keys().next().value as string;
		const origin = Origin.parse(originString);
		const promise = CoapClient.pendingConnections.get(originString);
		CoapClient.pendingConnections.delete(originString);

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
				if (i === maxTries) {
					promise.reject(e);
				}
			}
		}

		if (socket != null) {
			// add the event handler
			socket.on("message", CoapClient.onMessage.bind(CoapClient, originString));
			// initialize the connection params and remember them
			const ret = {
				origin,
				socket,
				lastMsgId: 0,
				lastToken: crypto.randomBytes(TOKEN_LENGTH),
			};
			CoapClient.connections.set(originString, ret);
			// and resolve the deferred promise
			promise.resolve(ret);
		}

		// continue working off the queue
		CoapClient.isConnecting = false;
		setTimeout(CoapClient.workOffPendingConnections, 0);
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
				if (!CoapClient.dtlsParams.has(origin.hostname)) {
					return Promise.reject(`No security parameters given for the resource at ${origin.toString()}`);
				}
				const dtlsOpts: dtls.Options = Object.assign(
					({
						type: "udp4",
						address: origin.hostname,
						port: origin.port,
					} as dtls.Options),
					CoapClient.dtlsParams.get(origin.hostname),
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
