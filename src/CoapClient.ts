import { EventEmitter } from "events";
import { dtls } from "node-dtls-client";
import * as dgram from "dgram";
import { MessageType, MessageCode, MessageCodes, Message } from "./Message";
import { Option, Options, NumericOption, StringOption, BinaryOption } from "./Option";
import { ContentFormats } from "./ContentFormats";
import * as nodeUrl from "url";
import * as crypto from "crypto";
import { createDeferredPromise, DeferredPromise } from "./lib/DeferredPromise";


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

/**
 * Identifies another endpoint (similar to the new WhatWG URL API "origin" property)
 */
class Origin {
	constructor(
		public protocol: string,
		public hostname: string,
		public port: number
	) {}

	public toString(): string {
		return `${this.protocol}//${this.hostname}:${this.port}`;
	}

	static fromUrl(url: nodeUrl.Url): Origin {
		return new Origin(url.protocol, url.hostname, +url.port);
	}
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
	origin: string,
	token: Buffer,
	promise: Promise<CoapResponse>,
	callback: (resp: CoapResponse) => void,
	keepAlive: boolean,
	observe: boolean
}

class SocketWrapper extends EventEmitter {

	private isDtls: boolean;

	constructor(public socket: dtls.Socket | dgram.Socket) {
		super();
		this.isDtls = (socket instanceof dtls.Socket);
		(socket as any).on("message", (message: Buffer, rinfo: dgram.RemoteInfo) => {
			console.log(`got a message: ${message.toString("hex")}`);
			this.emit("message", message, rinfo);
		});
	}


	send(msg: Buffer, origin: Origin) {
		if (this.isDtls) {
			(this.socket as dtls.Socket).send(msg);
		} else {
			(this.socket as dgram.Socket).send(msg, origin.port, origin.hostname);
		}
	}

    close(): void {
		if (this.isDtls) {
			(this.socket as dtls.Socket).close();
		} else {
			(this.socket as dgram.Socket).close();
		}
    }
}

export interface SecurityParameters {
	psk: { [identity: string]: string }
	// TODO support more
}

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
	return (++msgId > 0xffff) ? msgId : 1;
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
	private static pendingRequests: { [token: string]: PendingRequest } = {};
	/** All active observations, sorted by the url */
	private static activeObserveTokens: { [url: string]: string } = {};

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

		// remember the request
		const req: PendingRequest = {
			origin: originString,
			token,
			keepAlive: options.keepAlive,
			promise: response,
			callback: null,
			observe: false
		}
		CoapClient.pendingRequests[tokenString] = req;

		// now send the message
		CoapClient.send(connection, type, code, messageId, token, msgOptions, payload);

		return response;
		
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

		// remember the request
		const req: PendingRequest = {
			origin: originString,
			token,
			keepAlive: options.keepAlive,
			callback,
			observe: true,
			promise: null
		}
		CoapClient.pendingRequests[tokenString] = req;
		// also remember that we are observing
		CoapClient.activeObserveTokens[urlToString(url)] = tokenString;

		// now send the message
		CoapClient.send(connection, type, code, messageId, token, msgOptions, payload);

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
		// see if we have the associated token remembered
		if (CoapClient.activeObserveTokens.hasOwnProperty(urlString)) {
			const token = CoapClient.activeObserveTokens[urlString];
			// try to find the matching request
			if (CoapClient.pendingRequests.hasOwnProperty(token)) {
				const request = CoapClient.pendingRequests[token];
				// and remove it from the table
				delete CoapClient.pendingRequests[token];
			}
			// also remove the association from the observer table
			delete CoapClient.activeObserveTokens[urlString];
		}
	}

	private static onMessage(origin: string, message: Buffer, rinfo: dgram.RemoteInfo) {
		// parse the CoAP message
		const coapMsg = Message.parse(message);

		if (coapMsg.code.isEmpty()) {
			// ACK or RST 
			// TODO handle non-piggybacked messages
		} else if (coapMsg.code.isRequest()) {
			// we are a client implementation, we should not get requests
			// ignore them
		} else if (coapMsg.code.isResponse()) {
			// this is a response, find out what to do with it
			if (coapMsg.token && coapMsg.token.length) {
				// this message has a token, check which request it belongs to
				const tokenString = coapMsg.token.toString("hex");
				if (CoapClient.pendingRequests.hasOwnProperty(tokenString)) {
					const request = CoapClient.pendingRequests[tokenString];

					let contentFormat: ContentFormats = null;
					// parse options
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
						delete CoapClient.pendingRequests[tokenString];
					}


				} else {
					// no request found for this token, send RST so the server stops sending

					// try to find the connection that belongs to this origin
					const originString = origin.toString();
					if (CoapClient.connections.hasOwnProperty(originString)) {
						const connection = CoapClient.connections[originString];

						// and send the reset
						CoapClient.send(
							connection,
							MessageType.RST,
							MessageCodes.empty,
							coapMsg.messageId,
							null, [], null
						)
					}
				}
			}

		}
	}

    /**
     * Send a CoAP message to the given endpoint
     * @param connection 
     * @param type 
     * @param code 
     * @param messageId 
     * @param token 
     * @param options 
     * @param payload 
     */
    private static send(
        connection: ConnectionInfo,
        type: MessageType,
        code: MessageCode,
        messageId: number,
        token: Buffer,
        options: Option[], // do we need this?
        payload: Buffer
    ): void {

		// create the message
		const msg = new Message(
			0x01,
			type, code, messageId, token, options, payload
		);
		// and send it
		connection.socket.send(msg.serialize(), connection.origin);

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
			socket.on("message", CoapClient.bind(CoapClient, originString));
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