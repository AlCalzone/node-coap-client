/// <reference types="node" />
import * as nodeUrl from "url";
import { ContentFormats } from "./ContentFormats";
import { Origin } from "./lib/Origin";
import { MessageCode } from "./Message";
export declare type RequestMethod = "get" | "post" | "put" | "delete";
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
export interface SecurityParameters {
    psk: {
        [identity: string]: string;
    };
}
/**
 * provides methods to access CoAP server resources
 */
export declare class CoapClient {
    /** Table of all open connections and their parameters, sorted by the origin "coap(s)://host:port" */
    private static connections;
    /** Table of all known security params, sorted by the hostname */
    private static dtlsParams;
    /** All pending requests, sorted by the token */
    private static pendingRequestsByToken;
    private static pendingRequestsByMsgID;
    private static pendingRequestsByUrl;
    /**
     * Sets the security params to be used for the given hostname
     */
    static setSecurityParams(hostname: string, params: SecurityParameters): void;
    /**
     * Closes and forgets about connections, useful if DTLS session is reset on remote end
     * @param originOrHostname - Origin (protocol://hostname:port) or Hostname to reset,
     * omit to reset all connections
     */
    static reset(originOrHostname?: string | Origin): void;
    /**
     * Requests a CoAP resource
     * @param url - The URL to be requested. Must start with coap:// or coaps://
     * @param method - The request method to be used
     * @param payload - The optional payload to be attached to the request
     * @param options - Various options to control the request.
     */
    static request(url: string | nodeUrl.Url, method: RequestMethod, payload?: Buffer, options?: RequestOptions): Promise<CoapResponse>;
    /**
     * Pings a CoAP endpoint to check if it is alive
     * @param target - The target to be pinged. Must be a string, NodeJS.Url or Origin and has to contain the protocol, host and port.
     * @param timeout - (optional) Timeout in ms, after which the ping is deemed unanswered. Default: 5000ms
     */
    static ping(target: string | nodeUrl.Url | Origin, timeout?: number): Promise<boolean>;
    /**
     * Re-Sends a message in case it got lost
     * @param msgID
     */
    private static retransmit(msgID);
    private static getRetransmissionInterval();
    private static stopRetransmission(request);
    /**
     * Observes a CoAP resource
     * @param url - The URL to be requested. Must start with coap:// or coaps://
     * @param method - The request method to be used
     * @param payload - The optional payload to be attached to the request
     * @param options - Various options to control the request.
     */
    static observe(url: string | nodeUrl.Url, method: RequestMethod, callback: (resp: CoapResponse) => void, payload?: Buffer, options?: RequestOptions): Promise<void>;
    /**
     * Stops observation of the given url
     */
    static stopObserving(url: string | nodeUrl.Url): void;
    private static onMessage(origin, message, rinfo);
    /**
     * Creates a message with the given parameters
     * @param type
     * @param code
     * @param messageId
     * @param token
     * @param options
     * @param payload
     */
    private static createMessage(type, code, messageId, token?, options?, payload?);
    /**
     * Send a CoAP message to the given endpoint
     * @param connection
     */
    private static send(connection, message);
    /**
     * Remembers a request for resending lost messages and tracking responses and updates
     * @param request
     * @param byUrl
     * @param byMsgID
     * @param byToken
     */
    private static rememberRequest(request, byUrl?, byMsgID?, byToken?);
    /**
     * Forgets a pending request
     * @param request
     * @param byUrl
     * @param byMsgID
     * @param byToken
     */
    private static forgetRequest(which);
    /**
     * Finds a request we have remembered by one of its properties
     * @param which
     */
    private static findRequest(which);
    /**
     * Finds all pending requests of a given origin
     */
    private static findRequestsByOrigin(origin);
    /**
     * Tries to establish a connection to the given target. Returns true on success, false otherwise.
     * @param target The target to connect to. Must be a string, NodeJS.Url or Origin and has to contain the protocol, host and port.
     */
    static tryToConnect(target: string | nodeUrl.Url | Origin): Promise<boolean>;
    /**
     * Establishes a new or retrieves an existing connection to the given origin
     * @param origin - The other party
     */
    private static getConnection(origin);
    /**
     * Establishes or retrieves a socket that can be used to send to and receive data from the given origin
     * @param origin - The other party
     */
    private static getSocket(origin);
}
