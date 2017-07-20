/// <reference types="node" />
import { MessageCode } from "./Message";
import * as nodeUrl from "url";
export declare type RequestMethod = "get" | "post" | "put" | "delete";
/** Options to control CoAP requests */
export interface RequestOptions {
    /** Whether to keep the socket connection alive. Speeds up subsequent requests */
    keepAlive?: boolean;
    /** Whether we expect a confirmation of the request */
    confirmable?: boolean;
    /** Whether we want to receive updates */
    observe?: boolean;
}
export interface CoapResponse {
    code: MessageCode;
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
    private static pendingRequests;
    /** All active observations, sorted by the url */
    private static activeObserveTokens;
    /**
     * Sets the security params to be used for the given hostname
     */
    static setSecurityParams(hostname: string, params: SecurityParameters): void;
    /**
     * Requests a CoAP resource
     * @param url - The URL to be requested. Must start with coap:// or coaps://
     * @param method - The request method to be used
     * @param payload - The optional payload to be attached to the request
     * @param options - Various options to control the request.
     */
    static request(url: string | nodeUrl.Url, method: RequestMethod, payload?: Buffer, options?: RequestOptions): Promise<CoapResponse>;
    /**
     * Stops observation of the given url
     */
    static stopObserving(url: string | nodeUrl.Url): void;
    private static onMessage(origin, message, rinfo);
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
    private static send(connection, type, code, messageId, token, options, payload);
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
