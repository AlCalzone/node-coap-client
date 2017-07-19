import * as dtls from "node-dtls-client";
import * as dgram from "dgram";
import { MessageType } from "./Message";
import { Option } from "./Option";



export type RequestMethod = "get" | "post" | "put" | "delete";

/** Options to control CoAP requests */
export interface RequestOptions {
    /** Whether to keep the socket connection alive. Speeds up subsequent requests */
    keepAlive?: boolean
    /** Whether we expect a confirmation of the request */
    confirmable?: boolean
}

export interface CoapResponse {
    code: number,
    payload?: Buffer
}

class SocketWrapper {

    constructor(public socket: dtls.Socket | dgram.Socket) {
        // TODO do something?
    }

    close(): void {
        // TODO
    }
}

/**
 * provides methods to access CoAP server resources
 */
export class CoapClient {

    /** Table of all open connections and their parameters, sorted by the origin "coap(s)://host:port" */
    private static connections: {[origin: string]: {
        socket: SocketWrapper,
        lastToken: Buffer,
        lastMsgId: number
    }} = {};

    /**
     * Requests a CoAP resource 
     * @param url - The URL to be requested. Must start with coap:// or coaps://
     * @param method - The request method to be used
     * @param payload - The optional payload to be attached to the request
     * @param options - Various options to control the request.
     */
    static request(
        url: string, 
        method: RequestMethod,
        payload?: Buffer, 
        options?: RequestOptions
    ): Promise<CoapResponse> {
        // TODO
        throw new Error("not implemented");

        // TODO: we should use the deferred promise from Tradfri for this.
        // TODO: add security options
    }

    /**
     * Send a CoAP message to the other party located at origin
     * @param origin 
     * @param type 
     * @param code 
     * @param messageId 
     * @param token 
     * @param options 
     * @param payload 
     */
    private static send(
        origin: string,
        type: MessageType,
        code: number,
        messageId: number,
        token: Buffer,
        options: Option[], // do we need this?
        payload: Buffer
    ): Promise<void> {
        // TODO
        throw new Error("not implemented");
    }

    /**
     * Establishes a socket that can be used to send to and receive data from the given origin
     * @param origin - The other party
     */
    private static getSocket(origin: string): Promise<SocketWrapper> {
        // TODO
        throw new Error("not implemented");
    }

}