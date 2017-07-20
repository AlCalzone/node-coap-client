/// <reference types="node" />
import { Option } from "./Option";
export declare enum MessageType {
    CON = 0,
    NON = 1,
    ACK = 2,
    RST = 3,
}
/**
 * all defined message codes
 */
export declare const MessageCode: Readonly<{
    empty: number;
    request: {
        get: number;
        post: number;
        put: number;
        delete: number;
    };
    success: {
        created: number;
        deleted: number;
        valid: number;
        changed: number;
        content: number;
    };
    clientError: {
        badRequest: number;
        unauthorized: number;
        badOption: number;
        forbidden: number;
        notFound: number;
        methodNotAllowed: number;
        notAcceptable: number;
        preconditionFailed: number;
        requestEntityTooLarge: number;
        unsupportedContentFormat: number;
    };
    serverError: {
        internalServerError: number;
        notImplemented: number;
        badGateway: number;
        serviceUnavailable: number;
        gatewayTimeout: number;
        proxyingNotSupported: number;
    };
}>;
/**
 * represents a CoAP message
 */
export declare class Message {
    version: number;
    type: MessageType;
    code: number;
    messageId: number;
    token: Buffer;
    options: Option[];
    payload: Buffer;
    constructor(version: number, type: MessageType, code: number, messageId: number, token: Buffer, options: Option[], payload: Buffer);
    /**
     * parses a CoAP message from the given buffer
     * @param buf - the buffer to read from
     */
    static parse(buf: Buffer): Message;
    /**
     * serializes this message into a buffer
     */
    serialize(): Buffer;
}
