/// <reference types="node" />
export declare enum MessageType {
    CON = 0,
    NON = 1,
    ACK = 2,
    RST = 3,
}
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
export declare class Message {
    version: number;
    type: MessageType;
    code: number;
    messageId: number;
    token: Buffer;
    options: any[];
    payload: Buffer;
    constructor(version: number, type: MessageType, code: number, messageId: number, token: Buffer, options: any[], payload: Buffer);
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
