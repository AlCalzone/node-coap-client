/// <reference types="node" />
import * as dgram from "dgram";
import { EventEmitter } from "events";
import { dtls } from "node-dtls-client";
import { Origin } from "./Origin";
export declare class SocketWrapper extends EventEmitter {
    socket: dtls.Socket | dgram.Socket;
    private isDtls;
    constructor(socket: dtls.Socket | dgram.Socket);
    send(msg: Buffer, origin: Origin): void;
    close(): void;
}
