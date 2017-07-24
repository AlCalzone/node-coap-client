import { dtls } from "node-dtls-client";
import * as dgram from "dgram";
import { EventEmitter } from "events";
import { Origin } from "./Origin";

export class SocketWrapper extends EventEmitter {

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