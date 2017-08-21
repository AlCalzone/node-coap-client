import * as dgram from "dgram";
import { EventEmitter } from "events";
import { dtls } from "node-dtls-client";
import { Origin } from "./Origin";

export class SocketWrapper extends EventEmitter {

	private isDtls: boolean;
	private isClosed: boolean;

	constructor(public socket: dtls.Socket | dgram.Socket) {
		super();
		this.isDtls = (socket instanceof dtls.Socket);
		(socket as any)
			.on("message", (message: Buffer, rinfo: dgram.RemoteInfo) => {
				this.emit("message", message, rinfo);
			})
			.on("error", (err: Error) => {
				this.emit("error", err);
			})
			.on("close", () => {
				this.emit("close");
			})
			;
	}

	public send(msg: Buffer, origin: Origin) {
		if (this.isClosed) return;
		if (this.isDtls) {
			(this.socket as dtls.Socket).send(msg);
		} else {
			(this.socket as dgram.Socket).send(msg, origin.port, origin.hostname);
		}
	}

	public close(): void {
		if (this.isClosed) return;
		this.isClosed = true;
		if (this.isDtls) {
			(this.socket as dtls.Socket).close();
		} else {
			(this.socket as dgram.Socket).close();
		}
	}
}
