// initialize debugging
import * as debugPackage from "debug";
const debug = debugPackage("node-coap-client:message");

import { Message } from "../Message";

export function logMessage(msg: Message, includePayload: boolean = false): void {
	debug("=============================");
	debug(`received message`);
	debug(`messageId: ${msg.messageId}`);
	if (msg.token != null) {
		debug(`token: ${msg.token.toString("hex")}`);
	}
	debug(`code: ${msg.code}`);
	debug(`type: ${msg.type}`);
	debug(`version: ${msg.version}`);
	debug("options:");
	for (const opt of msg.options) {
		debug(`  [${opt.constructor.name}] ${opt.toString()}`);
	}
	debug("payload:");
	debug(msg.payload.toString("utf-8"));
	debug("=============================");
	debug("");
}
