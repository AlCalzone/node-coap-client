import { Option } from "./Option";

export enum MessageType {
	CON = 0, // Confirmable
	NON = 1, // Non-Confirmable
	ACK = 2, // Acknowledgement
	RST = 3, // Reset
}

export class MessageCode {
	constructor(
		public readonly major: number,
		public readonly minor: number,
	) { }

	public static fromValue(value: number) {
		return new MessageCode(
			(value >>> 5) & 0b111,
			value & 0b11111,
		);
	}

	public get value(): number {
		return ((this.major & 0b111) << 5) + (this.minor & 0b11111);
	}

	public isEmpty() { return this.value === MessageCodes.empty.value; }
	public isRequest() { return (!this.isEmpty()) && (this.major === MessageCodes.request.__major); }
	public isResponse() {
		return (this.major === MessageCodes.success.__major) ||
			(this.major === MessageCodes.clientError.__major) ||
			(this.major === MessageCodes.serverError.__major)
			;
	}

	public toString() { return `${this.major}.${this.minor < 10 ? "0" : ""}${this.minor}`; }
}

/**
 * all defined message codes
 */
// tslint:disable-next-line:variable-name
export const MessageCodes = Object.freeze({
	empty: new MessageCode(0, 0),

	request: {
		__major: 0,
		get: new MessageCode(0, 1),
		post: new MessageCode(0, 2),
		put: new MessageCode(0, 3),
		delete: new MessageCode(0, 4),
	},

	success: {
		__major: 2,
		created: new MessageCode(2, 1),
		deleted: new MessageCode(2, 2),
		valid: new MessageCode(2, 3),
		changed: new MessageCode(2, 4),
		content: new MessageCode(2, 5),
		continue: new MessageCode(2, 31),
	},

	clientError: {
		__major: 4,
		badRequest: new MessageCode(4, 0),
		unauthorized: new MessageCode(4, 1),
		badOption: new MessageCode(4, 2),
		forbidden: new MessageCode(4, 3),
		notFound: new MessageCode(4, 4),
		methodNotAllowed: new MessageCode(4, 5),
		notAcceptable: new MessageCode(4, 6),
		requestEntityIncomplete: new MessageCode(4, 8),
		preconditionFailed: new MessageCode(4, 12),
		requestEntityTooLarge: new MessageCode(4, 13),
		unsupportedContentFormat: new MessageCode(4, 15),
	},

	serverError: {
		__major: 5,
		internalServerError: new MessageCode(5, 0),
		notImplemented: new MessageCode(5, 1),
		badGateway: new MessageCode(5, 2),
		serviceUnavailable: new MessageCode(5, 3),
		gatewayTimeout: new MessageCode(5, 4),
		proxyingNotSupported: new MessageCode(5, 5),
	},

});

/**
 * represents a CoAP message
 */
export class Message {

	constructor(
		public version: number,
		public type: MessageType,
		public code: MessageCode,
		public messageId: number,
		public token: Buffer,
		public options: Option[],
		public payload: Buffer,
	) {

	}

	/**
	 * parses a CoAP message from the given buffer
	 * @param buf - the buffer to read from
	 */
	public static parse(buf: Buffer): Message {
		const version = (buf[0] >>> 6) & 0b11;
		const type = (buf[0] >>> 4) & 0b11;
		const tokenLength = buf[0] & 0b1111;

		const code = MessageCode.fromValue(buf[1]);

		const messageId = buf[2] * 256 + buf[3];

		const token = Buffer.alloc(tokenLength);
		if (tokenLength > 0) buf.copy(token, 0, 4, 4 + tokenLength);

		// parse options
		let optionsStart = 4 + tokenLength;
		const options = [];
		let prevCode = 0; // code of the previously read option
		while (optionsStart < buf.length && buf[optionsStart] !== 0xff) {
			// read option
			const result = Option.parse(buf.slice(optionsStart), prevCode);
			if (result.readBytes <= 0) {
				// This shouldn't happen but we want to prevent infinite loops
				throw new Error(`Zero or less bytes read while parsing packet options. The raw buffer was ${buf.toString("hex")}`);
			}
			options.push(result.result);
			prevCode = result.result.code;
			optionsStart += result.readBytes;
		}

		let payload: Buffer;

		if (optionsStart < buf.length && buf[optionsStart] === 0xff) {
			// here comes the payload
			// copy the remainder of the packet
			payload = Buffer.from(buf.slice(optionsStart + 1));
		} else {
			payload = Buffer.from([]);
		}

		return new Message(
			version, type, code, messageId, token, options, payload,
		);
	}

	/**
	 * serializes this message into a buffer
	 */
	public serialize(): Buffer {
		const tokenLength = this.token ? this.token.length : 0;

		// serialize the options first, so we know how many bytes to reserve
		let optionsBuffer: Buffer;
		if (this.options && this.options.length) {
			optionsBuffer = Buffer.concat(
				this.options.map((o, i, opts) => o.serialize(i > 0 ? opts[i - 1].code : 0)),
			);
		} else {
			optionsBuffer = Buffer.from([]);
		}

		// allocate the buffer to be filled
		const payloadLength = (this.payload && this.payload.length > 0) ? this.payload.length : -1; // -1 to offset the payload byte for empty payloads
		const ret = Buffer.allocUnsafe(4 + tokenLength + optionsBuffer.length + 1 + payloadLength);

		// write fixed values
		ret[0] = ((this.version & 0b11) << 6)
			+ ((this.type & 0b11) << 4)
			+ (tokenLength & 0b1111)
			;
		ret[1] = this.code.value;
		ret[2] = (this.messageId >>> 8) & 0xff;
		ret[3] = this.messageId & 0xff;

		// write the token if neccessary
		if (tokenLength > 0) {
			this.token.copy(ret, 4);
		}

		// write the options where they belong (if any)
		let offset = 4 + tokenLength;
		if (optionsBuffer.length > 0) {
			optionsBuffer.copy(ret, offset);
			offset += optionsBuffer.length;
		}

		// write the payload where it belongs
		if (payloadLength > 0) {
			ret[offset] = 0xff;
			this.payload.copy(ret, offset + 1);
		}

		return ret;
	}

	/**
	 * Checks if this message is part of a blockwise transfer
	 */
	public isPartialMessage(): boolean {
		// TODO: can we put the codes in an enum?

		// start with the response option, since that's more likely
		const block2option = this.options.find(o => o.code === 23 /* Block2 */);
		if (this.code.isResponse() && block2option != null) return true;
		const block1option = this.options.find(o => o.code === 27 /* Block1 */);
		if (this.code.isRequest() && block1option != null) return true;
		return false;
	}

}

/*
	0                   1                   2                   3
	0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |Ver| T |  TKL  |      Code     |          Message ID           |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |   Token (if any, TKL bytes) ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |   Options (if any) ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |1 1 1 1 1 1 1 1|    Payload (if any) ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
