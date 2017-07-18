import { Option } from "./Option";

export enum MessageType {
	CON = 0, // Confirmable
	NON = 1, // Non-Confirmable
	ACK = 2, // Acknowledgement
	RST = 3, // Reset
}

function code(major: number, minor: number) {
	return ((major & 0b111) << 5) + (minor & 0b11111);
}
export const MessageCode = Object.freeze({
	empty: code(0, 0),

	request: {
		get: code(0, 1),
		post: code(0, 2),
		put: code(0, 3),
		delete: code(0, 4)
	},

	success: {
		created: code(2, 1),
		deleted: code(2, 2),
		valid: code(2, 3),
		changed: code(2, 4),
		content: code(2, 5),
	},

	clientError: {
		badRequest: code(4, 0),
		unauthorized: code(4, 1),
		badOption: code(4, 2),
		forbidden: code(4, 3),
		notFound: code(4, 4),
		methodNotAllowed: code(4, 5),
		notAcceptable: code(4, 6),
		preconditionFailed: code(4, 12),
		requestEntityTooLarge: code(4, 13),
		unsupportedContentFormat: code(4, 15),
	},

	serverError: {
		internalServerError: code(5, 0),
		notImplemented: code(5, 1),
		badGateway: code(5, 2),
		serviceUnavailable: code(5, 3),
		gatewayTimeout: code(5, 4),
		proxyingNotSupported: code(5, 5),
	},

});

export class Message {

	constructor(
		public version: number,
		public type: MessageType,
		public code: number,
		public messageId: number,
		public token: Buffer,
		public options: Option[],
		public payload: Buffer
	) {

	}

	/**
	 * parses a CoAP message from the given buffer
	 * @param buf - the buffer to read from
	 */
	static parse(buf: Buffer): Message {
		const version = (buf[0] >>> 6) & 0b11;
		const type = (buf[0] >>> 4) & 0b11;
		const tokenLength = buf[0] & 0b1111;

		const code = buf[1];

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
			options.push(result.result);
			prevCode = result.result.code;
			optionsStart += result.readBytes;
		}

		let payload: Buffer;

		if (optionsStart < buf.length && buf[optionsStart] == 0xff) {
			// here comes the payload
			// copy the remainder of the packet
			payload = Buffer.from(buf.slice(optionsStart+1));
		} else {
			payload = Buffer.from([]);
		}

		return new Message(
			version, type, code, messageId, token, options, payload
		);
	}

	/**
	 * serializes this message into a buffer
	 */
	public serialize(): Buffer {
		const tokenLength = this.token ? this.token.length : 0;

		// serialize the options first, so we know how many bytes to reserve
		let optionsBuffer : Buffer;
		if (this.options && this.options.length) {
			optionsBuffer = Buffer.concat(
				this.options.map((o, i, opts) => o.serialize(i > 0 ? opts[i-1].code : 0))
			);
		} else {
			optionsBuffer = Buffer.from([]);
		}

		// allocate the buffer to be filled
		const ret = Buffer.allocUnsafe(4 + tokenLength + optionsBuffer.length + 1 + this.payload.length);

		// write fixed values
		ret[0] = ((this.version & 0b11) << 6)
			+ ((this.type & 0b11) << 4)
			+ (tokenLength & 0b1111)
			;
		ret[1] = this.code;
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
		ret[offset] = 0xff;
		this.payload.copy(ret, offset + 1);

		return ret;
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