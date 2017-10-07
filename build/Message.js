"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const Option_1 = require("./Option");
var MessageType;
(function (MessageType) {
    MessageType[MessageType["CON"] = 0] = "CON";
    MessageType[MessageType["NON"] = 1] = "NON";
    MessageType[MessageType["ACK"] = 2] = "ACK";
    MessageType[MessageType["RST"] = 3] = "RST";
})(MessageType = exports.MessageType || (exports.MessageType = {}));
class MessageCode {
    constructor(major, minor) {
        this.major = major;
        this.minor = minor;
    }
    static fromValue(value) {
        return new MessageCode((value >>> 5) & 0b111, value & 0b11111);
    }
    get value() {
        return ((this.major & 0b111) << 5) + (this.minor & 0b11111);
    }
    isEmpty() { return this.value === exports.MessageCodes.empty.value; }
    isRequest() { return (!this.isEmpty()) && (this.major === exports.MessageCodes.request.__major); }
    isResponse() {
        return (this.major === exports.MessageCodes.success.__major) ||
            (this.major === exports.MessageCodes.clientError.__major) ||
            (this.major === exports.MessageCodes.serverError.__major);
    }
    toString() { return `${this.major}.${this.minor < 10 ? "0" : ""}${this.minor}`; }
}
exports.MessageCode = MessageCode;
/**
 * all defined message codes
 */
// tslint:disable-next-line:variable-name
exports.MessageCodes = Object.freeze({
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
class Message {
    constructor(version, type, code, messageId, token, options, payload) {
        this.version = version;
        this.type = type;
        this.code = code;
        this.messageId = messageId;
        this.token = token;
        this.options = options;
        this.payload = payload;
    }
    /**
     * parses a CoAP message from the given buffer
     * @param buf - the buffer to read from
     */
    static parse(buf) {
        const version = (buf[0] >>> 6) & 0b11;
        const type = (buf[0] >>> 4) & 0b11;
        const tokenLength = buf[0] & 0b1111;
        const code = MessageCode.fromValue(buf[1]);
        const messageId = buf[2] * 256 + buf[3];
        const token = Buffer.alloc(tokenLength);
        if (tokenLength > 0)
            buf.copy(token, 0, 4, 4 + tokenLength);
        // parse options
        let optionsStart = 4 + tokenLength;
        const options = [];
        let prevCode = 0; // code of the previously read option
        while (optionsStart < buf.length && buf[optionsStart] !== 0xff) {
            // read option
            const result = Option_1.Option.parse(buf.slice(optionsStart), prevCode);
            if (result.readBytes <= 0) {
                // This shouldn't happen but we want to prevent infinite loops
                throw new Error(`Zero or less bytes read while parsing packet options. The raw buffer was ${buf.toString("hex")}`);
            }
            options.push(result.result);
            prevCode = result.result.code;
            optionsStart += result.readBytes;
        }
        let payload;
        if (optionsStart < buf.length && buf[optionsStart] === 0xff) {
            // here comes the payload
            // copy the remainder of the packet
            payload = Buffer.from(buf.slice(optionsStart + 1));
        }
        else {
            payload = Buffer.from([]);
        }
        return new Message(version, type, code, messageId, token, options, payload);
    }
    /**
     * serializes this message into a buffer
     */
    serialize() {
        const tokenLength = this.token ? this.token.length : 0;
        // serialize the options first, so we know how many bytes to reserve
        let optionsBuffer;
        if (this.options && this.options.length) {
            optionsBuffer = Buffer.concat(this.options.map((o, i, opts) => o.serialize(i > 0 ? opts[i - 1].code : 0)));
        }
        else {
            optionsBuffer = Buffer.from([]);
        }
        // allocate the buffer to be filled
        const payloadLength = (this.payload && this.payload.length > 0) ? this.payload.length : -1; // -1 to offset the payload byte for empty payloads
        const ret = Buffer.allocUnsafe(4 + tokenLength + optionsBuffer.length + 1 + payloadLength);
        // write fixed values
        ret[0] = ((this.version & 0b11) << 6)
            + ((this.type & 0b11) << 4)
            + (tokenLength & 0b1111);
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
}
exports.Message = Message;
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
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiTWVzc2FnZS5qcyIsInNvdXJjZVJvb3QiOiJDOi9Vc2Vycy9Eb21pbmljL0RvY3VtZW50cy9WaXN1YWwgU3R1ZGlvIDIwMTcvUmVwb3NpdG9yaWVzL25vZGUtY29hcC1jbGllbnQvc3JjLyIsInNvdXJjZXMiOlsiTWVzc2FnZS50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOztBQUFBLHFDQUFrQztBQUVsQyxJQUFZLFdBS1g7QUFMRCxXQUFZLFdBQVc7SUFDdEIsMkNBQU8sQ0FBQTtJQUNQLDJDQUFPLENBQUE7SUFDUCwyQ0FBTyxDQUFBO0lBQ1AsMkNBQU8sQ0FBQTtBQUNSLENBQUMsRUFMVyxXQUFXLEdBQVgsbUJBQVcsS0FBWCxtQkFBVyxRQUt0QjtBQUVEO0lBQ0MsWUFDaUIsS0FBYSxFQUNiLEtBQWE7UUFEYixVQUFLLEdBQUwsS0FBSyxDQUFRO1FBQ2IsVUFBSyxHQUFMLEtBQUssQ0FBUTtJQUMxQixDQUFDO0lBRUUsTUFBTSxDQUFDLFNBQVMsQ0FBQyxLQUFhO1FBQ3BDLE1BQU0sQ0FBQyxJQUFJLFdBQVcsQ0FDckIsQ0FBQyxLQUFLLEtBQUssQ0FBQyxDQUFDLEdBQUcsS0FBSyxFQUNyQixLQUFLLEdBQUcsT0FBTyxDQUNmLENBQUM7SUFDSCxDQUFDO0lBRUQsSUFBVyxLQUFLO1FBQ2YsTUFBTSxDQUFDLENBQUMsQ0FBQyxJQUFJLENBQUMsS0FBSyxHQUFHLEtBQUssQ0FBQyxJQUFJLENBQUMsQ0FBQyxHQUFHLENBQUMsSUFBSSxDQUFDLEtBQUssR0FBRyxPQUFPLENBQUMsQ0FBQztJQUM3RCxDQUFDO0lBRU0sT0FBTyxLQUFLLE1BQU0sQ0FBQyxJQUFJLENBQUMsS0FBSyxLQUFLLG9CQUFZLENBQUMsS0FBSyxDQUFDLEtBQUssQ0FBQyxDQUFDLENBQUM7SUFDN0QsU0FBUyxLQUFLLE1BQU0sQ0FBQyxDQUFDLENBQUMsSUFBSSxDQUFDLE9BQU8sRUFBRSxDQUFDLElBQUksQ0FBQyxJQUFJLENBQUMsS0FBSyxLQUFLLG9CQUFZLENBQUMsT0FBTyxD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