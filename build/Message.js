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