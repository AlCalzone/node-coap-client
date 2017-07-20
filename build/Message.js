"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var Option_1 = require("./Option");
var MessageType;
(function (MessageType) {
    MessageType[MessageType["CON"] = 0] = "CON";
    MessageType[MessageType["NON"] = 1] = "NON";
    MessageType[MessageType["ACK"] = 2] = "ACK";
    MessageType[MessageType["RST"] = 3] = "RST";
})(MessageType = exports.MessageType || (exports.MessageType = {}));
function code(major, minor) {
    return ((major & 7) << 5) + (minor & 31);
}
/**
 * all defined message codes
 */
exports.MessageCode = Object.freeze({
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
/**
 * represents a CoAP message
 */
var Message = (function () {
    function Message(version, type, code, messageId, token, options, payload) {
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
    Message.parse = function (buf) {
        var version = (buf[0] >>> 6) & 3;
        var type = (buf[0] >>> 4) & 3;
        var tokenLength = buf[0] & 15;
        var code = buf[1];
        var messageId = buf[2] * 256 + buf[3];
        var token = Buffer.alloc(tokenLength);
        if (tokenLength > 0)
            buf.copy(token, 0, 4, 4 + tokenLength);
        // parse options
        var optionsStart = 4 + tokenLength;
        var options = [];
        var prevCode = 0; // code of the previously read option 
        while (optionsStart < buf.length && buf[optionsStart] !== 0xff) {
            // read option
            var result = Option_1.Option.parse(buf.slice(optionsStart), prevCode);
            options.push(result.result);
            prevCode = result.result.code;
            optionsStart += result.readBytes;
        }
        var payload;
        if (optionsStart < buf.length && buf[optionsStart] == 0xff) {
            // here comes the payload
            // copy the remainder of the packet
            payload = Buffer.from(buf.slice(optionsStart + 1));
        }
        else {
            payload = Buffer.from([]);
        }
        return new Message(version, type, code, messageId, token, options, payload);
    };
    /**
     * serializes this message into a buffer
     */
    Message.prototype.serialize = function () {
        var tokenLength = this.token ? this.token.length : 0;
        // serialize the options first, so we know how many bytes to reserve
        var optionsBuffer;
        if (this.options && this.options.length) {
            optionsBuffer = Buffer.concat(this.options.map(function (o, i, opts) { return o.serialize(i > 0 ? opts[i - 1].code : 0); }));
        }
        else {
            optionsBuffer = Buffer.from([]);
        }
        // allocate the buffer to be filled
        var payloadLength = this.payload ? this.payload.length : -1; // -1 to offset the payload byte for empty payloads
        var ret = Buffer.allocUnsafe(4 + tokenLength + optionsBuffer.length + 1 + payloadLength);
        // write fixed values
        ret[0] = ((this.version & 3) << 6)
            + ((this.type & 3) << 4)
            + (tokenLength & 15);
        ret[1] = this.code;
        ret[2] = (this.messageId >>> 8) & 0xff;
        ret[3] = this.messageId & 0xff;
        // write the token if neccessary
        if (tokenLength > 0) {
            this.token.copy(ret, 4);
        }
        // write the options where they belong (if any)
        var offset = 4 + tokenLength;
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
    };
    return Message;
}());
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
//# sourceMappingURL=Message.js.map