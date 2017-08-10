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
var MessageCode = (function () {
    function MessageCode(major, minor) {
        this.major = major;
        this.minor = minor;
    }
    MessageCode.fromValue = function (value) {
        return new MessageCode((value >>> 5) & 7, value & 31);
    };
    Object.defineProperty(MessageCode.prototype, "value", {
        get: function () {
            return ((this.major & 7) << 5) + (this.minor & 31);
        },
        enumerable: true,
        configurable: true
    });
    MessageCode.prototype.isEmpty = function () { return this.value === exports.MessageCodes.empty.value; };
    MessageCode.prototype.isRequest = function () { return (!this.isEmpty()) && (this.major === exports.MessageCodes.request.__major); };
    MessageCode.prototype.isResponse = function () {
        return (this.major === exports.MessageCodes.success.__major) ||
            (this.major === exports.MessageCodes.clientError.__major) ||
            (this.major === exports.MessageCodes.serverError.__major);
    };
    MessageCode.prototype.toString = function () { return this.major + "." + (this.minor < 10 ? "0" : "") + this.minor; };
    return MessageCode;
}());
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
        var code = MessageCode.fromValue(buf[1]);
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
        if (optionsStart < buf.length && buf[optionsStart] === 0xff) {
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
        var payloadLength = (this.payload && this.payload.length > 0) ? this.payload.length : -1; // -1 to offset the payload byte for empty payloads
        var ret = Buffer.allocUnsafe(4 + tokenLength + optionsBuffer.length + 1 + payloadLength);
        // write fixed values
        ret[0] = ((this.version & 3) << 6)
            + ((this.type & 3) << 4)
            + (tokenLength & 15);
        ret[1] = this.code.value;
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
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiTWVzc2FnZS5qcyIsInNvdXJjZVJvb3QiOiJDOi9Vc2Vycy9Eb21pbmljL0RvY3VtZW50cy9WaXN1YWwgU3R1ZGlvIDIwMTcvUmVwb3NpdG9yaWVzL25vZGUtY29hcC1jbGllbnQvc3JjLyIsInNvdXJjZXMiOlsiTWVzc2FnZS50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOztBQUFBLG1DQUFrQztBQUVsQyxJQUFZLFdBS1g7QUFMRCxXQUFZLFdBQVc7SUFDdEIsMkNBQU8sQ0FBQTtJQUNQLDJDQUFPLENBQUE7SUFDUCwyQ0FBTyxDQUFBO0lBQ1AsMkNBQU8sQ0FBQTtBQUNSLENBQUMsRUFMVyxXQUFXLEdBQVgsbUJBQVcsS0FBWCxtQkFBVyxRQUt0QjtBQUVEO0lBQ0MscUJBQ2lCLEtBQWEsRUFDYixLQUFhO1FBRGIsVUFBSyxHQUFMLEtBQUssQ0FBUTtRQUNiLFVBQUssR0FBTCxLQUFLLENBQVE7SUFDMUIsQ0FBQztJQUVTLHFCQUFTLEdBQXZCLFVBQXdCLEtBQWE7UUFDcEMsTUFBTSxDQUFDLElBQUksV0FBVyxDQUNyQixDQUFDLEtBQUssS0FBSyxDQUFDLENBQUMsR0FBRyxDQUFLLEVBQ3JCLEtBQUssR0FBRyxFQUFPLENBQ2YsQ0FBQztJQUNILENBQUM7SUFFRCxzQkFBVyw4QkFBSzthQUFoQjtZQUNDLE1BQU0sQ0FBQyxDQUFDLENBQUMsSUFBSSxDQUFDLEtBQUssR0FBRyxDQUFLLENBQUMsSUFBSSxDQUFDLENBQUMsR0FBRyxDQUFDLElBQUksQ0FBQyxLQUFLLEdBQUcsRUFBTyxDQUFDLENBQUM7UUFDN0QsQ0FBQzs7O09BQUE7SUFFTSw2QkFBTyxHQUFkLGNBQW1CLE1BQU0sQ0FBQyxJQUFJLENBQUMsS0FBSyxLQUFLLG9CQUFZLENBQUMsS0FBSyxDQUFDLEtBQUssQ0FBQyxDQUFDLENBQUM7SUFDN0QsK0JBQVMsR0FBaEIsY0FBcUIsTUFBTSxDQUFDLENBQUMsQ0FBQyxJQUFJLENBQUMsT0FBTyxFQUFFLENBQUMsSUFBSSxDQUFDLElBQUksQ0FB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