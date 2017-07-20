"use strict";
var __extends = (this && this.__extends) || (function () {
    var extendStatics = Object.setPrototypeOf ||
        ({ __proto__: [] } instanceof Array && function (d, b) { d.__proto__ = b; }) ||
        function (d, b) { for (var p in b) if (b.hasOwnProperty(p)) d[p] = b[p]; };
    return function (d, b) {
        extendStatics(d, b);
        function __() { this.constructor = d; }
        d.prototype = b === null ? Object.create(b) : (__.prototype = b.prototype, new __());
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
function numberToBuffer(value) {
    var ret = [];
    while (value > 0) {
        ret.unshift(value & 0xff);
        value >>>= 8;
    }
    return Buffer.from(ret);
}
/**
 * Abstract base class for all message options. Provides methods to parse and serialize.
 */
var Option = (function () {
    function Option(code, name, rawValue) {
        this.code = code;
        this.name = name;
        this.rawValue = rawValue;
    }
    Object.defineProperty(Option.prototype, "noCacheKey", {
        /*
              0   1   2   3   4   5   6   7
            +---+---+---+---+---+---+---+---+
            |           | NoCacheKey| U | C |
            +---+---+---+---+---+---+---+---+
        */
        get: function () {
            return (this.code & 28) === 28;
        },
        enumerable: true,
        configurable: true
    });
    Object.defineProperty(Option.prototype, "unsafe", {
        get: function () {
            return (this.code & 2) === 2;
        },
        enumerable: true,
        configurable: true
    });
    Object.defineProperty(Option.prototype, "critical", {
        get: function () {
            return (this.code & 1) === 1;
        },
        enumerable: true,
        configurable: true
    });
    /*
    
         0   1   2   3   4   5   6   7
       +---------------+---------------+
       |  Option Delta | Option Length |   1 byte
       +---------------+---------------+
       /         Option Delta          /   0-2 bytes
       \          (extended)           \
       +-------------------------------+
       /         Option Length         /   0-2 bytes
       \          (extended)           \
       +-------------------------------+
       \                               \
       /         Option Value          /   0 or more bytes
       \                               \
       +-------------------------------+
    */
    /**
     * parses a CoAP option from the given buffer. The buffer must start at the option
     * @param buf - the buffer to read from
     * @param prevCode - The option code of the previous option
     */
    Option.parse = function (buf, prevCode) {
        if (prevCode === void 0) { prevCode = 0; }
        var delta = (buf[0] >>> 4) & 15;
        var length = buf[0] & 15;
        var dataStart = 1;
        // handle special cases for the delta
        switch (delta) {
            case 13:
                delta = buf[dataStart] + 13;
                dataStart += 1;
                break;
            case 14:
                delta = buf.readUInt16BE(dataStart) + 269;
                dataStart += 2;
                break;
            case 15:
                throw new Error("invalid option format");
            default:
        }
        // handle special cases for the length
        switch (length) {
            case 13:
                length = buf[dataStart] + 13;
                dataStart += 1;
                break;
            case 14:
                length = buf.readUInt16BE(dataStart) + 269;
                dataStart += 2;
                break;
            case 15:
                throw new Error("invalid option format");
            default:
        }
        var rawValue = Buffer.from(buf.slice(dataStart, dataStart + length));
        var code = prevCode + delta;
        return {
            result: OptionConstructors[code](rawValue),
            readBytes: dataStart + length
        };
    };
    /**
     * serializes this option into a buffer
     * @param prevCode - The option code of the previous option
     */
    Option.prototype.serialize = function (prevCode) {
        var delta = this.code - prevCode;
        var extraDelta = -1;
        var length = this.rawValue.length;
        var extraLength = -1;
        var totalLength = 1
            + (delta >= 13 ? 1 : 0)
            + (delta >= 269 ? 1 : 0)
            + (length >= 13 ? 1 : 0)
            + (length >= 269 ? 1 : 0)
            + length;
        var ret = Buffer.allocUnsafe(totalLength);
        var dataStart = 1;
        // check if we need to split the delta in 2 parts
        if (delta < 13) {
        }
        else if (delta < 269) {
            extraDelta = delta - 13;
            delta = 13;
            ret[dataStart] = extraDelta;
            dataStart += 1;
        }
        else {
            extraDelta = delta - 14;
            delta = 14;
            ret.writeUInt16BE(extraDelta, dataStart);
            dataStart += 2;
        }
        // check if we need to split the length in 2 parts
        if (length < 13) {
        }
        else if (length < 269) {
            extraLength = length - 13;
            length = 13;
            ret[dataStart] = extraLength;
            dataStart += 1;
        }
        else {
            extraLength = length - 14;
            length = 14;
            ret.writeUInt16BE(extraLength, dataStart);
            dataStart += 2;
        }
        // write the delta and length
        ret[0] = (delta << 4) + length;
        // copy the data
        this.rawValue.copy(ret, dataStart, 0);
        return ret;
    };
    return Option;
}());
exports.Option = Option;
/**
 * Specialized Message option for numeric contents
 */
var NumericOption = (function (_super) {
    __extends(NumericOption, _super);
    function NumericOption(code, name, repeatable, maxLength, rawValue) {
        var _this = _super.call(this, code, name, rawValue) || this;
        _this.name = name;
        _this.repeatable = repeatable;
        _this.maxLength = maxLength;
        return _this;
    }
    Object.defineProperty(NumericOption.prototype, "value", {
        get: function () {
            return this.rawValue.reduce(function (acc, cur) { return acc * 256 + cur; }, 0);
        },
        set: function (value) {
            var ret = [];
            while (value > 0) {
                ret.unshift(value & 0xff);
                value >>>= 8;
            }
            if (ret.length > this.maxLength)
                throw new Error("cannot serialize this value because it is too large");
            this.rawValue = Buffer.from(ret);
        },
        enumerable: true,
        configurable: true
    });
    NumericOption.create = function (code, name, repeatable, maxLength, rawValue) {
        return new NumericOption(code, name, repeatable, maxLength, rawValue);
    };
    return NumericOption;
}(Option));
exports.NumericOption = NumericOption;
/**
 * Specialized Message options for binary (and empty) content.
 */
var BinaryOption = (function (_super) {
    __extends(BinaryOption, _super);
    function BinaryOption(code, name, repeatable, minLength, maxLength, rawValue) {
        var _this = _super.call(this, code, name, rawValue) || this;
        _this.name = name;
        _this.repeatable = repeatable;
        _this.minLength = minLength;
        _this.maxLength = maxLength;
        return _this;
    }
    Object.defineProperty(BinaryOption.prototype, "value", {
        get: function () {
            return this.rawValue;
        },
        set: function (value) {
            if (value == null) {
                if (this.minLength > 0)
                    throw new Error("cannot assign null to a Buffer with minimum length");
            }
            else {
                if (value.length < this.minLength || value.length > this.maxLength) {
                    throw new Error("The length of the Buffer is outside the specified bounds");
                }
            }
            this.rawValue = value;
        },
        enumerable: true,
        configurable: true
    });
    BinaryOption.create = function (code, name, repeatable, minLength, maxLength, rawValue) {
        return new BinaryOption(code, name, repeatable, minLength, maxLength, rawValue);
    };
    return BinaryOption;
}(Option));
exports.BinaryOption = BinaryOption;
/**
 * Specialized Message options for string content.
 */
var StringOption = (function (_super) {
    __extends(StringOption, _super);
    function StringOption(code, name, repeatable, minLength, maxLength, rawValue) {
        var _this = _super.call(this, code, name, rawValue) || this;
        _this.name = name;
        _this.repeatable = repeatable;
        _this.minLength = minLength;
        _this.maxLength = maxLength;
        return _this;
    }
    Object.defineProperty(StringOption.prototype, "value", {
        get: function () {
            return this.rawValue.toString("utf8");
        },
        set: function (value) {
            if (value == null) {
                if (this.minLength > 0)
                    throw new Error("cannot assign null to a string with minimum length");
            }
            else {
                if (value.length < this.minLength || value.length > this.maxLength) {
                    throw new Error("The length of the string is outside the specified bounds");
                }
            }
            this.rawValue = Buffer.from(value, "utf8");
        },
        enumerable: true,
        configurable: true
    });
    StringOption.create = function (code, name, repeatable, minLength, maxLength, rawValue) {
        return new StringOption(code, name, repeatable, minLength, maxLength, rawValue);
    };
    return StringOption;
}(Option));
exports.StringOption = StringOption;
/**
 * all defined assignments for instancing Options
 */
var OptionConstructors = {};
function defineOptionConstructor(constructor, code, name, repeatable) {
    var args = [];
    for (var _i = 4; _i < arguments.length; _i++) {
        args[_i - 4] = arguments[_i];
    }
    OptionConstructors[code] = OptionConstructors[name] = (_a = constructor.create).bind.apply(_a, [constructor].concat([code, name, repeatable].concat(args)));
    var _a;
}
defineOptionConstructor(NumericOption, 6, "Observe", false, 3);
defineOptionConstructor(NumericOption, 7, "Uri-Port", false, 2);
defineOptionConstructor(NumericOption, 12, "Content-Format", false, 2);
defineOptionConstructor(NumericOption, 14, "Max-Age", false, 4);
defineOptionConstructor(NumericOption, 17, "Accept", false, 2);
defineOptionConstructor(NumericOption, 60, "Size1", false, 4);
defineOptionConstructor(BinaryOption, 1, "If-Match", true, 0, 8);
defineOptionConstructor(BinaryOption, 4, "ETag", true, 1, 8);
defineOptionConstructor(BinaryOption, 5, "If-None-Match", false, 0, 0);
defineOptionConstructor(StringOption, 3, "Uri-Host", false, 1, 255);
defineOptionConstructor(StringOption, 8, "Location-Path", true, 0, 255);
defineOptionConstructor(StringOption, 11, "Uri-Path", true, 0, 255);
defineOptionConstructor(StringOption, 15, "Uri-Query", true, 0, 255);
defineOptionConstructor(StringOption, 20, "Location-Query", true, 0, 255);
defineOptionConstructor(StringOption, 35, "Proxy-Uri", true, 1, 1034);
defineOptionConstructor(StringOption, 39, "Proxy-Scheme", true, 1, 255);
exports.Options = Object.freeze({
    UriHost: function (hostname) { return OptionConstructors["Uri-Host"](Buffer.from(hostname)); },
    UriPort: function (port) { return OptionConstructors["Uri-Port"](numberToBuffer(port)); },
    UriPath: function (pathname) { return OptionConstructors["Uri-Path"](Buffer.from(pathname)); },
    LocationPath: function (pathname) { return OptionConstructors["Location-Path"](Buffer.from(pathname)); },
    ContentFormat: function (format) { return OptionConstructors["Content-Format"](numberToBuffer(format)); },
    Observe: function (observe) { return OptionConstructors["Observe"](Buffer.from([observe ? 0 : 1])); },
});
//# sourceMappingURL=Option.js.map