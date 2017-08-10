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
            result: optionConstructors[code](rawValue),
            readBytes: dataStart + length,
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
            if (ret.length > this.maxLength) {
                throw new Error("cannot serialize this value because it is too large");
            }
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
var optionConstructors = {};
function defineOptionConstructor(
    // tslint:disable-next-line:ban-types
    constructor, code, name, repeatable) {
    var args = [];
    for (var _i = 4; _i < arguments.length; _i++) {
        args[_i - 4] = arguments[_i];
    }
    optionConstructors[code] = optionConstructors[name] = (_a = constructor.create).bind.apply(_a, [constructor].concat([code, name, repeatable].concat(args)));
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
// tslint:disable-next-line:variable-name
exports.Options = Object.freeze({
    UriHost: function (hostname) { return optionConstructors["Uri-Host"](Buffer.from(hostname)); },
    UriPort: function (port) { return optionConstructors["Uri-Port"](numberToBuffer(port)); },
    UriPath: function (pathname) { return optionConstructors["Uri-Path"](Buffer.from(pathname)); },
    LocationPath: function (pathname) { return optionConstructors["Location-Path"](Buffer.from(pathname)); },
    ContentFormat: function (format) { return optionConstructors["Content-Format"](numberToBuffer(format)); },
    // tslint:disable-next-line:no-string-literal
    Observe: function (observe) { return optionConstructors["Observe"](Buffer.from([observe ? 0 : 1])); },
});
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiT3B0aW9uLmpzIiwic291cmNlUm9vdCI6IkM6L1VzZXJzL0RvbWluaWMvRG9jdW1lbnRzL1Zpc3VhbCBTdHVkaW8gMjAxNy9SZXBvc2l0b3JpZXMvbm9kZS1jb2FwLWNsaWVudC9zcmMvIiwic291cmNlcyI6WyJPcHRpb24udHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6Ijs7Ozs7Ozs7Ozs7O0FBRUEsd0JBQXdCLEtBQWE7SUFDcEMsSUFBTSxHQUFHLEdBQUcsRUFBRSxDQUFDO0lBQ2YsT0FBTyxLQUFLLEdBQUcsQ0FBQyxFQUFFLENBQUM7UUFDbEIsR0FBRyxDQUFDLE9BQU8sQ0FBQyxLQUFLLEdBQUcsSUFBSSxDQUFDLENBQUM7UUFDMUIsS0FBSyxNQUFNLENBQUMsQ0FBQztJQUNkLENBQUM7SUFDRCxNQUFNLENBQUMsTUFBTSxDQUFDLElBQUksQ0FBQyxHQUFHLENBQUMsQ0FBQztBQUN6QixDQUFDO0FBRUQ7O0dBRUc7QUFDSDtJQUVDLGdCQUNpQixJQUFZLEVBQ1osSUFBWSxFQUNyQixRQUFnQjtRQUZQLFNBQUksR0FBSixJQUFJLENBQVE7UUFDWixTQUFJLEdBQUosSUFBSSxDQUFRO1FBQ3JCLGFBQVEsR0FBUixRQUFRLENBQVE7SUFHeEIsQ0FBQztJQVFELHNCQUFXLDhCQUFVO1FBTnRCOzs7OztVQUtFO2FBQ0Q7WUFDQyxNQUFNLENBQUMsQ0FBQyxJQUFJLENBQUMsSUFBSSxHQUFHLEVBQU8sQ0FBQyxLQUFLLEVBQU8sQ0FBQztRQUMxQyxDQUFDOzs7T0FBQTtJQUNELHNCQUFXLDBCQUFNO2FBQWpCO1lBQ0MsTUFBTSxDQUFDLENBQUMsSUFBSSxDQUFDLElBQUksR0FBRyxDQUFJLENBQUMsS0FBSyxDQUFJLENBQUM7UUFDcEMsQ0FBQzs7O09BQUE7SUFDRCxzQkFBVyw0QkFBUTthQUFuQjtZQUNDLE1BQU0sQ0FBQyxDQUFDLElBQUksQ0FBQyxJQUFJLEdBQUcsQ0FBRyxDQUFDLEtBQUssQ0FBRyxDQUFDO1FBQ2xDLENBQUM7OztPQUFBO0lBRUY7Ozs7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