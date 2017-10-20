"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
function numberToBuffer(value) {
    const ret = [];
    while (value > 0) {
        ret.unshift(value & 0xff);
        value >>>= 8;
    }
    return Buffer.from(ret);
}
/**
 * Abstract base class for all message options. Provides methods to parse and serialize.
 */
class Option {
    constructor(code, name, rawValue) {
        this.code = code;
        this.name = name;
        this.rawValue = rawValue;
    }
    /*
          0   1   2   3   4   5   6   7
        +---+---+---+---+---+---+---+---+
        |           | NoCacheKey| U | C |
        +---+---+---+---+---+---+---+---+
    */
    get noCacheKey() {
        return (this.code & 0b11100) === 0b11100;
    }
    get unsafe() {
        return (this.code & 0b10) === 0b10;
    }
    get critical() {
        return (this.code & 0b1) === 0b1;
    }
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
    static parse(buf, prevCode = 0) {
        let delta = (buf[0] >>> 4) & 0b1111;
        let length = buf[0] & 0b1111;
        let dataStart = 1;
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
        const rawValue = Buffer.from(buf.slice(dataStart, dataStart + length));
        const code = prevCode + delta;
        return {
            result: optionConstructors[code](rawValue),
            readBytes: dataStart + length,
        };
    }
    /**
     * serializes this option into a buffer
     * @param prevCode - The option code of the previous option
     */
    serialize(prevCode) {
        let delta = this.code - prevCode;
        let extraDelta = -1;
        let length = this.rawValue.length;
        let extraLength = -1;
        const totalLength = 1
            + (delta >= 13 ? 1 : 0)
            + (delta >= 269 ? 1 : 0)
            + (length >= 13 ? 1 : 0)
            + (length >= 269 ? 1 : 0)
            + length;
        const ret = Buffer.allocUnsafe(totalLength);
        let dataStart = 1;
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
    }
}
exports.Option = Option;
/**
 * Specialized Message option for numeric contents
 */
class NumericOption extends Option {
    constructor(code, name, repeatable, maxLength, rawValue) {
        super(code, name, rawValue);
        this.name = name;
        this.repeatable = repeatable;
        this.maxLength = maxLength;
    }
    get value() {
        return this.rawValue.reduce((acc, cur) => acc * 256 + cur, 0);
    }
    set value(value) {
        const ret = [];
        while (value > 0) {
            ret.unshift(value & 0xff);
            value >>>= 8;
        }
        if (ret.length > this.maxLength) {
            throw new Error("cannot serialize this value because it is too large");
        }
        this.rawValue = Buffer.from(ret);
    }
    static create(code, name, repeatable, maxLength, rawValue) {
        return new NumericOption(code, name, repeatable, maxLength, rawValue);
    }
}
exports.NumericOption = NumericOption;
/**
 * Specialized Message options for binary (and empty) content.
 */
class BinaryOption extends Option {
    constructor(code, name, repeatable, minLength, maxLength, rawValue) {
        super(code, name, rawValue);
        this.name = name;
        this.repeatable = repeatable;
        this.minLength = minLength;
        this.maxLength = maxLength;
    }
    get value() {
        return this.rawValue;
    }
    set value(value) {
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
    }
    static create(code, name, repeatable, minLength, maxLength, rawValue) {
        return new BinaryOption(code, name, repeatable, minLength, maxLength, rawValue);
    }
}
exports.BinaryOption = BinaryOption;
/**
 * Specialized Message options for string content.
 */
class StringOption extends Option {
    constructor(code, name, repeatable, minLength, maxLength, rawValue) {
        super(code, name, rawValue);
        this.name = name;
        this.repeatable = repeatable;
        this.minLength = minLength;
        this.maxLength = maxLength;
    }
    get value() {
        return this.rawValue.toString("utf8");
    }
    set value(value) {
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
    }
    static create(code, name, repeatable, minLength, maxLength, rawValue) {
        return new StringOption(code, name, repeatable, minLength, maxLength, rawValue);
    }
}
exports.StringOption = StringOption;
/**
 * all defined assignments for instancing Options
 */
const optionConstructors = {};
function defineOptionConstructor(
    // tslint:disable-next-line:ban-types
    constructor, code, name, repeatable, ...args) {
    optionConstructors[code] = optionConstructors[name] =
        constructor.create.bind(constructor, ...[code, name, repeatable, ...args]);
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
    UriHost: (hostname) => optionConstructors["Uri-Host"](Buffer.from(hostname)),
    UriPort: (port) => optionConstructors["Uri-Port"](numberToBuffer(port)),
    UriPath: (pathname) => optionConstructors["Uri-Path"](Buffer.from(pathname)),
    LocationPath: (pathname) => optionConstructors["Location-Path"](Buffer.from(pathname)),
    ContentFormat: (format) => optionConstructors["Content-Format"](numberToBuffer(format)),
    // tslint:disable-next-line:no-string-literal
    Observe: (observe) => optionConstructors["Observe"](Buffer.from([observe ? 0 : 1])),
});
