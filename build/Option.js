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
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiT3B0aW9uLmpzIiwic291cmNlUm9vdCI6IkM6L1VzZXJzL0RvbWluaWMvRG9jdW1lbnRzL1Zpc3VhbCBTdHVkaW8gMjAxNy9SZXBvc2l0b3JpZXMvbm9kZS1jb2FwLWNsaWVudC9zcmMvIiwic291cmNlcyI6WyJPcHRpb24udHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6Ijs7QUFFQSx3QkFBd0IsS0FBYTtJQUNwQyxNQUFNLEdBQUcsR0FBRyxFQUFFLENBQUM7SUFDZixPQUFPLEtBQUssR0FBRyxDQUFDLEVBQUUsQ0FBQztRQUNsQixHQUFHLENBQUMsT0FBTyxDQUFDLEtBQUssR0FBRyxJQUFJLENBQUMsQ0FBQztRQUMxQixLQUFLLE1BQU0sQ0FBQyxDQUFDO0lBQ2QsQ0FBQztJQUNELE1BQU0sQ0FBQyxNQUFNLENBQUMsSUFBSSxDQUFDLEdBQUcsQ0FBQyxDQUFDO0FBQ3pCLENBQUM7QUFFRDs7R0FFRztBQUNIO0lBRUMsWUFDaUIsSUFBWSxFQUNaLElBQVksRUFDckIsUUFBZ0I7UUFGUCxTQUFJLEdBQUosSUFBSSxDQUFRO1FBQ1osU0FBSSxHQUFKLElBQUksQ0FBUTtRQUNyQixhQUFRLEdBQVIsUUFBUSxDQUFRO0lBR3hCLENBQUM7SUFFRjs7Ozs7TUFLRTtJQUNELElBQVcsVUFBVTtRQUNwQixNQUFNLENBQUMsQ0FBQyxJQUFJLENBQUMsSUFBSSxHQUFHLE9BQU8sQ0FBQyxLQUFLLE9BQU8sQ0FBQztJQUMxQyxDQUFDO0lBQ0QsSUFBVyxNQUFNO1FBQ2hCLE1BQU0sQ0FBQyxDQUFDLElBQUksQ0FBQyxJQUFJLEdBQUcsSUFBSSxDQUFDLEtBQUssSUFBSSxDQUFDO0lBQ3BDLENBQUM7SUFDRCxJQUFXLFFBQVE7UUFDbEIsTUFBTSxDQUFDLENBQUMsSUFBSSxDQUFDLElBQUksR0FBRyxHQUFHLENBQUMsS0FBSyxHQUFHLENBQUM7SUFDbEMsQ0FBQztJQUVGOzs7Ozs7Ozs7Ozs7Ozs7O01BZ0JFO0lBRUQ7Ozs7T0FJRztJQUNJLE1BQU0sQ0FBQyxLQUFLLENB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