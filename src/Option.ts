import { ContentFormats } from "./ContentFormats";

function numberToBuffer(value: number): Buffer {
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
export abstract class Option {

	constructor(
		public readonly code: number,
		public readonly name: string,
		public rawValue: Buffer,
	) {

	}

/*
	  0   1   2   3   4   5   6   7
	+---+---+---+---+---+---+---+---+
	|           | NoCacheKey| U | C |
	+---+---+---+---+---+---+---+---+
*/
	public get noCacheKey(): boolean {
		return (this.code & 0b11100) === 0b11100;
	}
	public get unsafe(): boolean {
		return (this.code & 0b10) === 0b10;
	}
	public get critical(): boolean {
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
	public static parse(buf: Buffer, prevCode: number = 0): {result: Option, readBytes: number} {
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
				// all good
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
				// all good
		}

		const rawValue = Buffer.from(buf.slice(dataStart, dataStart + length));
		const code = prevCode + delta;

		return {
			result: optionConstructors[code](rawValue), // new Option(prevCode + delta, rawValue),
			readBytes: dataStart + length,
		};

	}

	/**
	 * serializes this option into a buffer
	 * @param prevCode - The option code of the previous option
	 */
	public serialize(prevCode: number): Buffer {
		let delta = this.code - prevCode;
		let extraDelta = -1;
		let length = this.rawValue.length;
		let extraLength = -1;
		const totalLength =
			1
			+ (delta >= 13 ? 1 : 0)
			+ (delta >= 269 ? 1 : 0)
			+ (length >= 13 ? 1 : 0)
			+ (length >= 269 ? 1 : 0)
			+ length
		;
		const ret = Buffer.allocUnsafe(totalLength);

		let dataStart = 1;
		// check if we need to split the delta in 2 parts
		if (delta < 13) { /* all good */
		} else if (delta < 269) {
			extraDelta = delta - 13;
			delta = 13;
			ret[dataStart] = extraDelta;
			dataStart += 1;
		} else {
			extraDelta = delta - 14;
			delta = 14;
			ret.writeUInt16BE(extraDelta, dataStart);
			dataStart += 2;
		}

		// check if we need to split the length in 2 parts
		if (length < 13) { /* all good */
		} else if (length < 269) {
			extraLength = length - 13;
			length = 13;
			ret[dataStart] = extraLength;
			dataStart += 1;
		} else {
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

/**
 * Specialized Message option for numeric contents
 */
export class NumericOption extends Option {

	constructor(
		code: number,
		public readonly name: string,
		public readonly repeatable: boolean,
		public readonly maxLength: number,
		rawValue: Buffer,
	) {
		super(code, name, rawValue);
	}

	public get value(): number {
		return this.rawValue.reduce((acc, cur) => acc * 256 + cur, 0);
	}
	public set value(value: number) {
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

	public static create(
		code: number,
		name: string,
		repeatable: boolean,
		maxLength: number,
		rawValue: Buffer,
	): NumericOption {
		return new NumericOption(code, name, repeatable, maxLength, rawValue);
	}

}

/**
 * Specialized Message optionis for blockwise transfer
 */
export class BlockOption extends NumericOption {

	/**
	 * The size exponent of this block in the range 0..6
	 * The actual block size is calculated by 2**(4 + exp)
	 */
	public get sizeExponent(): number {
		return this.value & 0b111;
	}
	public set sizeExponent(value: number) {
		if (value < 0 || value > 6) {
			throw new Error("the size exponent must be in the range of 0..6");
		}
		// overwrite the last 3 bits
		this.value = (this.value & ~0b111) | value;
	}
	/**
	 * The size of this block in bytes
	 */
	public get blockSize(): number {
		return 1 << (this.sizeExponent + 4);
	}

	/**
	 * Indicates if there are more blocks following after this one.
	 */
	public get isLastBlock(): boolean {
		const moreBlocks = (this.value & 0b1000) === 0b1000;
		return !moreBlocks;
	}
	public set isLastBlock(value: boolean) {
		const moreBlocks = !value;
		// overwrite the 4th bit
		this.value = (this.value & ~0b1000) | (moreBlocks ? 0b1000 : 0);
	}

	/**
	 * The sequence number of this block.
	 * When present in a request message, this determines the number of the block being requested
	 * When present in a response message, this indicates the number of the provided block
	 */
	public get blockNumber(): number {
		return this.value >>> 4;
	}
	public set blockNumber(value: number) {
		// TODO: check if we need to update the value length
		this.value = (value << 4) | (this.value & 0b1111);
	}

	/**
	 * Returns the position of the first byte of this block in the complete message
	 */
	public get byteOffset(): number {
		// from the spec:
		// Implementation note:  As an implementation convenience, "(val & ~0xF)
		// << (val & 7)", i.e., the option value with the last 4 bits masked
		// out, shifted to the left by the value of SZX, gives the byte
		// position of the first byte of the block being transferred.
		return (this.value & ~0b1111) << (this.value & 0b111);
	}

}

/**
 * Specialized Message options for binary (and empty) content.
 */
export class BinaryOption extends Option {

	constructor(
		code: number,
		public readonly name: string,
		public readonly repeatable: boolean,
		public readonly minLength: number,
		public readonly maxLength: number,
		rawValue: Buffer,
	) {
		super(code, name, rawValue);
	}

	public get value(): Buffer {
		return this.rawValue;
	}
	public set value(value: Buffer) {
		if (value == null) {
			if (this.minLength > 0) throw new Error("cannot assign null to a Buffer with minimum length");
		} else {
			if (value.length < this.minLength || value.length > this.maxLength) {
				throw new Error("The length of the Buffer is outside the specified bounds");
			}
		}
		this.rawValue = value;
	}

	public static create(
		code: number,
		name: string,
		repeatable: boolean,
		minLength: number,
		maxLength: number,
		rawValue: Buffer,
	): BinaryOption {
		return new BinaryOption(code, name, repeatable, minLength, maxLength, rawValue);
	}

}

/**
 * Specialized Message options for string content.
 */
export class StringOption extends Option {

	constructor(
		code: number,
		public readonly name: string,
		public readonly repeatable: boolean,
		public readonly minLength: number,
		public readonly maxLength: number,
		rawValue: Buffer,
	) {
		super(code, name, rawValue);
	}

	public get value(): string {
		return this.rawValue.toString("utf8");
	}
	public set value(value: string) {
		if (value == null) {
			if (this.minLength > 0) throw new Error("cannot assign null to a string with minimum length");
		} else {
			if (value.length < this.minLength || value.length > this.maxLength) {
				throw new Error("The length of the string is outside the specified bounds");
			}
		}
		this.rawValue = Buffer.from(value, "utf8");
	}

	public static create(
		code: number,
		name: string,
		repeatable: boolean,
		minLength: number,
		maxLength: number,
		rawValue: Buffer,
	): StringOption {
		return new StringOption(code, name, repeatable, minLength, maxLength, rawValue);
	}

}

/**
 * all defined assignments for instancing Options
 */
const optionConstructors: {[code: string]: (raw: Buffer) => Option} = {};
function defineOptionConstructor(
	// tslint:disable-next-line:ban-types
	constructor: Function,
	code: number, name: string, repeatable: boolean,
	...args: any[],
): void {
	optionConstructors[code] = optionConstructors[name] =
		(constructor as any).create.bind(constructor, ...[code, name, repeatable, ...args]);
}
defineOptionConstructor(NumericOption, 6, "Observe", false, 3);
defineOptionConstructor(NumericOption, 7, "Uri-Port", false, 2);
defineOptionConstructor(NumericOption, 12, "Content-Format", false, 2);
defineOptionConstructor(NumericOption, 14, "Max-Age", false, 4);
defineOptionConstructor(NumericOption, 17, "Accept", false, 2);
defineOptionConstructor(BlockOption, 23, "Block2", false, 3);
defineOptionConstructor(BlockOption, 27, "Block1", false, 3);
defineOptionConstructor(NumericOption, 28, "Size2", false, 4);
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
export const Options = Object.freeze({
	UriHost: (hostname: string) => optionConstructors["Uri-Host"](Buffer.from(hostname)),
	UriPort: (port: number) => optionConstructors["Uri-Port"](numberToBuffer(port)),
	UriPath: (pathname: string) => optionConstructors["Uri-Path"](Buffer.from(pathname)),

	LocationPath: (pathname: string) => optionConstructors["Location-Path"](Buffer.from(pathname)),

	ContentFormat: (format: ContentFormats) => optionConstructors["Content-Format"](numberToBuffer(format)),
	// tslint:disable-next-line:no-string-literal
	Observe: (observe: boolean) => optionConstructors["Observe"](Buffer.from([observe ? 0 : 1])),
});
