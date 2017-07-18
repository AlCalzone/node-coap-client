export class Option {

	constructor(
		public readonly code: number,
		public rawValue: Buffer
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
	static parse(buf: Buffer, prevCode: number = 0): {result: Option, readBytes: number} {
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

		return {
			result: new Option(prevCode + delta, rawValue),
			readBytes: dataStart + length
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
		let totalLength = 
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
			dataStart += 1
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
			dataStart += 1			
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

