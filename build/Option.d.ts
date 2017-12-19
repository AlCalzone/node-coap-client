/// <reference types="node" />
import { ContentFormats } from "./ContentFormats";
/**
 * Abstract base class for all message options. Provides methods to parse and serialize.
 */
export declare abstract class Option {
    readonly code: number;
    readonly name: string;
    rawValue: Buffer;
    constructor(code: number, name: string, rawValue: Buffer);
    readonly noCacheKey: boolean;
    readonly unsafe: boolean;
    readonly critical: boolean;
    /**
     * parses a CoAP option from the given buffer. The buffer must start at the option
     * @param buf - the buffer to read from
     * @param prevCode - The option code of the previous option
     */
    static parse(buf: Buffer, prevCode?: number): {
        result: Option;
        readBytes: number;
    };
    /**
     * serializes this option into a buffer
     * @param prevCode - The option code of the previous option
     */
    serialize(prevCode: number): Buffer;
}
/**
 * Specialized Message option for numeric contents
 */
export declare class NumericOption extends Option {
    readonly name: string;
    readonly repeatable: boolean;
    readonly maxLength: number;
    constructor(code: number, name: string, repeatable: boolean, maxLength: number, rawValue: Buffer);
    value: number;
    static create(code: number, name: string, repeatable: boolean, maxLength: number, rawValue: Buffer): NumericOption;
    toString(): string;
}
/**
 * Specialized Message optionis for blockwise transfer
 */
export declare class BlockOption extends NumericOption {
    static create(code: number, name: string, repeatable: boolean, maxLength: number, rawValue: Buffer): BlockOption;
    /**
     * The size exponent of this block in the range 0..6
     * The actual block size is calculated by 2**(4 + exp)
     */
    sizeExponent: number;
    /**
     * The size of this block in bytes
     */
    readonly blockSize: number;
    /**
     * Indicates if there are more blocks following after this one.
     */
    isLastBlock: boolean;
    /**
     * The sequence number of this block.
     * When present in a request message, this determines the number of the block being requested
     * When present in a response message, this indicates the number of the provided block
     */
    blockNumber: number;
    /**
     * Returns the position of the first byte of this block in the complete message
     */
    readonly byteOffset: number;
    toString(): string;
}
/**
 * Specialized Message options for binary (and empty) content.
 */
export declare class BinaryOption extends Option {
    readonly name: string;
    readonly repeatable: boolean;
    readonly minLength: number;
    readonly maxLength: number;
    constructor(code: number, name: string, repeatable: boolean, minLength: number, maxLength: number, rawValue: Buffer);
    value: Buffer;
    static create(code: number, name: string, repeatable: boolean, minLength: number, maxLength: number, rawValue: Buffer): BinaryOption;
    toString(): string;
}
/**
 * Specialized Message options for string content.
 */
export declare class StringOption extends Option {
    readonly name: string;
    readonly repeatable: boolean;
    readonly minLength: number;
    readonly maxLength: number;
    constructor(code: number, name: string, repeatable: boolean, minLength: number, maxLength: number, rawValue: Buffer);
    value: string;
    static create(code: number, name: string, repeatable: boolean, minLength: number, maxLength: number, rawValue: Buffer): StringOption;
    toString(): string;
}
export declare const Options: Readonly<{
    UriHost: (hostname: string) => Option;
    UriPort: (port: number) => Option;
    UriPath: (pathname: string) => Option;
    LocationPath: (pathname: string) => Option;
    ContentFormat: (format: ContentFormats) => Option;
    Observe: (observe: boolean) => Option;
    Block1: (num: number, isLast: boolean, size: number) => Option;
    Block2: (num: number, isLast: boolean, size: number) => Option;
}>;
