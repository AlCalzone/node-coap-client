/// <reference types="node" />
import { ContentFormats } from "./ContentFormats";
/**
 * All defined option names
 */
export declare type OptionName = "Observe" | "Uri-Port" | "Content-Format" | "Max-Age" | "Accept" | "Block2" | "Block1" | "Size2" | "Size1" | "If-Match" | "ETag" | "If-None-Match" | "Uri-Host" | "Location-Path" | "Uri-Path" | "Uri-Query" | "Location-Query" | "Proxy-Uri" | "Proxy-Scheme";
/**
 * Abstract base class for all message options. Provides methods to parse and serialize.
 */
export declare abstract class Option {
    readonly code: number;
    readonly name: OptionName;
    rawValue: Buffer;
    constructor(code: number, name: OptionName, rawValue: Buffer);
    get noCacheKey(): boolean;
    get unsafe(): boolean;
    get critical(): boolean;
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
    readonly name: OptionName;
    readonly repeatable: boolean;
    readonly maxLength: number;
    constructor(code: number, name: OptionName, repeatable: boolean, maxLength: number, rawValue: Buffer);
    get value(): number;
    set value(value: number);
    static create(code: number, name: OptionName, repeatable: boolean, maxLength: number, rawValue: Buffer): NumericOption;
    toString(): string;
}
/**
 * Specialized Message optionis for blockwise transfer
 */
export declare class BlockOption extends NumericOption {
    static create(code: number, name: OptionName, repeatable: boolean, maxLength: number, rawValue: Buffer): BlockOption;
    /**
     * The size exponent of this block in the range 0..6
     * The actual block size is calculated by 2**(4 + exp)
     */
    get sizeExponent(): number;
    set sizeExponent(value: number);
    /**
     * The size of this block in bytes
     */
    get blockSize(): number;
    /**
     * Indicates if there are more blocks following after this one.
     */
    get isLastBlock(): boolean;
    set isLastBlock(value: boolean);
    /**
     * The sequence number of this block.
     * When present in a request message, this determines the number of the block being requested
     * When present in a response message, this indicates the number of the provided block
     */
    get blockNumber(): number;
    set blockNumber(value: number);
    /**
     * Returns the position of the first byte of this block in the complete message
     */
    get byteOffset(): number;
    toString(): string;
}
/**
 * Specialized Message options for binary (and empty) content.
 */
export declare class BinaryOption extends Option {
    readonly name: OptionName;
    readonly repeatable: boolean;
    readonly minLength: number;
    readonly maxLength: number;
    constructor(code: number, name: OptionName, repeatable: boolean, minLength: number, maxLength: number, rawValue: Buffer);
    get value(): Buffer;
    set value(value: Buffer);
    static create(code: number, name: OptionName, repeatable: boolean, minLength: number, maxLength: number, rawValue: Buffer): BinaryOption;
    toString(): string;
}
/**
 * Specialized Message options for string content.
 */
export declare class StringOption extends Option {
    readonly name: OptionName;
    readonly repeatable: boolean;
    readonly minLength: number;
    readonly maxLength: number;
    constructor(code: number, name: OptionName, repeatable: boolean, minLength: number, maxLength: number, rawValue: Buffer);
    get value(): string;
    set value(value: string);
    static create(code: number, name: OptionName, repeatable: boolean, minLength: number, maxLength: number, rawValue: Buffer): StringOption;
    toString(): string;
}
export declare const Options: Readonly<{
    UriHost: (hostname: string) => Option;
    UriPort: (port: number) => Option;
    UriPath: (pathname: string) => Option;
    UriQuery: (query: string) => Option;
    LocationPath: (pathname: string) => Option;
    ContentFormat: (format: ContentFormats) => Option;
    Observe: (observe: boolean) => Option;
    Block1: (num: number, isLast: boolean, size: number) => BlockOption;
    Block2: (num: number, isLast: boolean, size: number) => BlockOption;
}>;
/**
 * Searches for a single option in an array of options
 * @param opts The options array to search for the option
 * @param name The name of the option to search for
 */
export declare function findOption(opts: Option[], name: OptionName): Option;
/**
 * Searches for a repeatable option in an array of options
 * @param opts The options array to search for the option
 * @param name The name of the option to search for
 */
export declare function findOptions(opts: Option[], name: OptionName): Option[];
