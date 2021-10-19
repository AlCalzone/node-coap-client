/** Converts the given hostname to be used in an URL. Wraps IPv6 addresses in square brackets */
export declare function getURLSafeHostname(hostname: string): string;
export declare function getSocketAddressFromURLSafeHostnameWithoutLookup(hostname: string): string;
/** Takes an URL-safe hostname and converts it to an address to be used in UDP sockets */
export declare function getSocketAddressFromURLSafeHostname(hostname: string): Promise<string>;
