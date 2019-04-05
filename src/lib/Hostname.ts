import { isIPv6 } from "net";

/** Converts the given hostname to be used in an URL. Wraps IPv6 addresses in square brackets */
export function getURLSafeHostname(hostname: string): string {
	if (isIPv6(hostname)) return `[${hostname}]`;
	return hostname;
}

/** Takes an URL-safe hostname and converts it to an address to be used in UDP sockets */
export function getSocketAddressFromURLSafeHostname(hostname: string): string {
	if (/^\[.+\]$/.test(hostname)) {
		const potentialIPv6 = hostname.slice(1, -1);
		if (isIPv6(potentialIPv6)) return potentialIPv6;
	}
	return hostname;
}
