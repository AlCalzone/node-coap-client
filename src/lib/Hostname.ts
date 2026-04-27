import { lookup } from "dns/promises";
import { isIPv4, isIPv6 } from "net";

/** Converts the given hostname to be used in an URL. Wraps IPv6 addresses in square brackets */
export function getURLSafeHostname(hostname: string): string {
	if (isIPv6(hostname)) return `[${hostname}]`;
	return hostname;
}

export function getSocketAddressFromURLSafeHostnameWithoutLookup(hostname: string): string {
	// IPv4 addresses are fine
	if (isIPv4(hostname)) return hostname;
	// IPv6 addresses are wrapped in [], which need to be removed
	if (/^\[.+\]$/.test(hostname)) return hostname.slice(1, -1);
	return hostname;
}

/** Takes an URL-safe hostname and converts it to an address to be used in UDP sockets */
export async function getSocketAddressFromURLSafeHostname(hostname: string): Promise<string> {
	// IPv4 addresses are fine
	if (isIPv4(hostname)) return hostname;
	// IPv6 addresses are wrapped in [], which need to be removed
	if (/^\[.+\]$/.test(hostname)) {
		const potentialIPv6 = hostname.slice(1, -1);
		if (isIPv6(potentialIPv6)) return potentialIPv6;
	}
	// This is a hostname, look it up
	try {
		const addresses = await lookup(hostname, { all: true });
		if (addresses[0]?.address) return addresses[0].address;
	} catch {
		// Lookup failed, continue working with the hostname
	}
	return hostname;
}
