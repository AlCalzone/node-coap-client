import * as dns from "dns";
import { isIPv4, isIPv6 } from "net";

/** Converts the given hostname to be used in an URL. Wraps IPv6 addresses in square brackets */
export function getURLSafeHostname(hostname: string): string {
	if (isIPv6(hostname)) return `[${hostname}]`;
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
		const address = await lookupAsync(hostname);
		// We found an address
		if (address) return address;
	} catch (e) {
		// Lookup failed, continue working with the hostname
	}
	return hostname;
}

/** Tries to look up a hostname and returns the first IP address found */
function lookupAsync(hostname: string): Promise<string> {
	return new Promise<string>((resolve, reject) => {
		dns.lookup(hostname, {all: true}, (err, addresses) => {
			if (err) return reject(err);
			resolve(addresses[0].address);
		});
	});
}
