"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const net_1 = require("net");
/** Converts the given hostname to be used in an URL. Wraps IPv6 addresses in square brackets */
function getURLSafeHostname(hostname) {
    if (net_1.isIPv6(hostname))
        return `[${hostname}]`;
    return hostname;
}
exports.getURLSafeHostname = getURLSafeHostname;
/** Takes an URL-safe hostname and converts it to an address to be used in UDP sockets */
function getSocketAddressFromURLSafeHostname(hostname) {
    if (/^\[.+\]$/.test(hostname)) {
        const potentialIPv6 = hostname.slice(1, -1);
        if (net_1.isIPv6(potentialIPv6))
            return potentialIPv6;
    }
    return hostname;
}
exports.getSocketAddressFromURLSafeHostname = getSocketAddressFromURLSafeHostname;
