"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.getSocketAddressFromURLSafeHostname = exports.getURLSafeHostname = void 0;
const dns = require("dns");
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
    return __awaiter(this, void 0, void 0, function* () {
        // IPv4 addresses are fine
        if (net_1.isIPv4(hostname))
            return hostname;
        // IPv6 addresses are wrapped in [], which need to be removed
        if (/^\[.+\]$/.test(hostname)) {
            const potentialIPv6 = hostname.slice(1, -1);
            if (net_1.isIPv6(potentialIPv6))
                return potentialIPv6;
        }
        // This is a hostname, look it up
        try {
            const address = yield lookupAsync(hostname);
            // We found an address
            if (address)
                return address;
        }
        catch (e) {
            // Lookup failed, continue working with the hostname
        }
        return hostname;
    });
}
exports.getSocketAddressFromURLSafeHostname = getSocketAddressFromURLSafeHostname;
/** Tries to look up a hostname and returns the first IP address found */
function lookupAsync(hostname) {
    return new Promise((resolve, reject) => {
        dns.lookup(hostname, { all: true }, (err, addresses) => {
            if (err)
                return reject(err);
            resolve(addresses[0].address);
        });
    });
}
