"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Origin = void 0;
const Hostname_1 = require("./Hostname");
const url_1 = require("url");
/**
 * Identifies another endpoint (similar to the new WhatWG URL API "origin" property)
 */
class Origin {
    constructor(protocol, hostname, port) {
        this.protocol = protocol;
        this.hostname = hostname;
        this.port = port;
    }
    toString() {
        return `${this.protocol}//${Hostname_1.getURLSafeHostname(this.hostname)}:${this.port}`;
    }
    static fromUrl(url) {
        return new Origin(url.protocol, url.hostname, +url.port);
    }
    static parse(origin) {
        return Origin.fromUrl(new url_1.URL(origin));
    }
}
exports.Origin = Origin;
