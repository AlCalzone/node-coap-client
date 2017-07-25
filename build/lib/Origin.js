"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
/**
 * Identifies another endpoint (similar to the new WhatWG URL API "origin" property)
 */
var Origin = (function () {
    function Origin(protocol, hostname, port) {
        this.protocol = protocol;
        this.hostname = hostname;
        this.port = port;
    }
    Origin.prototype.toString = function () {
        return this.protocol + "//" + this.hostname + ":" + this.port;
    };
    Origin.fromUrl = function (url) {
        return new Origin(url.protocol, url.hostname, +url.port);
    };
    return Origin;
}());
exports.Origin = Origin;
//# sourceMappingURL=Origin.js.map