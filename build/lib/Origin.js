"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var nodeUrl = require("url");
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
    Origin.parse = function (origin) {
        return Origin.fromUrl(nodeUrl.parse(origin));
    };
    return Origin;
}());
exports.Origin = Origin;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiT3JpZ2luLmpzIiwic291cmNlUm9vdCI6IkM6L1VzZXJzL0RvbWluaWMvRG9jdW1lbnRzL1Zpc3VhbCBTdHVkaW8gMjAxNy9SZXBvc2l0b3JpZXMvbm9kZS1jb2FwLWNsaWVudC9zcmMvIiwic291cmNlcyI6WyJsaWIvT3JpZ2luLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7O0FBQUEsNkJBQStCO0FBRS9COztHQUVHO0FBQ0g7SUFDQyxnQkFDUSxRQUFnQixFQUNoQixRQUFnQixFQUNoQixJQUFZO1FBRlosYUFBUSxHQUFSLFFBQVEsQ0FBUTtRQUNoQixhQUFRLEdBQVIsUUFBUSxDQUFRO1FBQ2hCLFNBQUksR0FBSixJQUFJLENBQVE7SUFDakIsQ0FBQztJQUVHLHlCQUFRLEdBQWY7UUFDQyxNQUFNLENBQUksSUFBSSxDQUFDLFFBQVEsVUFBSyxJQUFJLENBQUMsUUFBUSxTQUFJLElBQUksQ0FBQyxJQUFNLENBQUM7SUFDMUQsQ0FBQztJQUVhLGNBQU8sR0FBckIsVUFBc0IsR0FBZ0I7UUFDckMsTUFBTSxDQUFDLElBQUksTUFBTSxDQUFDLEdBQUcsQ0FBQyxRQUFRLEVBQUUsR0FBRyxDQUFDLFFBQVEsRUFBRSxDQUFDLEdBQUcsQ0FBQyxJQUFJLENBQUMsQ0FBQztJQUMxRCxDQUFDO0lBRWEsWUFBSyxHQUFuQixVQUFvQixNQUFjO1FBQ2pDLE1BQU0sQ0FBQyxNQUFNLENBQUMsT0FBTyxDQUFDLE9BQU8sQ0FBQyxLQUFLLENBQUMsTUFBTSxDQUFDLENBQUMsQ0FBQztJQUM5QyxDQUFDO0lBQ0YsYUFBQztBQUFELENBQUMsQUFsQkQsSUFrQkM7QUFsQlksd0JBQU0ifQ==