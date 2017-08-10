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
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiT3JpZ2luLmpzIiwic291cmNlUm9vdCI6IkM6L1VzZXJzL0RvbWluaWMvRG9jdW1lbnRzL1Zpc3VhbCBTdHVkaW8gMjAxNy9SZXBvc2l0b3JpZXMvbm9kZS1jb2FwLWNsaWVudC9zcmMvIiwic291cmNlcyI6WyJsaWIvT3JpZ2luLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7O0FBRUE7O0dBRUc7QUFDSDtJQUNDLGdCQUNRLFFBQWdCLEVBQ2hCLFFBQWdCLEVBQ2hCLElBQVk7UUFGWixhQUFRLEdBQVIsUUFBUSxDQUFRO1FBQ2hCLGFBQVEsR0FBUixRQUFRLENBQVE7UUFDaEIsU0FBSSxHQUFKLElBQUksQ0FBUTtJQUNqQixDQUFDO0lBRUcseUJBQVEsR0FBZjtRQUNDLE1BQU0sQ0FBSSxJQUFJLENBQUMsUUFBUSxVQUFLLElBQUksQ0FBQyxRQUFRLFNBQUksSUFBSSxDQUFDLElBQU0sQ0FBQztJQUMxRCxDQUFDO0lBRWEsY0FBTyxHQUFyQixVQUFzQixHQUFnQjtRQUNyQyxNQUFNLENBQUMsSUFBSSxNQUFNLENBQUMsR0FBRyxDQUFDLFFBQVEsRUFBRSxHQUFHLENBQUMsUUFBUSxFQUFFLENBQUMsR0FBRyxDQUFDLElBQUksQ0FBQyxDQUFDO0lBQzFELENBQUM7SUFDRixhQUFDO0FBQUQsQ0FBQyxBQWRELElBY0M7QUFkWSx3QkFBTSJ9