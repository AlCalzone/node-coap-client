"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const nodeUrl = require("url");
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
        return `${this.protocol}//${this.hostname}:${this.port}`;
    }
    static fromUrl(url) {
        return new Origin(url.protocol, url.hostname, +url.port);
    }
    static parse(origin) {
        return Origin.fromUrl(nodeUrl.parse(origin));
    }
}
exports.Origin = Origin;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiT3JpZ2luLmpzIiwic291cmNlUm9vdCI6IkM6L1VzZXJzL0RvbWluaWMvRG9jdW1lbnRzL1Zpc3VhbCBTdHVkaW8gMjAxNy9SZXBvc2l0b3JpZXMvbm9kZS1jb2FwLWNsaWVudC9zcmMvIiwic291cmNlcyI6WyJsaWIvT3JpZ2luLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7O0FBQUEsK0JBQStCO0FBRS9COztHQUVHO0FBQ0g7SUFDQyxZQUNRLFFBQWdCLEVBQ2hCLFFBQWdCLEVBQ2hCLElBQVk7UUFGWixhQUFRLEdBQVIsUUFBUSxDQUFRO1FBQ2hCLGFBQVEsR0FBUixRQUFRLENBQVE7UUFDaEIsU0FBSSxHQUFKLElBQUksQ0FBUTtJQUNqQixDQUFDO0lBRUcsUUFBUTtRQUNkLE1BQU0sQ0FBQyxHQUFHLElBQUksQ0FBQyxRQUFRLEtBQUssSUFBSSxDQUFDLFFBQVEsSUFBSSxJQUFJLENBQUMsSUFBSSxFQUFFLENBQUM7SUFDMUQsQ0FBQztJQUVNLE1BQU0sQ0FBQyxPQUFPLENBQUMsR0FBZ0I7UUFDckMsTUFBTSxDQUFDLElBQUksTUFBTSxDQUFDLEdBQUcsQ0FBQyxRQUFRLEVBQUUsR0FBRyxDQUFDLFFBQVEsRUFBRSxDQUFDLEdBQUcsQ0FBQyxJQUFJLENBQUMsQ0FBQztJQUMxRCxDQUFDO0lBRU0sTUFBTSxDQUFDLEtBQUssQ0FBQyxNQUFjO1FBQ2pDLE1BQU0sQ0FBQyxNQUFNLENBQUMsT0FBTyxDQUFDLE9BQU8sQ0FBQyxLQUFLLENBQUMsTUFBTSxDQUFDLENBQUMsQ0FBQztJQUM5QyxDQUFDO0NBQ0Q7QUFsQkQsd0JBa0JDIn0=