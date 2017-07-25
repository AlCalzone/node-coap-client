"use strict";
var __extends = (this && this.__extends) || (function () {
    var extendStatics = Object.setPrototypeOf ||
        ({ __proto__: [] } instanceof Array && function (d, b) { d.__proto__ = b; }) ||
        function (d, b) { for (var p in b) if (b.hasOwnProperty(p)) d[p] = b[p]; };
    return function (d, b) {
        extendStatics(d, b);
        function __() { this.constructor = d; }
        d.prototype = b === null ? Object.create(b) : (__.prototype = b.prototype, new __());
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
var node_dtls_client_1 = require("node-dtls-client");
var events_1 = require("events");
var SocketWrapper = (function (_super) {
    __extends(SocketWrapper, _super);
    function SocketWrapper(socket) {
        var _this = _super.call(this) || this;
        _this.socket = socket;
        _this.isDtls = (socket instanceof node_dtls_client_1.dtls.Socket);
        socket.on("message", function (message, rinfo) {
            console.log("got a message: " + message.toString("hex"));
            _this.emit("message", message, rinfo);
        });
        return _this;
    }
    SocketWrapper.prototype.send = function (msg, origin) {
        if (this.isDtls) {
            this.socket.send(msg);
        }
        else {
            this.socket.send(msg, origin.port, origin.hostname);
        }
    };
    SocketWrapper.prototype.close = function () {
        if (this.isDtls) {
            this.socket.close();
        }
        else {
            this.socket.close();
        }
    };
    return SocketWrapper;
}(events_1.EventEmitter));
exports.SocketWrapper = SocketWrapper;
//# sourceMappingURL=SocketWrapper.js.map