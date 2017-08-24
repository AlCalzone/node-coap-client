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
var events_1 = require("events");
var node_dtls_client_1 = require("node-dtls-client");
var SocketWrapper = (function (_super) {
    __extends(SocketWrapper, _super);
    function SocketWrapper(socket) {
        var _this = _super.call(this) || this;
        _this.socket = socket;
        _this.isDtls = (socket instanceof node_dtls_client_1.dtls.Socket);
        socket
            .on("message", function (message, rinfo) {
            _this.emit("message", message, rinfo);
        })
            .on("error", function (err) {
            _this.emit("error", err);
        })
            .on("close", function () {
            _this.emit("close");
        });
        return _this;
    }
    SocketWrapper.prototype.send = function (msg, origin) {
        if (this.isClosed)
            return;
        if (this.isDtls) {
            this.socket.send(msg);
        }
        else {
            this.socket.send(msg, origin.port, origin.hostname);
        }
    };
    SocketWrapper.prototype.close = function () {
        if (this.isClosed)
            return;
        this.isClosed = true;
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
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiU29ja2V0V3JhcHBlci5qcyIsInNvdXJjZVJvb3QiOiJDOi9Vc2Vycy9Eb21pbmljL0RvY3VtZW50cy9WaXN1YWwgU3R1ZGlvIDIwMTcvUmVwb3NpdG9yaWVzL25vZGUtY29hcC1jbGllbnQvc3JjLyIsInNvdXJjZXMiOlsibGliL1NvY2tldFdyYXBwZXIudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6Ijs7Ozs7Ozs7Ozs7O0FBQ0EsaUNBQXNDO0FBQ3RDLHFEQUF3QztBQUd4QztJQUFtQyxpQ0FBWTtJQUs5Qyx1QkFBbUIsTUFBa0M7UUFBckQsWUFDQyxpQkFBTyxTQWFQO1FBZGtCLFlBQU0sR0FBTixNQUFNLENBQTRCO1FBRXBELEtBQUksQ0FBQyxNQUFNLEdBQUcsQ0FBQyxNQUFNLFlBQVksdUJBQUksQ0FBQyxNQUFNLENBQUMsQ0FBQztRQUM3QyxNQUFjO2FBQ2IsRUFBRSxDQUFDLFNBQVMsRUFBRSxVQUFDLE9BQWUsRUFBRSxLQUF1QjtZQUN2RCxLQUFJLENBQUMsSUFBSSxDQUFDLFNBQVMsRUFBRSxPQUFPLEVBQUUsS0FBSyxDQUFDLENBQUM7UUFDdEMsQ0FBQyxDQUFDO2FBQ0QsRUFBRSxDQUFDLE9BQU8sRUFBRSxVQUFDLEdBQVU7WUFDdkIsS0FBSSxDQUFDLElBQUksQ0FBQyxPQUFPLEVBQUUsR0FBRyxDQUFDLENBQUM7UUFDekIsQ0FBQyxDQUFDO2FBQ0QsRUFBRSxDQUFDLE9BQU8sRUFBRTtZQUNaLEtBQUksQ0FBQyxJQUFJLENBQUMsT0FBTyxDQUFDLENBQUM7UUFDcEIsQ0FBQyxDQUFDLENBQ0Q7O0lBQ0gsQ0FBQztJQUVNLDRCQUFJLEdBQVgsVUFBWSxHQUFXLEVBQUUsTUFBYztRQUN0QyxFQUFFLENBQUMsQ0FBQyxJQUFJLENBQUMsUUFBUSxDQUFDO1lBQUMsTUFBTSxDQUFDO1FBQzFCLEVBQUUsQ0FBQyxDQUFDLElBQUksQ0FBQyxNQUFNLENBQUMsQ0FBQyxDQUFDO1lBQ2hCLElBQUksQ0FBQyxNQUFzQixDQUFDLElBQUksQ0FBQyxHQUFHLENBQUMsQ0FBQztRQUN4QyxDQUFDO1FBQUMsSUFBSSxDQUFDLENBQUM7WUFDTixJQUFJLENBQUMsTUFBdUIsQ0FBQyxJQUFJLENBQUMsR0FBRyxFQUFFLE1BQU0sQ0FBQyxJQUFJLEVBQUUsTUFBTSxDQUFDLFFBQVEsQ0FBQyxDQUFDO1FBQ3ZFLENBQUM7SUFDRixDQUFDO0lBRU0sNkJBQUssR0FBWjtRQUNDLEVBQUUsQ0FBQyxDQUFDLElBQUksQ0FBQyxRQUFRLENBQUM7WUFBQyxNQUFNLENBQUM7UUFDMUIsSUFBSSxDQUFDLFFBQVEsR0FBRyxJQUFJLENBQUM7UUFDckIsRUFBRSxDQUFDLENBQUMsSUFBSSxDQUFDLE1BQU0sQ0FBQyxDQUFDLENBQUM7WUFDaEIsSUFBSSxDQUFDLE1BQXNCLENBQUMsS0FBSyxFQUFFLENBQUM7UUFDdEMsQ0FBQztRQUFDLElBQUksQ0FBQyxDQUFDO1lBQ04sSUFBSSxDQUFDLE1BQXVCLENBQUMsS0FBSyxFQUFFLENBQUM7UUFDdkMsQ0FBQztJQUNGLENBQUM7SUFDRixvQkFBQztBQUFELENBQUMsQUF2Q0QsQ0FBbUMscUJBQVksR0F1QzlDO0FBdkNZLHNDQUFhIn0=