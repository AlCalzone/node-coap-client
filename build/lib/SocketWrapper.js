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
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiU29ja2V0V3JhcHBlci5qcyIsInNvdXJjZVJvb3QiOiJEOi9kZXYvYm9uYW4vbm9kZS1jb2FwLWNsaWVudC9zcmMvIiwic291cmNlcyI6WyJsaWIvU29ja2V0V3JhcHBlci50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7Ozs7Ozs7Ozs7QUFDQSxpQ0FBc0M7QUFDdEMscURBQXdDO0FBR3hDO0lBQW1DLGlDQUFZO0lBSzlDLHVCQUFtQixNQUFrQztRQUFyRCxZQUNDLGlCQUFPLFNBYVA7UUFka0IsWUFBTSxHQUFOLE1BQU0sQ0FBNEI7UUFFcEQsS0FBSSxDQUFDLE1BQU0sR0FBRyxDQUFDLE1BQU0sWUFBWSx1QkFBSSxDQUFDLE1BQU0sQ0FBQyxDQUFDO1FBQzdDLE1BQWM7YUFDYixFQUFFLENBQUMsU0FBUyxFQUFFLFVBQUMsT0FBZSxFQUFFLEtBQXVCO1lBQ3ZELEtBQUksQ0FBQyxJQUFJLENBQUMsU0FBUyxFQUFFLE9BQU8sRUFBRSxLQUFLLENBQUMsQ0FBQztRQUN0QyxDQUFDLENBQUM7YUFDRCxFQUFFLENBQUMsT0FBTyxFQUFFLFVBQUMsR0FBVTtZQUN2QixLQUFJLENBQUMsSUFBSSxDQUFDLE9BQU8sRUFBRSxHQUFHLENBQUMsQ0FBQztRQUN6QixDQUFDLENBQUM7YUFDRCxFQUFFLENBQUMsT0FBTyxFQUFFO1lBQ1osS0FBSSxDQUFDLElBQUksQ0FBQyxPQUFPLENBQUMsQ0FBQztRQUNwQixDQUFDLENBQUMsQ0FDRDs7SUFDSCxDQUFDO0lBRU0sNEJBQUksR0FBWCxVQUFZLEdBQVcsRUFBRSxNQUFjO1FBQ3RDLEVBQUUsQ0FBQyxDQUFDLElBQUksQ0FBQyxRQUFRLENBQUM7WUFBQyxNQUFNLENBQUM7UUFDMUIsRUFBRSxDQUFDLENBQUMsSUFBSSxDQUFDLE1BQU0sQ0FBQyxDQUFDLENBQUM7WUFDaEIsSUFBSSxDQUFDLE1BQXNCLENBQUMsSUFBSSxDQUFDLEdBQUcsQ0FBQyxDQUFDO1FBQ3hDLENBQUM7UUFBQyxJQUFJLENBQUMsQ0FBQztZQUNOLElBQUksQ0FBQyxNQUF1QixDQUFDLElBQUksQ0FBQyxHQUFHLEVBQUUsTUFBTSxDQUFDLElBQUksRUFBRSxNQUFNLENBQUMsUUFBUSxDQUFDLENBQUM7UUFDdkUsQ0FBQztJQUNGLENBQUM7SUFFTSw2QkFBSyxHQUFaO1FBQ0MsRUFBRSxDQUFDLENBQUMsSUFBSSxDQUFDLFFBQVEsQ0FBQztZQUFDLE1BQU0sQ0FBQztRQUMxQixJQUFJLENBQUMsUUFBUSxHQUFHLElBQUksQ0FBQztRQUNyQixFQUFFLENBQUMsQ0FBQyxJQUFJLENBQUMsTUFBTSxDQUFDLENBQUMsQ0FBQztZQUNoQixJQUFJLENBQUMsTUFBc0IsQ0FBQyxLQUFLLEVBQUUsQ0FBQztRQUN0QyxDQUFDO1FBQUMsSUFBSSxDQUFDLENBQUM7WUFDTixJQUFJLENBQUMsTUFBdUIsQ0FBQyxLQUFLLEVBQUUsQ0FBQztRQUN2QyxDQUFDO0lBQ0YsQ0FBQztJQUNGLG9CQUFDO0FBQUQsQ0FBQyxBQXZDRCxDQUFtQyxxQkFBWSxHQXVDOUM7QUF2Q1ksc0NBQWEifQ==