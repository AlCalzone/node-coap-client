"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const events_1 = require("events");
const node_dtls_client_1 = require("node-dtls-client");
class SocketWrapper extends events_1.EventEmitter {
    constructor(socket) {
        super();
        this.socket = socket;
        this.isDtls = (socket instanceof node_dtls_client_1.dtls.Socket);
        socket
            .on("message", (message, rinfo) => {
            this.emit("message", message, rinfo);
        })
            .on("error", (err) => {
            this.emit("error", err);
        })
            .on("close", () => {
            this.emit("close");
        });
    }
    send(msg, origin) {
        if (this.isClosed)
            return;
        if (this.isDtls) {
            this.socket.send(msg);
        }
        else {
            this.socket.send(msg, origin.port, origin.hostname);
        }
    }
    close() {
        if (this.isClosed)
            return;
        this.isClosed = true;
        if (this.isDtls) {
            this.socket.close();
        }
        else {
            this.socket.close();
        }
    }
}
exports.SocketWrapper = SocketWrapper;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiU29ja2V0V3JhcHBlci5qcyIsInNvdXJjZVJvb3QiOiJDOi9Vc2Vycy9Eb21pbmljL0RvY3VtZW50cy9WaXN1YWwgU3R1ZGlvIDIwMTcvUmVwb3NpdG9yaWVzL25vZGUtY29hcC1jbGllbnQvc3JjLyIsInNvdXJjZXMiOlsibGliL1NvY2tldFdyYXBwZXIudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6Ijs7QUFDQSxtQ0FBc0M7QUFDdEMsdURBQXdDO0FBR3hDLG1CQUEyQixTQUFRLHFCQUFZO0lBSzlDLFlBQW1CLE1BQWtDO1FBQ3BELEtBQUssRUFBRSxDQUFDO1FBRFUsV0FBTSxHQUFOLE1BQU0sQ0FBNEI7UUFFcEQsSUFBSSxDQUFDLE1BQU0sR0FBRyxDQUFDLE1BQU0sWUFBWSx1QkFBSSxDQUFDLE1BQU0sQ0FBQyxDQUFDO1FBQzdDLE1BQWM7YUFDYixFQUFFLENBQUMsU0FBUyxFQUFFLENBQUMsT0FBZSxFQUFFLEtBQXVCO1lBQ3ZELElBQUksQ0FBQyxJQUFJLENBQUMsU0FBUyxFQUFFLE9BQU8sRUFBRSxLQUFLLENBQUMsQ0FBQztRQUN0QyxDQUFDLENBQUM7YUFDRCxFQUFFLENBQUMsT0FBTyxFQUFFLENBQUMsR0FBVTtZQUN2QixJQUFJLENBQUMsSUFBSSxDQUFDLE9BQU8sRUFBRSxHQUFHLENBQUMsQ0FBQztRQUN6QixDQUFDLENBQUM7YUFDRCxFQUFFLENBQUMsT0FBTyxFQUFFO1lBQ1osSUFBSSxDQUFDLElBQUksQ0FBQyxPQUFPLENBQUMsQ0FBQztRQUNwQixDQUFDLENBQUMsQ0FDRDtJQUNILENBQUM7SUFFTSxJQUFJLENBQUMsR0FBVyxFQUFFLE1BQWM7UUFDdEMsRUFBRSxDQUFDLENBQUMsSUFBSSxDQUFDLFFBQVEsQ0FBQztZQUFDLE1BQU0sQ0FBQztRQUMxQixFQUFFLENBQUMsQ0FBQyxJQUFJLENBQUMsTUFBTSxDQUFDLENBQUMsQ0FBQztZQUNoQixJQUFJLENBQUMsTUFBc0IsQ0FBQyxJQUFJLENBQUMsR0FBRyxDQUFDLENBQUM7UUFDeEMsQ0FBQztRQUFDLElBQUksQ0FBQyxDQUFDO1lBQ04sSUFBSSxDQUFDLE1BQXVCLENBQUMsSUFBSSxDQUFDLEdBQUcsRUFBRSxNQUFNLENBQUMsSUFBSSxFQUFFLE1BQU0sQ0FBQyxRQUFRLENBQUMsQ0FBQztRQUN2RSxDQUFDO0lBQ0YsQ0FBQztJQUVNLEtBQUs7UUFDWCxFQUFFLENBQUMsQ0FBQyxJQUFJLENBQUMsUUFBUSxDQUFDO1lBQUMsTUFBTSxDQUFDO1FBQzFCLElBQUksQ0FBQyxRQUFRLEdBQUcsSUFBSSxDQUFDO1FBQ3JCLEVBQUUsQ0FBQyxDQUFDLElBQUksQ0FBQyxNQUFNLENBQUMsQ0FBQyxDQUFDO1lBQ2hCLElBQUksQ0FBQyxNQUFzQixDQUFDLEtBQUssRUFBRSxDQUFDO1FBQ3RDLENBQUM7UUFBQyxJQUFJLENBQUMsQ0FBQztZQUNOLElBQUksQ0FBQyxNQUF1QixDQUFDLEtBQUssRUFBRSxDQUFDO1FBQ3ZDLENBQUM7SUFDRixDQUFDO0NBQ0Q7QUF2Q0Qsc0NBdUNDIn0=