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
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : new P(function (resolve) { resolve(result.value); }).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __generator = (this && this.__generator) || function (thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g;
    return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (_) try {
            if (f = 1, y && (t = y[op[0] & 2 ? "return" : op[0] ? "throw" : "next"]) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [0, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
};
Object.defineProperty(exports, "__esModule", { value: true });
var crypto = require("crypto");
var dgram = require("dgram");
var events_1 = require("events");
var node_dtls_client_1 = require("node-dtls-client");
var nodeUrl = require("url");
var ContentFormats_1 = require("./ContentFormats");
var DeferredPromise_1 = require("./lib/DeferredPromise");
var Origin_1 = require("./lib/Origin");
var SocketWrapper_1 = require("./lib/SocketWrapper");
var Message_1 = require("./Message");
var Option_1 = require("./Option");
// initialize debugging
var debugPackage = require("debug");
var debug = debugPackage("node-coap-client");
// print version info
// tslint:disable-next-line:no-var-requires
var npmVersion = require("../package.json").version;
debug("CoAP client version " + npmVersion);
function urlToString(url) {
    return url.protocol + "//" + url.hostname + ":" + url.port + url.pathname;
}
var PendingRequest = (function (_super) {
    __extends(PendingRequest, _super);
    function PendingRequest(initial) {
        var _this = _super.call(this) || this;
        if (!initial)
            return _this;
        _this.connection = initial.connection;
        _this.url = initial.url;
        _this.originalMessage = initial.originalMessage;
        _this.retransmit = initial.retransmit;
        _this.promise = initial.promise;
        _this.callback = initial.callback;
        _this.keepAlive = initial.keepAlive;
        _this.observe = initial.observe;
        _this._concurrency = initial.concurrency;
        return _this;
    }
    Object.defineProperty(PendingRequest.prototype, "concurrency", {
        get: function () {
            return this._concurrency;
        },
        set: function (value) {
            var changed = value !== this._concurrency;
            this._concurrency = value;
            if (changed)
                this.emit("concurrencyChanged", this);
        },
        enumerable: true,
        configurable: true
    });
    return PendingRequest;
}(events_1.EventEmitter));
// TODO: make configurable
var RETRANSMISSION_PARAMS = {
    ackTimeout: 2,
    ackRandomFactor: 1.5,
    maxRetransmit: 4,
};
var TOKEN_LENGTH = 4;
/** How many concurrent messages are allowed. Should be 1 */
var MAX_CONCURRENCY = 1;
function incrementToken(token) {
    var len = token.length;
    var ret = Buffer.alloc(len, token);
    for (var i = len - 1; i >= 0; i--) {
        if (ret[i] < 0xff) {
            ret[i]++;
            break;
        }
        else {
            ret[i] = 0;
            // continue with the next digit
        }
    }
    return ret;
}
function incrementMessageID(msgId) {
    return (++msgId > 0xffff) ? 1 : msgId;
}
function findOption(opts, name) {
    for (var _i = 0, opts_1 = opts; _i < opts_1.length; _i++) {
        var opt = opts_1[_i];
        if (opt.name === name)
            return opt;
    }
}
function findOptions(opts, name) {
    return opts.filter(function (opt) { return opt.name === name; });
}
/**
 * provides methods to access CoAP server resources
 */
var CoapClient = (function () {
    function CoapClient() {
    }
    /**
     * Sets the security params to be used for the given hostname
     */
    CoapClient.setSecurityParams = function (hostname, params) {
        CoapClient.dtlsParams[hostname] = params;
    };
    /**
     * Closes and forgets about connections, useful if DTLS session is reset on remote end
     * @param originOrHostname - Origin (protocol://hostname:port) or Hostname to reset,
     * omit to reset all connections
     */
    CoapClient.reset = function (originOrHostname) {
        var predicate;
        if (originOrHostname != null) {
            if (typeof originOrHostname === "string") {
                // we were given a hostname, forget the connection if the origin's hostname matches
                predicate = function (originString) { return Origin_1.Origin.parse(originString).hostname === originOrHostname; };
            }
            else {
                // we were given an origin, forget the connection if its string representation matches
                var match_1 = originOrHostname.toString();
                predicate = function (originString) { return originString === match_1; };
            }
        }
        else {
            // we weren't given a filter, forget all connections
            predicate = function (originString) { return true; };
        }
        for (var originString in CoapClient.connections) {
            if (!predicate(originString))
                continue;
            debug("closing connection to " + originString);
            if (CoapClient.connections[originString].socket) {
                CoapClient.connections[originString].socket.close();
            }
            delete CoapClient.connections[originString];
        }
    };
    /**
     * Requests a CoAP resource
     * @param url - The URL to be requested. Must start with coap:// or coaps://
     * @param method - The request method to be used
     * @param payload - The optional payload to be attached to the request
     * @param options - Various options to control the request.
     */
    CoapClient.request = function (url, method, payload, options) {
        return __awaiter(this, void 0, void 0, function () {
            var origin, originString, connection, type, code, messageId, token, tokenString, msgOptions, pathname, pathParts, response, message, retransmit, timeout, req;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        // parse/convert url
                        if (typeof url === "string") {
                            url = nodeUrl.parse(url);
                        }
                        // ensure we have options and set the default params
                        options = options || {};
                        if (options.confirmable == null)
                            options.confirmable = true;
                        if (options.keepAlive == null)
                            options.keepAlive = true;
                        if (options.retransmit == null)
                            options.retransmit = true;
                        origin = Origin_1.Origin.fromUrl(url);
                        originString = origin.toString();
                        return [4 /*yield*/, CoapClient.getConnection(origin)];
                    case 1:
                        connection = _a.sent();
                        type = options.confirmable ? Message_1.MessageType.CON : Message_1.MessageType.NON;
                        code = Message_1.MessageCodes.request[method];
                        messageId = connection.lastMsgId = incrementMessageID(connection.lastMsgId);
                        token = connection.lastToken = incrementToken(connection.lastToken);
                        tokenString = token.toString("hex");
                        payload = payload || Buffer.from([]);
                        msgOptions = [];
                        pathname = url.pathname || "";
                        while (pathname.startsWith("/")) {
                            pathname = pathname.slice(1);
                        }
                        while (pathname.endsWith("/")) {
                            pathname = pathname.slice(0, -1);
                        }
                        pathParts = pathname.split("/");
                        msgOptions.push.apply(msgOptions, pathParts.map(function (part) { return Option_1.Options.UriPath(part); }));
                        // [12] content format
                        msgOptions.push(Option_1.Options.ContentFormat(ContentFormats_1.ContentFormats.application_json));
                        response = DeferredPromise_1.createDeferredPromise();
                        message = CoapClient.createMessage(type, code, messageId, token, msgOptions, payload);
                        if (options.retransmit && type === Message_1.MessageType.CON) {
                            timeout = CoapClient.getRetransmissionInterval();
                            retransmit = {
                                timeout: timeout,
                                jsTimeout: setTimeout(function () { return CoapClient.retransmit(messageId); }, timeout),
                                counter: 0,
                            };
                        }
                        req = new PendingRequest({
                            connection: connection,
                            url: urlToString(url),
                            originalMessage: message,
                            retransmit: retransmit,
                            keepAlive: options.keepAlive,
                            callback: null,
                            observe: false,
                            promise: response,
                            concurrency: 0,
                        });
                        // remember the request
                        CoapClient.rememberRequest(req);
                        // now send the message
                        CoapClient.send(connection, message);
                        return [2 /*return*/, response];
                }
            });
        });
    };
    /**
     * Pings a CoAP endpoint to check if it is alive
     * @param target - The target to be pinged. Must be a string, NodeJS.Url or Origin and has to contain the protocol, host and port.
     * @param timeout - (optional) Timeout in ms, after which the ping is deemed unanswered. Default: 5000ms
     */
    CoapClient.ping = function (target, timeout) {
        if (timeout === void 0) { timeout = 5000; }
        return __awaiter(this, void 0, void 0, function () {
            var originString, connection, e_1, response, messageId, message, req, failTimeout, success, e_2;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        // parse/convert url
                        if (typeof target === "string") {
                            target = Origin_1.Origin.parse(target);
                        }
                        else if (!(target instanceof Origin_1.Origin)) {
                            target = Origin_1.Origin.fromUrl(target);
                        }
                        originString = target.toString();
                        _a.label = 1;
                    case 1:
                        _a.trys.push([1, 3, , 4]);
                        return [4 /*yield*/, CoapClient.getConnection(target)];
                    case 2:
                        connection = _a.sent();
                        return [3 /*break*/, 4];
                    case 3:
                        e_1 = _a.sent();
                        // we didn't even get a connection, so fail the ping
                        return [2 /*return*/, false];
                    case 4:
                        response = DeferredPromise_1.createDeferredPromise();
                        messageId = connection.lastMsgId = incrementMessageID(connection.lastMsgId);
                        message = CoapClient.createMessage(Message_1.MessageType.CON, Message_1.MessageCodes.empty, messageId);
                        req = new PendingRequest({
                            connection: connection,
                            url: originString,
                            originalMessage: message,
                            retransmit: null,
                            keepAlive: true,
                            callback: null,
                            observe: false,
                            promise: response,
                            concurrency: 0,
                        });
                        // remember the request
                        CoapClient.rememberRequest(req);
                        // now send the message
                        CoapClient.send(connection, message);
                        failTimeout = setTimeout(function () { return response.reject(); }, timeout);
                        _a.label = 5;
                    case 5:
                        _a.trys.push([5, 7, 8, 9]);
                        // now wait for success or failure
                        return [4 /*yield*/, response];
                    case 6:
                        // now wait for success or failure
                        _a.sent();
                        success = true;
                        return [3 /*break*/, 9];
                    case 7:
                        e_2 = _a.sent();
                        success = false;
                        return [3 /*break*/, 9];
                    case 8:
                        // cleanup
                        clearTimeout(failTimeout);
                        CoapClient.forgetRequest({ request: req });
                        return [7 /*endfinally*/];
                    case 9: return [2 /*return*/, success];
                }
            });
        });
    };
    /**
     * Re-Sends a message in case it got lost
     * @param msgID
     */
    CoapClient.retransmit = function (msgID) {
        // find the request with all the information
        var request = CoapClient.findRequest({ msgID: msgID });
        if (request == null || request.retransmit == null)
            return;
        // are we over the limit?
        if (request.retransmit.counter > RETRANSMISSION_PARAMS.maxRetransmit) {
            // if this is a one-time request, reject the response promise
            if (request.promise !== null) {
                request.promise.reject(new Error("Retransmit counter exceeded"));
            }
            // then stop retransmitting and forget the request
            CoapClient.forgetRequest({ request: request });
            return;
        }
        debug("retransmitting message " + msgID.toString(16) + ", try #" + (request.retransmit.counter + 1));
        // resend the message
        CoapClient.send(request.connection, request.originalMessage);
        // and increase the params
        request.retransmit.counter++;
        request.retransmit.timeout *= 2;
        request.retransmit.jsTimeout = setTimeout(function () { return CoapClient.retransmit(msgID); }, request.retransmit.timeout);
    };
    CoapClient.getRetransmissionInterval = function () {
        return Math.round(1000 /*ms*/ * RETRANSMISSION_PARAMS.ackTimeout *
            (1 + Math.random() * (RETRANSMISSION_PARAMS.ackRandomFactor - 1)));
    };
    CoapClient.stopRetransmission = function (request) {
        if (request.retransmit == null)
            return;
        clearTimeout(request.retransmit.jsTimeout);
        request.retransmit = null;
    };
    /**
     * Observes a CoAP resource
     * @param url - The URL to be requested. Must start with coap:// or coaps://
     * @param method - The request method to be used
     * @param payload - The optional payload to be attached to the request
     * @param options - Various options to control the request.
     */
    CoapClient.observe = function (url, method, callback, payload, options) {
        return __awaiter(this, void 0, void 0, function () {
            var origin, originString, connection, type, code, messageId, token, tokenString, msgOptions, pathname, pathParts, response, message, retransmit, timeout, req;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        // parse/convert url
                        if (typeof url === "string") {
                            url = nodeUrl.parse(url);
                        }
                        // ensure we have options and set the default params
                        options = options || {};
                        if (options.confirmable == null)
                            options.confirmable = true;
                        if (options.keepAlive == null)
                            options.keepAlive = true;
                        if (options.retransmit == null)
                            options.retransmit = true;
                        origin = Origin_1.Origin.fromUrl(url);
                        originString = origin.toString();
                        return [4 /*yield*/, CoapClient.getConnection(origin)];
                    case 1:
                        connection = _a.sent();
                        type = options.confirmable ? Message_1.MessageType.CON : Message_1.MessageType.NON;
                        code = Message_1.MessageCodes.request[method];
                        messageId = connection.lastMsgId = incrementMessageID(connection.lastMsgId);
                        token = connection.lastToken = incrementToken(connection.lastToken);
                        tokenString = token.toString("hex");
                        payload = payload || Buffer.from([]);
                        msgOptions = [];
                        // [6] observe?
                        msgOptions.push(Option_1.Options.Observe(true));
                        pathname = url.pathname || "";
                        while (pathname.startsWith("/")) {
                            pathname = pathname.slice(1);
                        }
                        while (pathname.endsWith("/")) {
                            pathname = pathname.slice(0, -1);
                        }
                        pathParts = pathname.split("/");
                        msgOptions.push.apply(msgOptions, pathParts.map(function (part) { return Option_1.Options.UriPath(part); }));
                        // [12] content format
                        msgOptions.push(Option_1.Options.ContentFormat(ContentFormats_1.ContentFormats.application_json));
                        response = DeferredPromise_1.createDeferredPromise();
                        message = CoapClient.createMessage(type, code, messageId, token, msgOptions, payload);
                        if (options.retransmit && type === Message_1.MessageType.CON) {
                            timeout = CoapClient.getRetransmissionInterval();
                            retransmit = {
                                timeout: timeout,
                                jsTimeout: setTimeout(function () { return CoapClient.retransmit(messageId); }, timeout),
                                counter: 0,
                            };
                        }
                        req = new PendingRequest({
                            connection: connection,
                            url: urlToString(url),
                            originalMessage: message,
                            retransmit: retransmit,
                            keepAlive: options.keepAlive,
                            callback: callback,
                            observe: true,
                            promise: null,
                            concurrency: 0,
                        });
                        // remember the request
                        CoapClient.rememberRequest(req);
                        // now send the message
                        CoapClient.send(connection, message);
                        return [2 /*return*/];
                }
            });
        });
    };
    /**
     * Stops observation of the given url
     */
    CoapClient.stopObserving = function (url) {
        // parse/convert url
        if (typeof url === "string") {
            url = nodeUrl.parse(url);
        }
        // normalize the url
        var urlString = urlToString(url);
        // and forget the request if we have one remembered
        CoapClient.forgetRequest({ url: urlString });
    };
    CoapClient.onMessage = function (origin, message, rinfo) {
        // parse the CoAP message
        var coapMsg = Message_1.Message.parse(message);
        debug("received message: ID=" + coapMsg.messageId + ((coapMsg.token && coapMsg.token.length) ? (", token=" + coapMsg.token.toString("hex")) : ""));
        if (coapMsg.code.isEmpty()) {
            // ACK or RST
            // see if we have a request for this message id
            var request = CoapClient.findRequest({ msgID: coapMsg.messageId });
            if (request != null) {
                // reduce the request's concurrency, since it was handled on the server
                request.concurrency = 0;
                // handle the message
                switch (coapMsg.type) {
                    case Message_1.MessageType.ACK:
                        debug("received ACK for " + coapMsg.messageId.toString(16) + ", stopping retransmission...");
                        // the other party has received the message, stop resending
                        CoapClient.stopRetransmission(request);
                        break;
                    case Message_1.MessageType.RST:
                        if (request.originalMessage.type === Message_1.MessageType.CON &&
                            request.originalMessage.code === Message_1.MessageCodes.empty) {
                            // resolve the promise
                            debug("received response to ping " + coapMsg.messageId.toString(16));
                            request.promise.resolve();
                        }
                        else {
                            // the other party doesn't know what to do with the request, forget it
                            debug("received RST for " + coapMsg.messageId.toString(16) + ", forgetting the request...");
                            CoapClient.forgetRequest({ request: request });
                        }
                        break;
                }
            }
        }
        else if (coapMsg.code.isRequest()) {
            // we are a client implementation, we should not get requests
            // ignore them
        }
        else if (coapMsg.code.isResponse()) {
            // this is a response, find out what to do with it
            if (coapMsg.token && coapMsg.token.length) {
                // this message has a token, check which request it belongs to
                var tokenString = coapMsg.token.toString("hex");
                var request = CoapClient.findRequest({ token: tokenString });
                if (request) {
                    // if the message is an acknowledgement, stop resending
                    if (coapMsg.type === Message_1.MessageType.ACK) {
                        debug("received ACK for " + coapMsg.messageId.toString(16) + ", stopping retransmission...");
                        CoapClient.stopRetransmission(request);
                        // reduce the request's concurrency, since it was handled on the server
                        request.concurrency = 0;
                    }
                    // parse options
                    var contentFormat = null;
                    if (coapMsg.options && coapMsg.options.length) {
                        // see if the response contains information about the content format
                        var optCntFmt = findOption(coapMsg.options, "Content-Format");
                        if (optCntFmt)
                            contentFormat = optCntFmt.value;
                    }
                    // prepare the response
                    var response = {
                        code: coapMsg.code,
                        format: contentFormat,
                        payload: coapMsg.payload,
                    };
                    if (request.observe) {
                        // call the callback
                        request.callback(response);
                    }
                    else {
                        // resolve the promise
                        request.promise.resolve(response);
                        // after handling one-time requests, delete the info about them
                        CoapClient.forgetRequest({ request: request });
                    }
                    // also acknowledge the packet if neccessary
                    if (coapMsg.type === Message_1.MessageType.CON) {
                        debug("sending ACK for " + coapMsg.messageId.toString(16));
                        var ACK = CoapClient.createMessage(Message_1.MessageType.ACK, Message_1.MessageCodes.empty, coapMsg.messageId);
                        CoapClient.send(request.connection, ACK, true);
                    }
                }
                else {
                    // no request found for this token, send RST so the server stops sending
                    // try to find the connection that belongs to this origin
                    var originString = origin.toString();
                    if (CoapClient.connections.hasOwnProperty(originString)) {
                        var connection = CoapClient.connections[originString];
                        // and send the reset
                        debug("sending RST for " + coapMsg.messageId.toString(16));
                        var RST = CoapClient.createMessage(Message_1.MessageType.RST, Message_1.MessageCodes.empty, coapMsg.messageId);
                        CoapClient.send(connection, RST, true);
                    }
                } // request != null?
            } // (coapMsg.token && coapMsg.token.length)
        } // (coapMsg.code.isResponse())
    };
    /**
     * Creates a message with the given parameters
     * @param type
     * @param code
     * @param messageId
     * @param token
     * @param options
     * @param payload
     */
    CoapClient.createMessage = function (type, code, messageId, token, options, // do we need this?
        payload) {
        if (token === void 0) { token = null; }
        if (options === void 0) { options = []; }
        if (payload === void 0) { payload = null; }
        return new Message_1.Message(0x01, type, code, messageId, token, options, payload);
    };
    /**
     * Send a CoAP message to the given endpoint
     * @param connection The connection to send the message on
     * @param message The message to send
     * @param highPriority Whether the message should be prioritized
     */
    CoapClient.send = function (connection, message, highPriority) {
        if (highPriority === void 0) { highPriority = false; }
        // Put the message in the queue
        if (highPriority) {
            // insert at the end of the high-priority queue
            CoapClient.sendQueue.splice(CoapClient.sendQueueHighPrioCount, 0, { connection: connection, message: message });
            CoapClient.sendQueueHighPrioCount++;
        }
        else {
            // at the end
            CoapClient.sendQueue.push({ connection: connection, message: message });
        }
        debug("added message to send queue, new length = " + CoapClient.sendQueue.length + " (high prio: " + CoapClient.sendQueueHighPrioCount + ")");
        // if there's a request for this message, listen for concurrency changes
        var request = CoapClient.findRequest({ msgID: message.messageId });
        if (request != null) {
            // and continue working off the queue when it drops
            request.on("concurrencyChanged", function (req) {
                debug("request " + message.messageId.toString(16) + ": concurrency changed => " + req.concurrency);
                if (request.concurrency === 0)
                    CoapClient.workOffSendQueue();
            });
        }
        // start working it off now (maybe)
        CoapClient.workOffSendQueue();
    };
    CoapClient.workOffSendQueue = function () {
        // check if there are messages to send
        if (CoapClient.sendQueue.length === 0) {
            debug("workOffSendQueue > queue empty");
            return;
        }
        // check if we may send a message now
        debug("workOffSendQueue > concurrency = " + CoapClient.calculateConcurrency() + " (MAX " + MAX_CONCURRENCY + ")");
        if (CoapClient.calculateConcurrency() < MAX_CONCURRENCY) {
            // get the next message to send
            var _a = CoapClient.sendQueue.shift(), connection = _a.connection, message = _a.message;
            debug("concurrency low enough, sending message " + message.messageId.toString(16));
            // update the request's concurrency (it's now being handled)
            var request = CoapClient.findRequest({ msgID: message.messageId });
            if (request != null)
                request.concurrency = 1;
            // update the high priority count
            if (CoapClient.sendQueueHighPrioCount > 0)
                CoapClient.sendQueueHighPrioCount--;
            // send the message
            connection.socket.send(message.serialize(), connection.origin);
        }
        // to avoid any deadlocks we didn't think of, re-call this later
        setTimeout(CoapClient.workOffSendQueue, 1000);
    };
    /** Calculates the current concurrency, i.e. how many parallel requests are being handled */
    CoapClient.calculateConcurrency = function () {
        return Object.keys(CoapClient.pendingRequestsByMsgID) // find all requests
            .map(function (msgid) { return CoapClient.pendingRequestsByMsgID[msgid]; })
            .map(function (req) { return req.concurrency; }) // extract their concurrency
            .reduce(function (sum, item) { return sum + item; }, 0) // and sum it up
        ;
    };
    /**
     * Remembers a request for resending lost messages and tracking responses and updates
     * @param request
     * @param byUrl
     * @param byMsgID
     * @param byToken
     */
    CoapClient.rememberRequest = function (request, byUrl, byMsgID, byToken) {
        if (byUrl === void 0) { byUrl = true; }
        if (byMsgID === void 0) { byMsgID = true; }
        if (byToken === void 0) { byToken = true; }
        var tokenString = "";
        if (byToken && request.originalMessage.token != null) {
            tokenString = request.originalMessage.token.toString("hex");
            CoapClient.pendingRequestsByToken[tokenString] = request;
        }
        if (byMsgID) {
            CoapClient.pendingRequestsByMsgID[request.originalMessage.messageId] = request;
        }
        if (byUrl) {
            CoapClient.pendingRequestsByUrl[request.url] = request;
        }
        debug("remembering request: msgID=" + request.originalMessage.messageId.toString(16) + ", token=" + tokenString + ", url=" + request.url);
    };
    /**
     * Forgets a pending request
     * @param request
     * @param byUrl
     * @param byMsgID
     * @param byToken
     */
    CoapClient.forgetRequest = function (which) {
        // find the request
        var request = CoapClient.findRequest(which);
        // none found, return
        if (request == null)
            return;
        debug("forgetting request: token=" + request.originalMessage.token.toString("hex") + "; msgID=" + request.originalMessage.messageId);
        // stop retransmission if neccessary
        CoapClient.stopRetransmission(request);
        // delete all references
        var tokenString = request.originalMessage.token.toString("hex");
        if (CoapClient.pendingRequestsByToken.hasOwnProperty(tokenString)) {
            delete CoapClient.pendingRequestsByToken[tokenString];
        }
        var msgID = request.originalMessage.messageId;
        if (CoapClient.pendingRequestsByMsgID.hasOwnProperty(msgID)) {
            delete CoapClient.pendingRequestsByMsgID[msgID];
        }
        if (CoapClient.pendingRequestsByUrl.hasOwnProperty(request.url)) {
            delete CoapClient.pendingRequestsByUrl[request.url];
        }
        // Set concurrency to 0, so the send queue can continue
        request.concurrency = 0;
        // Clean up the event listeners
        request.removeAllListeners();
        // If this request doesn't have the keepAlive option,
        // close the connection if it was the last one with the same origin
        if (!request.keepAlive) {
            var origin = Origin_1.Origin.parse(request.url);
            var requestsOnOrigin = CoapClient.findRequestsByOrigin(origin).length;
            if (requestsOnOrigin === 0) {
                // this was the last request, close the connection
                CoapClient.reset(origin);
            }
        }
    };
    /**
     * Finds a request we have remembered by one of its properties
     * @param which
     */
    CoapClient.findRequest = function (which) {
        if (which.url != null) {
            if (CoapClient.pendingRequestsByUrl.hasOwnProperty(which.url)) {
                return CoapClient.pendingRequestsByUrl[which.url];
            }
        }
        else if (which.msgID != null) {
            if (CoapClient.pendingRequestsByMsgID.hasOwnProperty(which.msgID)) {
                return CoapClient.pendingRequestsByMsgID[which.msgID];
            }
        }
        else if (which.token != null) {
            if (CoapClient.pendingRequestsByToken.hasOwnProperty(which.token)) {
                return CoapClient.pendingRequestsByToken[which.token];
            }
        }
        return null;
    };
    /**
     * Finds all pending requests of a given origin
     */
    CoapClient.findRequestsByOrigin = function (origin) {
        var originString = origin.toString();
        return Object
            .keys(CoapClient.pendingRequestsByMsgID)
            .map(function (msgID) { return CoapClient.pendingRequestsByMsgID[msgID]; })
            .filter(function (req) { return Origin_1.Origin.parse(req.url).toString() === originString; });
    };
    /**
     * Tries to establish a connection to the given target. Returns true on success, false otherwise.
     * @param target The target to connect to. Must be a string, NodeJS.Url or Origin and has to contain the protocol, host and port.
     */
    CoapClient.tryToConnect = function (target) {
        return __awaiter(this, void 0, void 0, function () {
            var originString, e_3;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        // parse/convert url
                        if (typeof target === "string") {
                            target = Origin_1.Origin.parse(target);
                        }
                        else if (!(target instanceof Origin_1.Origin)) {
                            target = Origin_1.Origin.fromUrl(target);
                        }
                        originString = target.toString();
                        _a.label = 1;
                    case 1:
                        _a.trys.push([1, 3, , 4]);
                        return [4 /*yield*/, CoapClient.getConnection(target)];
                    case 2:
                        _a.sent();
                        return [2 /*return*/, true];
                    case 3:
                        e_3 = _a.sent();
                        return [2 /*return*/, false];
                    case 4: return [2 /*return*/];
                }
            });
        });
    };
    /**
     * Establishes a new or retrieves an existing connection to the given origin
     * @param origin - The other party
     */
    CoapClient.getConnection = function (origin) {
        var originString = origin.toString();
        if (CoapClient.connections.hasOwnProperty(originString)) {
            debug("getConnection(" + originString + ") => found existing connection");
            // return existing connection
            return Promise.resolve(CoapClient.connections[originString]);
        }
        else if (CoapClient.pendingConnections.hasOwnProperty(originString)) {
            debug("getConnection(" + originString + ") => connection is pending");
            // return the pending connection
            return CoapClient.pendingConnections[originString];
        }
        else {
            debug("getConnection(" + originString + ") => establishing new connection");
            // create a promise and start the connection queue
            var ret = DeferredPromise_1.createDeferredPromise();
            CoapClient.pendingConnections[originString] = ret;
            setTimeout(CoapClient.workOffPendingConnections, 0);
            return ret;
        }
    };
    CoapClient.workOffPendingConnections = function () {
        return __awaiter(this, void 0, void 0, function () {
            var originString, origin, promise, maxTries, socket, i, e_4, ret;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        if (Object.keys(CoapClient.pendingConnections).length === 0) {
                            // no more pending connections, we're done
                            CoapClient.isConnecting = false;
                            return [2 /*return*/];
                        }
                        else if (CoapClient.isConnecting) {
                            // we're already busy
                            return [2 /*return*/];
                        }
                        CoapClient.isConnecting = true;
                        originString = Object.keys(CoapClient.pendingConnections)[0];
                        origin = Origin_1.Origin.parse(originString);
                        promise = CoapClient.pendingConnections[originString];
                        delete CoapClient.pendingConnections[originString];
                        maxTries = 3;
                        i = 1;
                        _a.label = 1;
                    case 1:
                        if (!(i <= maxTries)) return [3 /*break*/, 6];
                        _a.label = 2;
                    case 2:
                        _a.trys.push([2, 4, , 5]);
                        return [4 /*yield*/, CoapClient.getSocket(origin)];
                    case 3:
                        socket = _a.sent();
                        return [3 /*break*/, 6]; // it worked
                    case 4:
                        e_4 = _a.sent();
                        // if we are going to try again, ignore the error
                        // else throw it
                        if (i === maxTries) {
                            promise.reject(e_4);
                        }
                        return [3 /*break*/, 5];
                    case 5:
                        i++;
                        return [3 /*break*/, 1];
                    case 6:
                        if (socket != null) {
                            // add the event handler
                            socket.on("message", CoapClient.onMessage.bind(CoapClient, originString));
                            ret = CoapClient.connections[originString] = {
                                origin: origin,
                                socket: socket,
                                lastMsgId: 0,
                                lastToken: crypto.randomBytes(TOKEN_LENGTH),
                            };
                            // and resolve the deferred promise
                            promise.resolve(ret);
                        }
                        // continue working off the queue
                        CoapClient.isConnecting = false;
                        setTimeout(CoapClient.workOffPendingConnections, 0);
                        return [2 /*return*/];
                }
            });
        });
    };
    /**
     * Establishes or retrieves a socket that can be used to send to and receive data from the given origin
     * @param origin - The other party
     */
    CoapClient.getSocket = function (origin) {
        return __awaiter(this, void 0, void 0, function () {
            var ret_1, dtlsOpts, onConnection_1, onError_1, sock_1;
            return __generator(this, function (_a) {
                switch (origin.protocol) {
                    case "coap:":
                        // simply return a normal udp socket
                        return [2 /*return*/, Promise.resolve(new SocketWrapper_1.SocketWrapper(dgram.createSocket("udp4")))];
                    case "coaps:":
                        ret_1 = DeferredPromise_1.createDeferredPromise();
                        // try to find security parameters
                        if (!CoapClient.dtlsParams.hasOwnProperty(origin.hostname)) {
                            return [2 /*return*/, Promise.reject("No security parameters given for the resource at " + origin.toString())];
                        }
                        dtlsOpts = Object.assign({
                            type: "udp4",
                            address: origin.hostname,
                            port: origin.port,
                        }, CoapClient.dtlsParams[origin.hostname]);
                        onConnection_1 = function () {
                            debug("successfully created socket for origin " + origin.toString());
                            sock_1.removeListener("error", onError_1);
                            ret_1.resolve(new SocketWrapper_1.SocketWrapper(sock_1));
                        };
                        onError_1 = function (e) {
                            debug("socket creation for origin " + origin.toString() + " failed: " + e);
                            sock_1.removeListener("connected", onConnection_1);
                            ret_1.reject(e.message);
                        };
                        sock_1 = node_dtls_client_1.dtls
                            .createSocket(dtlsOpts)
                            .once("connected", onConnection_1)
                            .once("error", onError_1);
                        return [2 /*return*/, ret_1];
                    default:
                        throw new Error("protocol type \"" + origin.protocol + "\" is not supported");
                }
                return [2 /*return*/];
            });
        });
    };
    return CoapClient;
}());
/** Table of all open connections and their parameters, sorted by the origin "coap(s)://host:port" */
CoapClient.connections = {};
/** Queue of the connections waiting to be established */
CoapClient.pendingConnections = {};
CoapClient.isConnecting = false;
/** Table of all known security params, sorted by the hostname */
CoapClient.dtlsParams = {};
/** All pending requests, sorted by the token */
CoapClient.pendingRequestsByToken = {};
CoapClient.pendingRequestsByMsgID = {};
CoapClient.pendingRequestsByUrl = {};
/** Queue of the messages waiting to be sent */
CoapClient.sendQueue = [];
CoapClient.sendQueueHighPrioCount = 0;
/** Number of message we expect an answer for */
CoapClient.concurrency = 0;
exports.CoapClient = CoapClient;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiQ29hcENsaWVudC5qcyIsInNvdXJjZVJvb3QiOiJDOi9Vc2Vycy9Eb21pbmljL0RvY3VtZW50cy9WaXN1YWwgU3R1ZGlvIDIwMTcvUmVwb3NpdG9yaWVzL25vZGUtY29hcC1jbGllbnQvc3JjLyIsInNvdXJjZXMiOlsiQ29hcENsaWVudC50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7OztBQUFBLCtCQUFpQztBQUNqQyw2QkFBK0I7QUFDL0IsaUNBQXNDO0FBQ3RDLHFEQUF3QztBQUN4Qyw2QkFBK0I7QUFDL0IsbURBQWtEO0FBQ2xELHlEQUErRTtBQUMvRSx1Q0FBc0M7QUFDdEMscURBQW9EO0FBQ3BELHFDQUE0RTtBQUM1RSxtQ0FBc0Y7QUFFdEYsdUJBQXVCO0FBQ3ZCLG9DQUFzQztBQUN0QyxJQUFNLEtBQUssR0FBRyxZQUFZLENBQUMsa0JBQWtCLENBQUMsQ0FBQztBQUUvQyxxQkFBcUI7QUFDckIsMkNBQTJDO0FBQzNDLElBQU0sVUFBVSxHQUFHLE9BQU8sQ0FBQyxpQkFBaUIsQ0FBQyxDQUFDLE9BQU8sQ0FBQztBQUN0RCxLQUFLLENBQUMseUJBQXVCLFVBQVksQ0FBQyxDQUFDO0FBb0IzQyxxQkFBcUIsR0FBZ0I7SUFDcEMsTUFBTSxDQUFJLEdBQUcsQ0FBQyxRQUFRLFVBQUssR0FBRyxDQUFDLFFBQVEsU0FBSSxHQUFHLENBQUMsSUFBSSxHQUFHLEdBQUcsQ0FBQyxRQUFVLENBQUM7QUFDdEUsQ0FBQztBQXNCRDtJQUE2QixrQ0FBWTtJQUV4Qyx3QkFBWSxPQUF5QjtRQUFyQyxZQUNDLGlCQUFPLFNBWVA7UUFYQSxFQUFFLENBQUMsQ0FBQyxDQUFDLE9BQU8sQ0FBQzt5QkFBUTtRQUVyQixLQUFJLENBQUMsVUFBVSxHQUFHLE9BQU8sQ0FBQyxVQUFVLENBQUM7UUFDckMsS0FBSSxDQUFDLEdBQUcsR0FBRyxPQUFPLENBQUMsR0FBRyxDQUFDO1FBQ3ZCLEtBQUksQ0FB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