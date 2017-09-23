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
            var originString, connection, response, messageId, message, req, failTimeout, success, e_1;
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
                        return [4 /*yield*/, CoapClient.getConnection(target)];
                    case 1:
                        connection = _a.sent();
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
                        _a.label = 2;
                    case 2:
                        _a.trys.push([2, 4, 5, 6]);
                        // now wait for success or failure
                        return [4 /*yield*/, response];
                    case 3:
                        // now wait for success or failure
                        _a.sent();
                        success = true;
                        return [3 /*break*/, 6];
                    case 4:
                        e_1 = _a.sent();
                        success = false;
                        return [3 /*break*/, 6];
                    case 5:
                        // cleanup
                        clearTimeout(failTimeout);
                        CoapClient.forgetRequest({ request: req });
                        return [7 /*endfinally*/];
                    case 6: return [2 /*return*/, success];
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
        if (byToken) {
            var tokenString = request.originalMessage.token.toString("hex");
            debug("remembering request with token " + tokenString);
            CoapClient.pendingRequestsByToken[tokenString] = request;
        }
        if (byMsgID) {
            CoapClient.pendingRequestsByMsgID[request.originalMessage.messageId] = request;
        }
        if (byUrl) {
            CoapClient.pendingRequestsByUrl[request.url] = request;
        }
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
            var originString, e_2;
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
                        e_2 = _a.sent();
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
        return __awaiter(this, void 0, void 0, function () {
            var originString, maxTries, socket, i, e_3, ret;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        originString = origin.toString();
                        if (!CoapClient.connections.hasOwnProperty(originString)) return [3 /*break*/, 1];
                        // return existing connection
                        return [2 /*return*/, CoapClient.connections[originString]];
                    case 1:
                        maxTries = 3;
                        socket = void 0;
                        i = 1;
                        _a.label = 2;
                    case 2:
                        if (!(i <= maxTries)) return [3 /*break*/, 7];
                        _a.label = 3;
                    case 3:
                        _a.trys.push([3, 5, , 6]);
                        return [4 /*yield*/, CoapClient.getSocket(origin)];
                    case 4:
                        socket = _a.sent();
                        return [3 /*break*/, 7]; // it worked
                    case 5:
                        e_3 = _a.sent();
                        // if we are going to try again, ignore the error
                        // else throw it
                        if (i === maxTries)
                            throw e_3;
                        return [3 /*break*/, 6];
                    case 6:
                        i++;
                        return [3 /*break*/, 2];
                    case 7:
                        // add the event handler
                        socket.on("message", CoapClient.onMessage.bind(CoapClient, originString));
                        ret = CoapClient.connections[originString] = {
                            origin: origin,
                            socket: socket,
                            lastMsgId: 0,
                            lastToken: crypto.randomBytes(TOKEN_LENGTH),
                        };
                        // and return it
                        return [2 /*return*/, ret];
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
/** Table of all known security params, sorted by the hostname */
CoapClient.dtlsParams = {};
/** All pending requests, sorted by the token */
CoapClient.pendingRequestsByToken = {};
CoapClient.pendingRequestsByMsgID = {};
CoapClient.pendingRequestsByUrl = {};
/** Array of the messages waiting to be sent */
CoapClient.sendQueue = [];
CoapClient.sendQueueHighPrioCount = 0;
CoapClient.isSending = false;
/** Number of message we expect an answer for */
CoapClient.concurrency = 0;
exports.CoapClient = CoapClient;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiQ29hcENsaWVudC5qcyIsInNvdXJjZVJvb3QiOiJDOi9Vc2Vycy9Eb21pbmljL0RvY3VtZW50cy9WaXN1YWwgU3R1ZGlvIDIwMTcvUmVwb3NpdG9yaWVzL25vZGUtY29hcC1jbGllbnQvc3JjLyIsInNvdXJjZXMiOlsiQ29hcENsaWVudC50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7OztBQUFBLCtCQUFpQztBQUNqQyw2QkFBK0I7QUFDL0IsaUNBQXNDO0FBQ3RDLHFEQUF3QztBQUN4Qyw2QkFBK0I7QUFDL0IsbURBQWtEO0FBQ2xELHlEQUErRTtBQUMvRSx1Q0FBc0M7QUFDdEMscURBQW9EO0FBQ3BELHFDQUE0RTtBQUM1RSxtQ0FBc0Y7QUFFdEYsdUJBQXVCO0FBQ3ZCLG9DQUFzQztBQUN0QyxJQUFNLEtBQUssR0FBRyxZQUFZLENBQUMsa0JBQWtCLENBQUMsQ0FBQztBQW9CL0MscUJBQXFCLEdBQWdCO0lBQ3BDLE1BQU0sQ0FBSSxHQUFHLENBQUMsUUFBUSxVQUFLLEdBQUcsQ0FBQyxRQUFRLFNBQUksR0FBRyxDQUFDLElBQUksR0FBRyxHQUFHLENBQUMsUUFBVSxDQUFDO0FBQ3RFLENBQUM7QUFzQkQ7SUFBNkIsa0NBQVk7SUFFeEMsd0JBQVksT0FBeUI7UUFBckMsWUFDQyxpQkFBTyxTQVlQO1FBWEEsRUFBRSxDQUFDLENBQUMsQ0FBQyxPQUFPLENBQUM7eUJBQVE7UUFFckIsS0FBSSxDQUFDLFVBQVUsR0FBRyxPQUFPLENBQUMsVUFBVSxDQUFDO1FBQ3JDLEtBQUksQ0FBQyxHQUFHLEdBQUcsT0FBTyxDQUFDLEdBQUcsQ0FBQztRQUN2QixLQUFJLENBQUMsZUFBZSxHQUFHLE9BQU8sQ0FBQyxlQUFlLENBQUM7UUFDL0MsS0FBSSxDQUFDLFVBQVUsR0FBRyxPQUFPLENBQUMsVUFBVSxDQUFDO1FBQ3JDLEtBQUksQ0FBQyxPQUFPLEdBQUcsT0FBTyxDQUFDLE9BQU8sQ0FB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