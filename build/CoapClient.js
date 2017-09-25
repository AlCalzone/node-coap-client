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
            var originString, origin, promise, maxTries, socket, i, e_3, ret;
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
                        e_3 = _a.sent();
                        // if we are going to try again, ignore the error
                        // else throw it
                        if (i === maxTries) {
                            promise.reject(e_3);
                            return [2 /*return*/];
                        }
                        return [3 /*break*/, 5];
                    case 5:
                        i++;
                        return [3 /*break*/, 1];
                    case 6:
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