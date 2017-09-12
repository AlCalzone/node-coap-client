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
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t;
    return { next: verb(0), "throw": verb(1), "return": verb(2) };
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
var debugPackage = require("debug");
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
    for (var i = len - 1; i >= 0; i--) {
        if (token[i] < 0xff) {
            token[i]++;
            break;
        }
        else {
            token[i] = 0;
            // continue with the next digit
        }
    }
    return token;
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
                        options.confirmable = options.confirmable || true;
                        options.keepAlive = options.keepAlive || true;
                        origin = Origin_1.Origin.fromUrl(url);
                        originString = origin.toString();
                        return [4 /*yield*/, this.getConnection(origin)];
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
                        if (type === Message_1.MessageType.CON) {
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
                            concurrency: 1,
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
                        options.confirmable = options.confirmable || true;
                        options.keepAlive = options.keepAlive || true;
                        origin = Origin_1.Origin.fromUrl(url);
                        originString = origin.toString();
                        return [4 /*yield*/, this.getConnection(origin)];
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
                        if (type === Message_1.MessageType.CON) {
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
                            concurrency: 1,
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
                        // the other party doesn't know what to do with the request, forget it
                        debug("received RST for " + coapMsg.messageId.toString(16) + ", forgetting the request...");
                        CoapClient.forgetRequest({ request: request });
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
                    // in any case, reduce the request's concurrency, since it was handled
                    request.concurrency = 0;
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
     * @param connection
     */
    CoapClient.send = function (connection, message, highPriority) {
        if (highPriority === void 0) { highPriority = false; }
        // Put the message in the queue
        if (highPriority) {
            // in front
            CoapClient.sendQueue.unshift({ connection: connection, message: message });
        }
        else {
            // at the end
            CoapClient.sendQueue.push({ connection: connection, message: message });
        }
        // if there's a request for this message, listen for concurrency changes
        var request = CoapClient.findRequest({ msgID: message.messageId });
        if (request != null) {
            // and continue working off the queue when it does
            request.once("concurrencyChanged", function (req) { return CoapClient.workOffSendQueue(); });
        }
        // start working it off now (maybe)
        CoapClient.workOffSendQueue();
    };
    CoapClient.workOffSendQueue = function () {
        // check if there are messages to send
        if (CoapClient.sendQueue.length === 0)
            return;
        // check if we may send a message now
        if (CoapClient.calculateConcurrency() < MAX_CONCURRENCY) {
            // get the next message to send
            var _a = CoapClient.sendQueue.shift(), connection = _a.connection, message = _a.message;
            // send the message
            connection.socket.send(message.serialize(), connection.origin);
        }
        // to avoid any deadlocks we didn't think of, re-call this later
        setTimeout(CoapClient.workOffSendQueue, 100);
    };
    /** Calculates the current concurrency, i.e. how many parallel requests are being handled */
    CoapClient.calculateConcurrency = function () {
        return Object.keys(CoapClient.pendingRequestsByMsgID) // find all requests
            .map(function (msgid) { return CoapClient.pendingRequestsByMsgID[msgid]; })
            .map(function (req) { return req.concurrency; }) // extract their concurrency
            .reduce(function (sum, item) { return sum + item; }) // and sum it up
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
     * Establishes a new or retrieves an existing connection to the given origin
     * @param origin - The other party
     */
    CoapClient.getConnection = function (origin) {
        return __awaiter(this, void 0, void 0, function () {
            var originString, maxTries, socket, i, e_1, ret;
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
                        e_1 = _a.sent();
                        // if we are going to try again, ignore the error
                        // else throw it
                        if (i === maxTries)
                            throw e_1;
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
CoapClient.isSending = false;
/** Number of message we expect an answer for */
CoapClient.concurrency = 0;
exports.CoapClient = CoapClient;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiQ29hcENsaWVudC5qcyIsInNvdXJjZVJvb3QiOiJDOi9Vc2Vycy9Eb21pbmljL0RvY3VtZW50cy9WaXN1YWwgU3R1ZGlvIDIwMTcvUmVwb3NpdG9yaWVzL25vZGUtY29hcC1jbGllbnQvc3JjLyIsInNvdXJjZXMiOlsiQ29hcENsaWVudC50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7O0FBQUEsK0JBQWlDO0FBQ2pDLG9DQUFzQztBQUN0Qyw2QkFBK0I7QUFDL0IscURBQXdDO0FBQ3hDLDZCQUErQjtBQUMvQixtREFBa0Q7QUFDbEQseURBQStFO0FBQy9FLHVDQUFzQztBQUN0QyxxREFBb0Q7QUFDcEQscUNBQTRFO0FBQzVFLG1DQUFzRjtBQUV0Rix1QkFBdUI7QUFDdkIsSUFBTSxLQUFLLEdBQUcsWUFBWSxDQUFDLGtCQUFrQixDQUFDLENBQUM7QUFrQi9DLHFCQUFxQixHQUFnQjtJQUNwQyxNQUFNLENBQUksR0FBRyxDQUFDLFFBQVEsVUFBSyxHQUFHLENBQUMsUUFBUSxTQUFJLEdBQUcsQ0FBQyxJQUFJLEdBQUcsR0FBRyxDQUFDLFFBQVUsQ0FBQztBQUN0RSxDQUFDO0FBZ0NELDBCQUEwQjtBQUMxQixJQUFNLHFCQUFxQixHQUFHO0lBQzdCLFVBQVUsRUFBRSxDQUFDO0lBQ2IsZUFBZSxFQUFFLEdBQUc7SUFDcEIsYUFBYSxFQUFFLENBQUM7Q0FDaEIsQ0FBQztBQUNGLElBQU0sWUFBWSxHQUFHLENBQUMsQ0FBQztBQUV2Qix3QkFBd0IsS0FBYTtJQUNwQyxJQUFNLEdBQUcsR0FBRyxLQUFLLENBQUMsTUFBTSxDQUFDO0lBQ3pCLEdBQUcsQ0FBQyxDQUFDLElBQUksQ0FBQyxHQUFHLEdBQUcsR0FBRyxDQUFDLEVBQUUsQ0FBQyxJQUFJLENBQUMsRUFBRSxDQUFDLEVBQUUsRUFBRSxDQUFDO1FBQ25DLEVBQUUsQ0FBQyxDQUFDLEtBQUssQ0FBQyxDQUFDLENBQUMsR0FBRyxJQUFJLENBQUMs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