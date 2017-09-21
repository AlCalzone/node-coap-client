"use strict";
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
var debugPackage = require("debug");
var dgram = require("dgram");
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
// TODO: make configurable
var RETRANSMISSION_PARAMS = {
    ackTimeout: 2,
    ackRandomFactor: 1.5,
    maxRetransmit: 4,
};
var TOKEN_LENGTH = 4;
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
                        req = {
                            connection: connection,
                            url: urlToString(url),
                            originalMessage: message,
                            retransmit: retransmit,
                            keepAlive: options.keepAlive,
                            callback: null,
                            observe: false,
                            promise: response,
                        };
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
                        req = {
                            connection: connection,
                            url: originString,
                            originalMessage: message,
                            retransmit: null,
                            keepAlive: true,
                            callback: null,
                            observe: false,
                            promise: response,
                        };
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
                        req = {
                            connection: connection,
                            url: urlToString(url),
                            originalMessage: message,
                            retransmit: retransmit,
                            keepAlive: options.keepAlive,
                            callback: callback,
                            observe: true,
                            promise: null,
                        };
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
            // TODO handle non-piggybacked messages
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
                        CoapClient.send(request.connection, ACK);
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
                        CoapClient.send(connection, RST);
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
    CoapClient.send = function (connection, message) {
        // send the message
        connection.socket.send(message.serialize(), connection.origin);
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
    /** Table of all open connections and their parameters, sorted by the origin "coap(s)://host:port" */
    CoapClient.connections = {};
    /** Table of all known security params, sorted by the hostname */
    CoapClient.dtlsParams = {};
    /** All pending requests, sorted by the token */
    CoapClient.pendingRequestsByToken = {};
    CoapClient.pendingRequestsByMsgID = {};
    CoapClient.pendingRequestsByUrl = {};
    return CoapClient;
}());
exports.CoapClient = CoapClient;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiQ29hcENsaWVudC5qcyIsInNvdXJjZVJvb3QiOiJEOi9ub2RlLWNvYXAtY2xpZW50L3NyYy8iLCJzb3VyY2VzIjpbIkNvYXBDbGllbnQudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6Ijs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7OztBQUFBLCtCQUFpQztBQUNqQyxvQ0FBc0M7QUFDdEMsNkJBQStCO0FBQy9CLHFEQUF3QztBQUN4Qyw2QkFBK0I7QUFDL0IsbURBQWtEO0FBQ2xELHlEQUErRTtBQUMvRSx1Q0FBc0M7QUFDdEMscURBQW9EO0FBQ3BELHFDQUE0RTtBQUM1RSxtQ0FBc0Y7QUFFdEYsdUJBQXVCO0FBQ3ZCLElBQU0sS0FBSyxHQUFHLFlBQVksQ0FBQyxrQkFBa0IsQ0FBQyxDQUFDO0FBb0IvQyxxQkFBcUIsR0FBZ0I7SUFDcEMsTUFBTSxDQUFJLEdBQUcsQ0FBQyxRQUFRLFVBQUssR0FBRyxDQUFDLFFBQVEsU0FBSSxHQUFHLENBQUMsSUFBSSxHQUFHLEdBQUcsQ0FBQyxRQUFVLENBQUM7QUFDdEUsQ0FBQztBQWdDRCwwQkFBMEI7QUFDMUIsSUFBTSxxQkFBcUIsR0FBRztJQUM3QixVQUFVLEVBQUUsQ0FBQztJQUNiLGVBQWUsRUFBRSxHQUFHO0lBQ3BCLGFBQWEsRUFBRSxDQUFDO0NBQ2hCLENBQUM7QUFDRixJQUFNLFlBQVksR0FBRyxDQUFDLENBQUM7QUFFdkIsd0JBQXdCLEtBQWE7SUFDcEMsSUFBTSxHQUFHLEdBQUcsS0FBSyxDQUFDLE1BQU0sQ0FBQztJQUN6QixHQUFHLENBQUMsQ0FBQyxJQUFJLENBQUMsR0FBRyxHQUFHLEdBQUcsQ0FBQyxFQUFFLENBQUMsSUFBSSxDQUFDLEVBQUUsQ0FBQyxFQUFFLEVBQUUsQ0FBQztRQUNuQyxFQUFFLENBQUMsQ0FBQyxLQUFLLENBQUMsQ0FBQyxDQUFDLEdBQUcsSUFBSSxDQUFDLENBQUMsQ0FBQztZQUNyQixLQUFLLENBQUMsQ0FBQyxDQUFDLEVBQUUsQ0FBQztZQUNYLEtBQUss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