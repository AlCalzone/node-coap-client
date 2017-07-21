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
var events_1 = require("events");
var node_dtls_client_1 = require("node-dtls-client");
var dgram = require("dgram");
var Message_1 = require("./Message");
var Option_1 = require("./Option");
var ContentFormats_1 = require("./ContentFormats");
var nodeUrl = require("url");
var crypto = require("crypto");
var DeferredPromise_1 = require("./lib/DeferredPromise");
/**
 * Identifies another endpoint (similar to the new WhatWG URL API "origin" property)
 */
var Origin = (function () {
    function Origin(protocol, hostname, port) {
        this.protocol = protocol;
        this.hostname = hostname;
        this.port = port;
    }
    Origin.prototype.toString = function () {
        return this.protocol + "//" + this.hostname + ":" + this.port;
    };
    Origin.fromUrl = function (url) {
        return new Origin(url.protocol, url.hostname, +url.port);
    };
    return Origin;
}());
function urlToString(url) {
    return url.protocol + "//" + url.hostname + ":" + url.port + url.pathname;
}
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
    return (++msgId > 0xffff) ? msgId : 1;
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
     * Requests a CoAP resource
     * @param url - The URL to be requested. Must start with coap:// or coaps://
     * @param method - The request method to be used
     * @param payload - The optional payload to be attached to the request
     * @param options - Various options to control the request.
     */
    CoapClient.request = function (url, method, payload, options) {
        return __awaiter(this, void 0, void 0, function () {
            var origin, originString, connection, type, code, messageId, token, tokenString, msgOptions, pathname, pathParts, response, req;
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
                        origin = Origin.fromUrl(url), originString = origin.toString();
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
                        req = {
                            origin: originString,
                            token: token,
                            keepAlive: options.keepAlive,
                            promise: response,
                            callback: null,
                            observe: false
                        };
                        CoapClient.pendingRequests[tokenString] = req;
                        // now send the message
                        CoapClient.send(connection, type, code, messageId, token, msgOptions, payload);
                        return [2 /*return*/, response];
                }
            });
        });
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
            var origin, originString, connection, type, code, messageId, token, tokenString, msgOptions, pathname, pathParts, response, req;
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
                        origin = Origin.fromUrl(url), originString = origin.toString();
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
                        req = {
                            origin: originString,
                            token: token,
                            keepAlive: options.keepAlive,
                            callback: callback,
                            observe: true,
                            promise: null
                        };
                        CoapClient.pendingRequests[tokenString] = req;
                        // also remember that we are observing
                        CoapClient.activeObserveTokens[urlToString(url)] = tokenString;
                        // now send the message
                        CoapClient.send(connection, type, code, messageId, token, msgOptions, payload);
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
        // see if we have the associated token remembered
        if (CoapClient.activeObserveTokens.hasOwnProperty(urlString)) {
            var token = CoapClient.activeObserveTokens[urlString];
            // try to find the matching request
            if (CoapClient.pendingRequests.hasOwnProperty(token)) {
                var request = CoapClient.pendingRequests[token];
                // and remove it from the table
                delete CoapClient.pendingRequests[token];
            }
            // also remove the association from the observer table
            delete CoapClient.activeObserveTokens[urlString];
        }
    };
    CoapClient.onMessage = function (origin, message, rinfo) {
        // parse the CoAP message
        var coapMsg = Message_1.Message.parse(message);
        if (coapMsg.code.isEmpty()) {
            // ACK or RST 
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
                if (CoapClient.pendingRequests.hasOwnProperty(tokenString)) {
                    var request = CoapClient.pendingRequests[tokenString];
                    var contentFormat = null;
                    // parse options
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
                        payload: coapMsg.payload
                    };
                    if (request.observe) {
                        // call the callback
                        request.callback(response);
                    }
                    else {
                        // resolve the promise
                        request.promise.resolve(response);
                        // after handling one-time requests, delete the info about them
                        delete CoapClient.pendingRequests[tokenString];
                    }
                }
                else {
                    // no request found for this token, send RST so the server stops sending
                    // try to find the connection that belongs to this origin
                    var originString = origin.toString();
                    if (CoapClient.connections.hasOwnProperty(originString)) {
                        var connection = CoapClient.connections[originString];
                        // and send the reset
                        CoapClient.send(connection, Message_1.MessageType.RST, Message_1.MessageCodes.empty, coapMsg.messageId, null, [], null);
                    }
                }
            }
        }
    };
    /**
     * Send a CoAP message to the given endpoint
     * @param connection
     * @param type
     * @param code
     * @param messageId
     * @param token
     * @param options
     * @param payload
     */
    CoapClient.send = function (connection, type, code, messageId, token, options, // do we need this?
        payload) {
        // create the message
        var msg = new Message_1.Message(0x01, type, code, messageId, token, options, payload);
        // and send it
        connection.socket.send(msg.serialize(), connection.origin);
    };
    /**
     * Establishes a new or retrieves an existing connection to the given origin
     * @param origin - The other party
     */
    CoapClient.getConnection = function (origin) {
        return __awaiter(this, void 0, void 0, function () {
            var originString, socket, ret;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        originString = origin.toString();
                        if (!CoapClient.connections.hasOwnProperty(originString)) return [3 /*break*/, 1];
                        // return existing connection
                        return [2 /*return*/, CoapClient.connections[originString]];
                    case 1: return [4 /*yield*/, CoapClient.getSocket(origin)];
                    case 2:
                        socket = _a.sent();
                        // add the event handler
                        socket.on("message", CoapClient.bind(CoapClient, originString));
                        ret = CoapClient.connections[originString] = {
                            origin: origin,
                            socket: socket,
                            lastMsgId: 0,
                            lastToken: crypto.randomBytes(4)
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
        switch (origin.protocol) {
            case "coap:":
                // simply return a normal udp socket
                return Promise.resolve(new SocketWrapper(dgram.createSocket("udp4")));
            case "coaps:":
                // return a promise we resolve as soon as the connection is secured
                var ret_1 = DeferredPromise_1.createDeferredPromise();
                // try to find security parameters
                if (!CoapClient.dtlsParams.hasOwnProperty(origin.hostname))
                    return Promise.reject("No security parameters given for the resource at " + origin.toString());
                var dtlsOpts = Object.assign({
                    type: "udp4",
                    address: origin.hostname,
                    port: origin.port,
                }, CoapClient.dtlsParams[origin.hostname]);
                // try connecting
                var sock_1 = node_dtls_client_1.dtls
                    .createSocket(dtlsOpts)
                    .on("connected", function () { return ret_1.resolve(new SocketWrapper(sock_1)); })
                    .on("error", function (e) { return ret_1.reject(e.message); });
                return ret_1;
            default:
                throw new Error("protocol type \"" + origin.protocol + "\" is not supported");
        }
    };
    return CoapClient;
}());
/** Table of all open connections and their parameters, sorted by the origin "coap(s)://host:port" */
CoapClient.connections = {};
/** Table of all known security params, sorted by the hostname */
CoapClient.dtlsParams = {};
/** All pending requests, sorted by the token */
CoapClient.pendingRequests = {};
/** All active observations, sorted by the url */
CoapClient.activeObserveTokens = {};
exports.CoapClient = CoapClient;
//# sourceMappingURL=CoapClient.js.map