"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : new P(function (resolve) { resolve(result.value); }).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
const crypto = require("crypto");
const dgram = require("dgram");
const events_1 = require("events");
const node_dtls_client_1 = require("node-dtls-client");
const nodeUrl = require("url");
const ContentFormats_1 = require("./ContentFormats");
const DeferredPromise_1 = require("./lib/DeferredPromise");
const Origin_1 = require("./lib/Origin");
const SocketWrapper_1 = require("./lib/SocketWrapper");
const Message_1 = require("./Message");
const Option_1 = require("./Option");
// initialize debugging
const debugPackage = require("debug");
const debug = debugPackage("node-coap-client");
// print version info
// tslint:disable-next-line:no-var-requires
const npmVersion = require("../package.json").version;
debug(`CoAP client version ${npmVersion}`);
function urlToString(url) {
    return `${url.protocol}//${url.hostname}:${url.port}${url.pathname}`;
}
class PendingRequest extends events_1.EventEmitter {
    constructor(initial) {
        super();
        if (!initial)
            return;
        this.connection = initial.connection;
        this.url = initial.url;
        this.originalMessage = initial.originalMessage;
        this.retransmit = initial.retransmit;
        this.promise = initial.promise;
        this.callback = initial.callback;
        this.keepAlive = initial.keepAlive;
        this.observe = initial.observe;
        this._concurrency = initial.concurrency;
    }
    set concurrency(value) {
        const changed = value !== this._concurrency;
        this._concurrency = value;
        if (changed)
            this.emit("concurrencyChanged", this);
    }
    get concurrency() {
        return this._concurrency;
    }
    queueForRetransmission() {
        if (this.retransmit != null && typeof this.retransmit.action === "function") {
            this.retransmit.jsTimeout = setTimeout(this.retransmit.action, this.retransmit.timeout);
        }
    }
}
// TODO: make configurable
const RETRANSMISSION_PARAMS = {
    ackTimeout: 2,
    ackRandomFactor: 1.5,
    maxRetransmit: 4,
};
const TOKEN_LENGTH = 4;
/** How many concurrent messages are allowed. Should be 1 */
const MAX_CONCURRENCY = 1;
function incrementToken(token) {
    const len = token.length;
    const ret = Buffer.alloc(len, token);
    for (let i = len - 1; i >= 0; i--) {
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
    for (const opt of opts) {
        if (opt.name === name)
            return opt;
    }
}
function findOptions(opts, name) {
    return opts.filter(opt => opt.name === name);
}
/**
 * provides methods to access CoAP server resources
 */
class CoapClient {
    /**
     * Sets the security params to be used for the given hostname
     */
    static setSecurityParams(hostname, params) {
        CoapClient.dtlsParams[hostname] = params;
    }
    /**
     * Closes and forgets about connections, useful if DTLS session is reset on remote end
     * @param originOrHostname - Origin (protocol://hostname:port) or Hostname to reset,
     * omit to reset all connections
     */
    static reset(originOrHostname) {
        debug(`reset(${originOrHostname || ""})`);
        let predicate;
        if (originOrHostname != null) {
            if (typeof originOrHostname === "string") {
                // we were given a hostname, forget the connection if the origin's hostname matches
                predicate = (originString) => Origin_1.Origin.parse(originString).hostname === originOrHostname;
            }
            else {
                // we were given an origin, forget the connection if its string representation matches
                const match = originOrHostname.toString();
                predicate = (originString) => originString === match;
            }
        }
        else {
            // we weren't given a filter, forget all connections
            predicate = (originString) => true;
        }
        // forget all pending requests matching the predicate
        for (const msgId of Object.keys(CoapClient.pendingRequestsByMsgID)) {
            // check if the request matches the predicate
            const request = CoapClient.pendingRequestsByMsgID[msgId];
            const originString = Origin_1.Origin.parse(request.url).toString();
            if (!predicate(originString))
                continue;
            // and forget it if so
            if (request.promise != null)
                request.promise.reject("CoapClient was reset");
            CoapClient.forgetRequest({ request });
        }
        // cancel all pending connections matching the predicate
        for (const originString of Object.keys(CoapClient.pendingConnections)) {
            if (!predicate(originString))
                continue;
            debug(`canceling pending connection to ${originString}`);
            CoapClient.pendingConnections[originString].reject("CoapClient was reset");
            delete CoapClient.pendingConnections[originString];
        }
        // forget all connections matching the predicate
        for (const originString in CoapClient.connections) {
            if (!predicate(originString))
                continue;
            debug(`closing connection to ${originString}`);
            if (CoapClient.connections[originString].socket) {
                CoapClient.connections[originString].socket.close();
            }
            delete CoapClient.connections[originString];
        }
    }
    /**
     * Requests a CoAP resource
     * @param url - The URL to be requested. Must start with coap:// or coaps://
     * @param method - The request method to be used
     * @param payload - The optional payload to be attached to the request
     * @param options - Various options to control the request.
     */
    static request(url, method, payload, options) {
        return __awaiter(this, void 0, void 0, function* () {
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
            // retrieve or create the connection we're going to use
            const origin = Origin_1.Origin.fromUrl(url);
            const originString = origin.toString();
            const connection = yield CoapClient.getConnection(origin);
            // find all the message parameters
            const type = options.confirmable ? Message_1.MessageType.CON : Message_1.MessageType.NON;
            const code = Message_1.MessageCodes.request[method];
            const messageId = connection.lastMsgId = incrementMessageID(connection.lastMsgId);
            const token = connection.lastToken = incrementToken(connection.lastToken);
            const tokenString = token.toString("hex");
            payload = payload || Buffer.from([]);
            // create message options, be careful to order them by code, no sorting is implemented yet
            const msgOptions = [];
            //// [6] observe or not?
            // msgOptions.push(Options.Observe(options.observe))
            // [11] path of the request
            let pathname = url.pathname || "";
            while (pathname.startsWith("/")) {
                pathname = pathname.slice(1);
            }
            while (pathname.endsWith("/")) {
                pathname = pathname.slice(0, -1);
            }
            const pathParts = pathname.split("/");
            msgOptions.push(...pathParts.map(part => Option_1.Options.UriPath(part)));
            // [12] content format
            msgOptions.push(Option_1.Options.ContentFormat(ContentFormats_1.ContentFormats.application_json));
            // create the promise we're going to return
            const response = DeferredPromise_1.createDeferredPromise();
            // create the message we're going to send
            const message = CoapClient.createMessage(type, code, messageId, token, msgOptions, payload);
            // create the retransmission info
            let retransmit;
            if (options.retransmit && type === Message_1.MessageType.CON) {
                const timeout = CoapClient.getRetransmissionInterval();
                retransmit = {
                    timeout,
                    action: () => CoapClient.retransmit(messageId),
                    jsTimeout: null,
                    counter: 0,
                };
            }
            // remember the request
            const req = new PendingRequest({
                connection,
                url: urlToString(url),
                originalMessage: message,
                retransmit,
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
            return response;
        });
    }
    /**
     * Pings a CoAP endpoint to check if it is alive
     * @param target - The target to be pinged. Must be a string, NodeJS.Url or Origin and has to contain the protocol, host and port.
     * @param timeout - (optional) Timeout in ms, after which the ping is deemed unanswered. Default: 5000ms
     */
    static ping(target, timeout = 5000) {
        return __awaiter(this, void 0, void 0, function* () {
            // parse/convert url
            if (typeof target === "string") {
                target = Origin_1.Origin.parse(target);
            }
            else if (!(target instanceof Origin_1.Origin)) {
                target = Origin_1.Origin.fromUrl(target);
            }
            // retrieve or create the connection we're going to use
            const originString = target.toString();
            let connection;
            try {
                connection = yield CoapClient.getConnection(target);
            }
            catch (e) {
                // we didn't even get a connection, so fail the ping
                return false;
            }
            // create the promise we're going to return
            const response = DeferredPromise_1.createDeferredPromise();
            // create the message we're going to send.
            // An empty message with type CON equals a ping and provokes a RST from the server
            const messageId = connection.lastMsgId = incrementMessageID(connection.lastMsgId);
            const message = CoapClient.createMessage(Message_1.MessageType.CON, Message_1.MessageCodes.empty, messageId);
            // remember the request
            const req = new PendingRequest({
                connection,
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
            // fail the ping after the timeout has passed
            const failTimeout = setTimeout(() => response.reject(), timeout);
            let success;
            try {
                // now wait for success or failure
                yield response;
                success = true;
            }
            catch (e) {
                success = false;
            }
            finally {
                // cleanup
                clearTimeout(failTimeout);
                CoapClient.forgetRequest({ request: req });
            }
            return success;
        });
    }
    /**
     * Re-Sends a message in case it got lost
     * @param msgID
     */
    static retransmit(msgID) {
        // find the request with all the information
        const request = CoapClient.findRequest({ msgID });
        if (request == null || request.retransmit == null)
            return;
        // are we over the limit?
        if (request.retransmit.counter > RETRANSMISSION_PARAMS.maxRetransmit) {
            // if this is a one-time request, reject the response promise
            if (request.promise !== null) {
                request.promise.reject(new Error("Retransmit counter exceeded"));
            }
            // then stop retransmitting and forget the request
            CoapClient.forgetRequest({ request });
            return;
        }
        debug(`retransmitting message ${msgID.toString(16)}, try #${request.retransmit.counter + 1}`);
        // resend the message
        CoapClient.send(request.connection, request.originalMessage, true);
        // and increase the params
        request.retransmit.counter++;
        request.retransmit.timeout *= 2;
        request.retransmit.jsTimeout = setTimeout(() => CoapClient.retransmit(msgID), request.retransmit.timeout);
    }
    static getRetransmissionInterval() {
        return Math.round(1000 /*ms*/ * RETRANSMISSION_PARAMS.ackTimeout *
            (1 + Math.random() * (RETRANSMISSION_PARAMS.ackRandomFactor - 1)));
    }
    static stopRetransmission(request) {
        if (request.retransmit == null)
            return;
        clearTimeout(request.retransmit.jsTimeout);
        request.retransmit = null;
    }
    /**
     * Observes a CoAP resource
     * @param url - The URL to be requested. Must start with coap:// or coaps://
     * @param method - The request method to be used
     * @param payload - The optional payload to be attached to the request
     * @param options - Various options to control the request.
     */
    static observe(url, method, callback, payload, options) {
        return __awaiter(this, void 0, void 0, function* () {
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
            // retrieve or create the connection we're going to use
            const origin = Origin_1.Origin.fromUrl(url);
            const originString = origin.toString();
            const connection = yield CoapClient.getConnection(origin);
            // find all the message parameters
            const type = options.confirmable ? Message_1.MessageType.CON : Message_1.MessageType.NON;
            const code = Message_1.MessageCodes.request[method];
            const messageId = connection.lastMsgId = incrementMessageID(connection.lastMsgId);
            const token = connection.lastToken = incrementToken(connection.lastToken);
            const tokenString = token.toString("hex");
            payload = payload || Buffer.from([]);
            // create message options, be careful to order them by code, no sorting is implemented yet
            const msgOptions = [];
            // [6] observe?
            msgOptions.push(Option_1.Options.Observe(true));
            // [11] path of the request
            let pathname = url.pathname || "";
            while (pathname.startsWith("/")) {
                pathname = pathname.slice(1);
            }
            while (pathname.endsWith("/")) {
                pathname = pathname.slice(0, -1);
            }
            const pathParts = pathname.split("/");
            msgOptions.push(...pathParts.map(part => Option_1.Options.UriPath(part)));
            // [12] content format
            msgOptions.push(Option_1.Options.ContentFormat(ContentFormats_1.ContentFormats.application_json));
            // create the promise we're going to return
            const response = DeferredPromise_1.createDeferredPromise();
            // create the message we're going to send
            const message = CoapClient.createMessage(type, code, messageId, token, msgOptions, payload);
            // create the retransmission info
            let retransmit;
            if (options.retransmit && type === Message_1.MessageType.CON) {
                const timeout = CoapClient.getRetransmissionInterval();
                retransmit = {
                    timeout,
                    action: () => CoapClient.retransmit(messageId),
                    jsTimeout: null,
                    counter: 0,
                };
            }
            // remember the request
            const req = new PendingRequest({
                connection,
                url: urlToString(url),
                originalMessage: message,
                retransmit,
                keepAlive: options.keepAlive,
                callback,
                observe: true,
                promise: null,
                concurrency: 0,
            });
            // remember the request
            CoapClient.rememberRequest(req);
            // now send the message
            CoapClient.send(connection, message);
        });
    }
    /**
     * Stops observation of the given url
     */
    static stopObserving(url) {
        // parse/convert url
        if (typeof url === "string") {
            url = nodeUrl.parse(url);
        }
        // normalize the url
        const urlString = urlToString(url);
        // and forget the request if we have one remembered
        CoapClient.forgetRequest({ url: urlString });
    }
    static onMessage(origin, message, rinfo) {
        // parse the CoAP message
        const coapMsg = Message_1.Message.parse(message);
        debug(`received message: ID=${coapMsg.messageId}${(coapMsg.token && coapMsg.token.length) ? (", token=" + coapMsg.token.toString("hex")) : ""}`);
        if (coapMsg.code.isEmpty()) {
            // ACK or RST
            // see if we have a request for this message id
            const request = CoapClient.findRequest({ msgID: coapMsg.messageId });
            if (request != null) {
                // reduce the request's concurrency, since it was handled on the server
                request.concurrency = 0;
                // handle the message
                switch (coapMsg.type) {
                    case Message_1.MessageType.ACK:
                        debug(`received ACK for ${coapMsg.messageId.toString(16)}, stopping retransmission...`);
                        // the other party has received the message, stop resending
                        CoapClient.stopRetransmission(request);
                        break;
                    case Message_1.MessageType.RST:
                        if (request.originalMessage.type === Message_1.MessageType.CON &&
                            request.originalMessage.code === Message_1.MessageCodes.empty) {
                            // resolve the promise
                            debug(`received response to ping ${coapMsg.messageId.toString(16)}`);
                            request.promise.resolve();
                        }
                        else {
                            // the other party doesn't know what to do with the request, forget it
                            debug(`received RST for ${coapMsg.messageId.toString(16)}, forgetting the request...`);
                            CoapClient.forgetRequest({ request });
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
                const tokenString = coapMsg.token.toString("hex");
                const request = CoapClient.findRequest({ token: tokenString });
                if (request) {
                    // if the message is an acknowledgement, stop resending
                    if (coapMsg.type === Message_1.MessageType.ACK) {
                        debug(`received ACK for ${coapMsg.messageId.toString(16)}, stopping retransmission...`);
                        CoapClient.stopRetransmission(request);
                        // reduce the request's concurrency, since it was handled on the server
                        request.concurrency = 0;
                    }
                    // parse options
                    let contentFormat = null;
                    if (coapMsg.options && coapMsg.options.length) {
                        // see if the response contains information about the content format
                        const optCntFmt = findOption(coapMsg.options, "Content-Format");
                        if (optCntFmt)
                            contentFormat = optCntFmt.value;
                    }
                    // prepare the response
                    const response = {
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
                        CoapClient.forgetRequest({ request });
                    }
                    // also acknowledge the packet if neccessary
                    if (coapMsg.type === Message_1.MessageType.CON) {
                        debug(`sending ACK for ${coapMsg.messageId.toString(16)}`);
                        const ACK = CoapClient.createMessage(Message_1.MessageType.ACK, Message_1.MessageCodes.empty, coapMsg.messageId);
                        CoapClient.send(request.connection, ACK, true);
                    }
                }
                else {
                    // no request found for this token, send RST so the server stops sending
                    // try to find the connection that belongs to this origin
                    const originString = origin.toString();
                    if (CoapClient.connections.hasOwnProperty(originString)) {
                        const connection = CoapClient.connections[originString];
                        // and send the reset
                        debug(`sending RST for ${coapMsg.messageId.toString(16)}`);
                        const RST = CoapClient.createMessage(Message_1.MessageType.RST, Message_1.MessageCodes.empty, coapMsg.messageId);
                        CoapClient.send(connection, RST, true);
                    }
                } // request != null?
            } // (coapMsg.token && coapMsg.token.length)
        } // (coapMsg.code.isResponse())
    }
    /**
     * Creates a message with the given parameters
     * @param type
     * @param code
     * @param messageId
     * @param token
     * @param options
     * @param payload
     */
    static createMessage(type, code, messageId, token = null, options = [], // do we need this?
        payload = null) {
        return new Message_1.Message(0x01, type, code, messageId, token, options, payload);
    }
    /**
     * Send a CoAP message to the given endpoint
     * @param connection The connection to send the message on
     * @param message The message to send
     * @param highPriority Whether the message should be prioritized
     */
    static send(connection, message, highPriority = false) {
        const request = CoapClient.findRequest({ msgID: message.messageId });
        if (highPriority) {
            // Send high-prio messages immediately
            debug(`sending high priority message with ID 0x${message.messageId.toString(16)}`);
            // TODO: this can be refactored
            if (request != null) {
                request.concurrency = 1;
                request.queueForRetransmission();
            }
            connection.socket.send(message.serialize(), connection.origin);
        }
        else {
            // Put the message in the queue
            CoapClient.sendQueue.push({ connection, message });
            debug(`added message to send queue, new length = ${CoapClient.sendQueue.length}`);
        }
        // if there's a request for this message, listen for concurrency changes
        if (request != null) {
            // and continue working off the queue when it drops
            request.on("concurrencyChanged", (req) => {
                debug(`request ${message.messageId.toString(16)}: concurrency changed => ${req.concurrency}`);
                if (request.concurrency === 0)
                    CoapClient.workOffSendQueue();
            });
        }
        // start working it off now (maybe)
        CoapClient.workOffSendQueue();
    }
    static workOffSendQueue() {
        // check if there are messages to send
        if (CoapClient.sendQueue.length === 0) {
            debug(`workOffSendQueue > queue empty`);
            return;
        }
        // check if we may send a message now
        debug(`workOffSendQueue > concurrency = ${CoapClient.calculateConcurrency()} (MAX ${MAX_CONCURRENCY})`);
        if (CoapClient.calculateConcurrency() < MAX_CONCURRENCY) {
            // get the next message to send
            const { connection, message } = CoapClient.sendQueue.shift();
            debug(`concurrency low enough, sending message ${message.messageId.toString(16)}`);
            // update the request's concurrency (it's now being handled)
            const request = CoapClient.findRequest({ msgID: message.messageId });
            if (request != null) {
                request.concurrency = 1;
                request.queueForRetransmission();
            }
            // send the message
            connection.socket.send(message.serialize(), connection.origin);
        }
        // to avoid any deadlocks we didn't think of, re-call this later
        setTimeout(CoapClient.workOffSendQueue, 1000);
    }
    /** Calculates the current concurrency, i.e. how many parallel requests are being handled */
    static calculateConcurrency() {
        return Object.keys(CoapClient.pendingRequestsByMsgID) // find all requests
            .map(msgid => CoapClient.pendingRequestsByMsgID[msgid])
            .map(req => req.concurrency) // extract their concurrency
            .reduce((sum, item) => sum + item, 0) // and sum it up
        ;
    }
    /**
     * Remembers a request for resending lost messages and tracking responses and updates
     * @param request
     * @param byUrl
     * @param byMsgID
     * @param byToken
     */
    static rememberRequest(request, byUrl = true, byMsgID = true, byToken = true) {
        let tokenString = "";
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
        debug(`remembering request: msgID=${request.originalMessage.messageId.toString(16)}, token=${tokenString}, url=${request.url}`);
    }
    /**
     * Forgets a pending request
     * @param request
     * @param byUrl
     * @param byMsgID
     * @param byToken
     */
    static forgetRequest(which) {
        // find the request
        const request = CoapClient.findRequest(which);
        // none found, return
        if (request == null)
            return;
        debug(`forgetting request: token=${request.originalMessage.token.toString("hex")}; msgID=${request.originalMessage.messageId}`);
        // stop retransmission if neccessary
        CoapClient.stopRetransmission(request);
        // delete all references
        const tokenString = request.originalMessage.token.toString("hex");
        if (CoapClient.pendingRequestsByToken.hasOwnProperty(tokenString)) {
            delete CoapClient.pendingRequestsByToken[tokenString];
        }
        const msgID = request.originalMessage.messageId;
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
            const origin = Origin_1.Origin.parse(request.url);
            const requestsOnOrigin = CoapClient.findRequestsByOrigin(origin).length;
            if (requestsOnOrigin === 0) {
                // this was the last request, close the connection
                CoapClient.reset(origin);
            }
        }
    }
    /**
     * Finds a request we have remembered by one of its properties
     * @param which
     */
    static findRequest(which) {
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
    }
    /**
     * Finds all pending requests of a given origin
     */
    static findRequestsByOrigin(origin) {
        const originString = origin.toString();
        return Object
            .keys(CoapClient.pendingRequestsByMsgID)
            .map(msgID => CoapClient.pendingRequestsByMsgID[msgID])
            .filter((req) => Origin_1.Origin.parse(req.url).toString() === originString);
    }
    /**
     * Tries to establish a connection to the given target. Returns true on success, false otherwise.
     * @param target The target to connect to. Must be a string, NodeJS.Url or Origin and has to contain the protocol, host and port.
     */
    static tryToConnect(target) {
        return __awaiter(this, void 0, void 0, function* () {
            // parse/convert url
            if (typeof target === "string") {
                target = Origin_1.Origin.parse(target);
            }
            else if (!(target instanceof Origin_1.Origin)) {
                target = Origin_1.Origin.fromUrl(target);
            }
            // retrieve or create the connection we're going to use
            const originString = target.toString();
            try {
                yield CoapClient.getConnection(target);
                return true;
            }
            catch (e) {
                return false;
            }
        });
    }
    /**
     * Establishes a new or retrieves an existing connection to the given origin
     * @param origin - The other party
     */
    static getConnection(origin) {
        const originString = origin.toString();
        if (CoapClient.connections.hasOwnProperty(originString)) {
            debug(`getConnection(${originString}) => found existing connection`);
            // return existing connection
            return Promise.resolve(CoapClient.connections[originString]);
        }
        else if (CoapClient.pendingConnections.hasOwnProperty(originString)) {
            debug(`getConnection(${originString}) => connection is pending`);
            // return the pending connection
            return CoapClient.pendingConnections[originString];
        }
        else {
            debug(`getConnection(${originString}) => establishing new connection`);
            // create a promise and start the connection queue
            const ret = DeferredPromise_1.createDeferredPromise();
            CoapClient.pendingConnections[originString] = ret;
            setTimeout(CoapClient.workOffPendingConnections, 0);
            return ret;
        }
    }
    static workOffPendingConnections() {
        return __awaiter(this, void 0, void 0, function* () {
            if (Object.keys(CoapClient.pendingConnections).length === 0) {
                // no more pending connections, we're done
                CoapClient.isConnecting = false;
                return;
            }
            else if (CoapClient.isConnecting) {
                // we're already busy
                return;
            }
            CoapClient.isConnecting = true;
            // Get the connection to establish
            const originString = Object.keys(CoapClient.pendingConnections)[0];
            const origin = Origin_1.Origin.parse(originString);
            const promise = CoapClient.pendingConnections[originString];
            delete CoapClient.pendingConnections[originString];
            // Try a few times to setup a working connection
            const maxTries = 3;
            let socket;
            for (let i = 1; i <= maxTries; i++) {
                try {
                    socket = yield CoapClient.getSocket(origin);
                    break; // it worked
                }
                catch (e) {
                    // if we are going to try again, ignore the error
                    // else throw it
                    if (i === maxTries) {
                        promise.reject(e);
                    }
                }
            }
            if (socket != null) {
                // add the event handler
                socket.on("message", CoapClient.onMessage.bind(CoapClient, originString));
                // initialize the connection params and remember them
                const ret = CoapClient.connections[originString] = {
                    origin,
                    socket,
                    lastMsgId: 0,
                    lastToken: crypto.randomBytes(TOKEN_LENGTH),
                };
                // and resolve the deferred promise
                promise.resolve(ret);
            }
            // continue working off the queue
            CoapClient.isConnecting = false;
            setTimeout(CoapClient.workOffPendingConnections, 0);
        });
    }
    /**
     * Establishes or retrieves a socket that can be used to send to and receive data from the given origin
     * @param origin - The other party
     */
    static getSocket(origin) {
        return __awaiter(this, void 0, void 0, function* () {
            switch (origin.protocol) {
                case "coap:":
                    // simply return a normal udp socket
                    return Promise.resolve(new SocketWrapper_1.SocketWrapper(dgram.createSocket("udp4")));
                case "coaps:":
                    // return a promise we resolve as soon as the connection is secured
                    const ret = DeferredPromise_1.createDeferredPromise();
                    // try to find security parameters
                    if (!CoapClient.dtlsParams.hasOwnProperty(origin.hostname)) {
                        return Promise.reject(`No security parameters given for the resource at ${origin.toString()}`);
                    }
                    const dtlsOpts = Object.assign({
                        type: "udp4",
                        address: origin.hostname,
                        port: origin.port,
                    }, CoapClient.dtlsParams[origin.hostname]);
                    // try connecting
                    const onConnection = () => {
                        debug("successfully created socket for origin " + origin.toString());
                        sock.removeListener("error", onError);
                        ret.resolve(new SocketWrapper_1.SocketWrapper(sock));
                    };
                    const onError = (e) => {
                        debug("socket creation for origin " + origin.toString() + " failed: " + e);
                        sock.removeListener("connected", onConnection);
                        ret.reject(e.message);
                    };
                    const sock = node_dtls_client_1.dtls
                        .createSocket(dtlsOpts)
                        .once("connected", onConnection)
                        .once("error", onError);
                    return ret;
                default:
                    throw new Error(`protocol type "${origin.protocol}" is not supported`);
            }
        });
    }
}
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
/** Number of message we expect an answer for */
CoapClient.concurrency = 0;
exports.CoapClient = CoapClient;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiQ29hcENsaWVudC5qcyIsInNvdXJjZVJvb3QiOiJEOi9ub2RlLWNvYXAtY2xpZW50L3NyYy8iLCJzb3VyY2VzIjpbIkNvYXBDbGllbnQudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6Ijs7Ozs7Ozs7OztBQUFBLGlDQUFpQztBQUNqQywrQkFBK0I7QUFDL0IsbUNBQXNDO0FBQ3RDLHVEQUF3QztBQUN4QywrQkFBK0I7QUFDL0IscURBQWtEO0FBQ2xELDJEQUErRTtBQUMvRSx5Q0FBc0M7QUFDdEMsdURBQW9EO0FBQ3BELHVDQUE0RTtBQUM1RSxxQ0FBc0Y7QUFFdEYsdUJBQXVCO0FBQ3ZCLHNDQUFzQztBQUN0QyxNQUFNLEtBQUssR0FBRyxZQUFZLENBQUMsa0JBQWtCLENBQUMsQ0FBQztBQUUvQyxxQkFBcUI7QUFDckIsMkNBQTJDO0FBQzNDLE1BQU0sVUFBVSxHQUFHLE9BQU8sQ0FBQyxpQkFBaUIsQ0FBQyxDQUFDLE9BQU8sQ0FBQztBQUN0RCxLQUFLLENBQUMsdUJBQXVCLFVBQVUsRUFBRSxDQUFDLENBQUM7QUFvQjNDLHFCQUFxQixHQUFnQjtJQUNwQyxNQUFNLENBQUMsR0FBRyxHQUFHLENBQUMsUUFBUSxLQUFLLEdBQUcsQ0FBQyxRQUFRLElBQUksR0FBRyxDQUFDLElBQUksR0FBRyxHQUFHLENBQUMsUUFBUSxFQUFFLENBQUM7QUFDdEUsQ0FBQztBQXNCRCxvQkFBcUIsU0FBUSxxQkFBWTtJQUV4QyxZQUFZLE9BQXlCO1FBQ3BDLEtBQUssRUFBRSxDQUFDO1FBQ1IsRUFBRSxDQUFDLENBQUMsQ0FBQyxPQUFPLENBQUM7WUFBQyxNQUFNLENBQUM7UUFFckIsSUFBSSxDQUFDLFVBQVUsR0FBRyxPQUFPLENBQUMsVUFBVSxDQUFDO1FBQ3JDLElBQUksQ0FBQyxHQUFHLEdBQUcsT0FBTyxDQUFDLEdBQUcsQ0FBQztRQUN2QixJQUFJLENBQUMsZUFBZSxHQUFHLE9BQU8sQ0FBQyxlQUFlLENBQUM7UUFDL0MsSUFBSSxDQUFDLFVBQVUsR0FBRyxPQUFPLENB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