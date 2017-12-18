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
        debug(`${Object.keys(CoapClient.pendingRequestsByMsgID).length} pending requests remaining...`);
        // cancel all pending connections matching the predicate
        for (const originString of Object.keys(CoapClient.pendingConnections)) {
            if (!predicate(originString))
                continue;
            CoapClient.pendingConnections[originString].reject("CoapClient was reset");
            delete CoapClient.pendingConnections[originString];
        }
        debug(`${Object.keys(CoapClient.pendingConnections).length} pending connections remaining...`);
        // forget all connections matching the predicate
        for (const originString of Object.keys(CoapClient.connections)) {
            if (!predicate(originString))
                continue;
            debug(`closing connection to ${originString}`);
            if (CoapClient.connections[originString].socket) {
                CoapClient.connections[originString].socket.close();
            }
            delete CoapClient.connections[originString];
        }
        debug(`${Object.keys(CoapClient.connections).length} active connections remaining...`);
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
            const connection = yield CoapClient.getConnection(origin);
            // find all the message parameters
            const type = options.confirmable ? Message_1.MessageType.CON : Message_1.MessageType.NON;
            const code = Message_1.MessageCodes.request[method];
            const messageId = connection.lastMsgId = incrementMessageID(connection.lastMsgId);
            const token = connection.lastToken = incrementToken(connection.lastToken);
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
        request.queueForRetransmission();
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
            const connection = yield CoapClient.getConnection(origin);
            // find all the message parameters
            const type = options.confirmable ? Message_1.MessageType.CON : Message_1.MessageType.NON;
            const code = Message_1.MessageCodes.request[method];
            const messageId = connection.lastMsgId = incrementMessageID(connection.lastMsgId);
            const token = connection.lastToken = incrementToken(connection.lastToken);
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
            // In contrast to requests, we don't work with a deferred promise when observing
            // Instead, we invoke a callback for *every* response.
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
        debug(`received message: ID=0x${coapMsg.messageId.toString(16)}${(coapMsg.token && coapMsg.token.length) ? (", token=" + coapMsg.token.toString("hex")) : ""}`);
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
                        debug(`received ACK for message 0x${coapMsg.messageId.toString(16)}, stopping retransmission...`);
                        // the other party has received the message, stop resending
                        CoapClient.stopRetransmission(request);
                        break;
                    case Message_1.MessageType.RST:
                        if (request.originalMessage.type === Message_1.MessageType.CON &&
                            request.originalMessage.code === Message_1.MessageCodes.empty) {
                            // resolve the promise
                            debug(`received response to ping with ID 0x${coapMsg.messageId.toString(16)}`);
                            request.promise.resolve();
                        }
                        else {
                            // the other party doesn't know what to do with the request, forget it
                            debug(`received RST for message 0x${coapMsg.messageId.toString(16)}, forgetting the request...`);
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
            debug(`response with payload: ${coapMsg.payload.toString("utf8")}`);
            // this is a response, find out what to do with it
            if (coapMsg.token && coapMsg.token.length) {
                // this message has a token, check which request it belongs to
                const tokenString = coapMsg.token.toString("hex");
                const request = CoapClient.findRequest({ token: tokenString });
                if (request) {
                    // if the message is an acknowledgement, stop resending
                    if (coapMsg.type === Message_1.MessageType.ACK) {
                        debug(`received ACK for message 0x${coapMsg.messageId.toString(16)}, stopping retransmission...`);
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
                        debug(`sending ACK for message 0x${coapMsg.messageId.toString(16)}`);
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
                        debug(`sending RST for message 0x${coapMsg.messageId.toString(16)}`);
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
            debug(`sending high priority message 0x${message.messageId.toString(16)}`);
            CoapClient.doSend(connection, request, message);
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
                debug(`request 0x${message.messageId.toString(16)}: concurrency changed => ${req.concurrency}`);
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
            debug(`concurrency low enough, sending message 0x${message.messageId.toString(16)}`);
            // update the request's concurrency (it's now being handled)
            const request = CoapClient.findRequest({ msgID: message.messageId });
            CoapClient.doSend(connection, request, message);
        }
        // to avoid any deadlocks we didn't think of, re-call this later
        setTimeout(CoapClient.workOffSendQueue, 1000);
    }
    /**
     * Does the actual sending of a message and starts concurrency/retransmission handling
     */
    static doSend(connection, request, message) {
        // handle concurrency/retransmission if neccessary
        if (request != null) {
            request.concurrency = 1;
            request.queueForRetransmission();
        }
        // send the message
        connection.socket.send(message.serialize(), connection.origin);
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
        debug(`remembering request: msgID=0x${request.originalMessage.messageId.toString(16)}, token=${tokenString}, url=${request.url}`);
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
        const request = which.request || CoapClient.findRequest(which);
        // none found, return
        if (request == null)
            return;
        let tokenString = "";
        if (request.originalMessage.token != null) {
            tokenString = request.originalMessage.token.toString("hex");
        }
        const msgID = request.originalMessage.messageId;
        debug(`forgetting request: token=${tokenString}; msgID=0x${msgID.toString(16)}`);
        // stop retransmission if neccessary
        CoapClient.stopRetransmission(request);
        // delete all references
        if (CoapClient.pendingRequestsByToken.hasOwnProperty(tokenString)) {
            delete CoapClient.pendingRequestsByToken[tokenString];
        }
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
exports.CoapClient = CoapClient;
