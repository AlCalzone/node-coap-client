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