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
                    jsTimeout: setTimeout(() => CoapClient.retransmit(messageId), timeout),
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
        CoapClient.send(request.connection, request.originalMessage);
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
                    jsTimeout: setTimeout(() => CoapClient.retransmit(messageId), timeout),
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
        // Put the message in the queue
        if (highPriority) {
            // insert at the end of the high-priority queue
            CoapClient.sendQueue.splice(CoapClient.sendQueueHighPrioCount, 0, { connection, message });
            CoapClient.sendQueueHighPrioCount++;
        }
        else {
            // at the end
            CoapClient.sendQueue.push({ connection, message });
        }
        debug(`added message to send queue, new length = ${CoapClient.sendQueue.length} (high prio: ${CoapClient.sendQueueHighPrioCount})`);
        // if there's a request for this message, listen for concurrency changes
        const request = CoapClient.findRequest({ msgID: message.messageId });
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
CoapClient.sendQueueHighPrioCount = 0;
/** Number of message we expect an answer for */
CoapClient.concurrency = 0;
exports.CoapClient = CoapClient;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiQ29hcENsaWVudC5qcyIsInNvdXJjZVJvb3QiOiJDOi9Vc2Vycy9Eb21pbmljL0RvY3VtZW50cy9WaXN1YWwgU3R1ZGlvIDIwMTcvUmVwb3NpdG9yaWVzL25vZGUtY29hcC1jbGllbnQvc3JjLyIsInNvdXJjZXMiOlsiQ29hcENsaWVudC50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7Ozs7Ozs7O0FBQUEsaUNBQWlDO0FBQ2pDLCtCQUErQjtBQUMvQixtQ0FBc0M7QUFDdEMsdURBQXdDO0FBQ3hDLCtCQUErQjtBQUMvQixxREFBa0Q7QUFDbEQsMkRBQStFO0FBQy9FLHlDQUFzQztBQUN0Qyx1REFBb0Q7QUFDcEQsdUNBQTRFO0FBQzVFLHFDQUFzRjtBQUV0Rix1QkFBdUI7QUFDdkIsc0NBQXNDO0FBQ3RDLE1BQU0sS0FBSyxHQUFHLFlBQVksQ0FBQyxrQkFBa0IsQ0FBQyxDQUFDO0FBRS9DLHFCQUFxQjtBQUNyQiwyQ0FBMkM7QUFDM0MsTUFBTSxVQUFVLEdBQUcsT0FBTyxDQUFDLGlCQUFpQixDQUFDLENBQUMsT0FBTyxDQUFDO0FBQ3RELEtBQUssQ0FBQyx1QkFBdUIsVUFBVSxFQUFFLENBQUMsQ0FBQztBQW9CM0MscUJBQXFCLEdBQWdCO0lBQ3BDLE1BQU0sQ0FBQyxHQUFHLEdBQUcsQ0FBQyxRQUFRLEtBQUssR0FBRyxDQUFDLFFBQVEsSUFBSSxHQUFHLENBQUMsSUFBSSxHQUFHLEdBQUcsQ0FBQyxRQUFRLEVBQUUsQ0FBQztBQUN0RSxDQUFDO0FBc0JELG9CQUFxQixTQUFRLHFCQUFZO0lBRXhDLFlBQVksT0FBeUI7UUFDcEMsS0FBSyxFQUFFLENBQUM7UUFDUixFQUFFLENBQUMsQ0FBQyxDQUFDLE9BQU8sQ0FBQztZQUFDLE1BQU0sQ0FBQztRQUVyQixJQUFJLENBQUMsVUFBVSxHQUFHLE9BQU8sQ0FBQyxVQUFVLENBQUM7UUFDckMsSUFBSSxDQUFDLEdBQUcsR0FBRyxPQUFPLENBQUMsR0FBRyxDQUFDO1FBQ3ZCLElBQUksQ0FBQyxlQUFlLEdB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