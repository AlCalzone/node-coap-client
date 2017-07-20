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
Object.defineProperty(exports, "__esModule", { value: true });
/**
 * Superset of the promise class that allows to manually resolve or reject the promise
 */
var DeferredPromise = (function (_super) {
    __extends(DeferredPromise, _super);
    function DeferredPromise() {
        var _this = 
        // remember the resolve and reject functions so we can manually call them
        _super.call(this, function (resolve, reject) {
            _this.res = resolve;
            _this.rej = reject;
        }) || this;
        return _this;
    }
    /**
     * Resolve the promise with the given value
     */
    DeferredPromise.prototype.resolve = function (value) {
        this.res(value);
    };
    /**
     * Resolve the promise with the given reason
     */
    DeferredPromise.prototype.reject = function (reason) {
        this.rej(reason);
    };
    return DeferredPromise;
}(Promise));
exports.DeferredPromise = DeferredPromise;
//# sourceMappingURL=DeferredPromise.js.map