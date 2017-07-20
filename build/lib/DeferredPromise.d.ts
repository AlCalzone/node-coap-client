/**
 * Superset of the promise class that allows to manually resolve or reject the promise
 */
export declare class DeferredPromise<T> extends Promise<T> {
    private res;
    /**
     * Resolve the promise with the given value
     */
    resolve(value?: T | PromiseLike<T>): void;
    private rej;
    /**
     * Resolve the promise with the given reason
     */
    reject(reason?: any): void;
    constructor();
}
