/**
 * Superset of the promise class that allows to manually resolve or reject the promise
 */
export class DeferredPromise<T> extends Promise<T> {

	private res: (value?: T | PromiseLike<T>) => void;
	/**
	 * Resolve the promise with the given value
	 */
	resolve(value?: T | PromiseLike<T>): void {
		this.res(value);
	}

	private rej: (reason?: any) => void;
	/**
	 * Resolve the promise with the given reason
	 */
	reject(reason?: any): void {
		this.rej(reason);
	}

	constructor() {
		// remember the resolve and reject functions so we can manually call them
		super((resolve, reject) => {
			this.res = resolve;
			this.rej = reject;
		});
	}

}