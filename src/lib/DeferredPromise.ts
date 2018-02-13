export interface DeferredPromise<T> extends Promise<T> {
	resolve(value?: T | PromiseLike<T>): void;

	reject(reason: Error): void;
	reject(reason?: any): void;
}

function normalizeReason(reason?: any): any {
	if (typeof reason === "string") return new Error(reason);
	return reason;
}

export function createDeferredPromise<T>(): DeferredPromise<T> {
	let res: (value?: T | PromiseLike<T>) => void;
	let rej: (reason?: any) => void;

	const promise = new Promise<T>((resolve, reject) => {
		res = resolve;
		rej = (reason?: any) => { reject(normalizeReason(reason)); };
	}) as DeferredPromise<T>;

	promise.resolve = res;
	promise.reject = rej;

	return promise;
}
