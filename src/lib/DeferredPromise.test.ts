import { describe, expect, it } from "vitest";
import { createDeferredPromise } from "./DeferredPromise.js";

describe("lib/DeferredPromise => createDeferredPromise() =>", () => {

	it("should resolve with the given value", async () => {
		const promiseRes = createDeferredPromise<boolean>();
		promiseRes.resolve(true);
		await expect(promiseRes).resolves.toBe(true);
	});

	it("should be rejected when reject() is called", async () => {
		const promiseRej = createDeferredPromise<boolean>();
		promiseRej.reject();
		await expect(promiseRej).rejects.toBeUndefined();
	});

	it("reject should normalize strings to errors", async () => {
		const promiseRej = createDeferredPromise<boolean>();
		promiseRej.reject("error message");
		await expect(promiseRej).rejects.toBeInstanceOf(Error);
	});

});
