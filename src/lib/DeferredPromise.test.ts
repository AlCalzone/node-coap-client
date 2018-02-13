import { expect, use } from "chai";
import * as chaiAsPromised from "chai-as-promised";

before(() => {
	use(chaiAsPromised);
});

import { createDeferredPromise } from "./DeferredPromise";
// tslint:disable:no-unused-expression

describe("lib/DeferredPromise => createDeferredPromise() =>", () => {

	const promiseRes = createDeferredPromise<boolean>();

	it("should resolve correctly", () => {
		return expect(promiseRes).to.become(true);
	});

	promiseRes.resolve(true);

	it("should be fulfilled", () => {
		return expect(promiseRes).to.be.fulfilled;
	});

	it("should be rejected", () => {
		// the promise has to get rejected inside it() or we'll get an uncaught rejection error
		const promiseRej = createDeferredPromise<boolean>();
		promiseRej.reject();
		return expect(promiseRej).to.be.rejected;
	});

	it("reject should normalize strings to errors", () => {
		// the promise has to get rejected inside it() or we'll get an uncaught rejection error
		const promiseRej = createDeferredPromise<boolean>();
		promiseRej.reject("error message");
		return expect(promiseRej).to.be.rejected.then(err => expect(err).to.be.an("Error"));
	});

});
