// tslint:disable:no-console
// tslint:disable:no-unused-expression
import { expect, should, use } from "chai";
import * as chaiAsPromised from "chai-as-promised";

before(() => {
	use(chaiAsPromised);
	should();
});

import { CoapClient as coap } from "./CoapClient";
import { Origin } from "./lib/Origin";

describe("CoapClient Tests =>", () => {

	coap.setSecurityParams("does-not-exist", {
		psk: { IDENTITY: "FOO" },
	});
	const correctOrigin = new Origin("coaps:", "does-not-exist", 5684);
	// tslint:disable-next-line:variable-name
	const correctOrigin_wrongCasing = new Origin("coaps:", "does-NOT-exist", 5684);
	const wrongOrigin = new Origin("coaps:", "does-not-exist2", 5684);

	it("connecting to a non-existing endpoint should fail with ENOTFOUND or DTLS timeout", function() {
		this.timeout(10000);
		return coap.getConnection(correctOrigin).should.be.rejectedWith(/(ENOTFOUND)|(DTLS handshake timed out)/);
	});
	it("the hostname should not be case-sensitive", function() {
		this.timeout(10000);
		// we test against a non-existing endpoint, so ENOTFOUND should be thrown but not "No security parameters given"
		return coap.getConnection(correctOrigin_wrongCasing).should.be.rejectedWith(/(ENOTFOUND)|(DTLS handshake timed out)/);
	});
	it("missing security params should fail the connection with the correct message", function() {
		this.timeout(10000);
		return coap.getConnection(wrongOrigin).should.be.rejectedWith("No security parameters");
	});

});
