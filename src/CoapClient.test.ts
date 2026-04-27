import { describe, expect, it } from "vitest";

import { CoapClient as coap } from "./CoapClient.js";
import { Origin } from "./lib/Origin.js";

describe("CoapClient Tests =>", () => {

	coap.setSecurityParams("does-not-exist", {
		psk: { IDENTITY: "FOO" },
	});
	const correctOrigin = new Origin("coaps:", "does-not-exist", 5684);
	const correctOrigin_wrongCasing = new Origin("coaps:", "does-NOT-exist", 5684);
	const wrongOrigin = new Origin("coaps:", "does-not-exist2", 5684);

	it("connecting to a non-existing endpoint should fail with ENOTFOUND or DTLS timeout", async () => {
		await expect(coap.getConnection(correctOrigin)).rejects.toThrow(/(ENOTFOUND)|(DTLS handshake timed out)/);
	}, 10000);

	it("the hostname should not be case-sensitive", async () => {
		// we test against a non-existing endpoint, so ENOTFOUND should be thrown but not "No security parameters given"
		await expect(coap.getConnection(correctOrigin_wrongCasing)).rejects.toThrow(/(ENOTFOUND)|(DTLS handshake timed out)/);
	}, 10000);

	it("missing security params should fail the connection with the correct message", async () => {
		await expect(coap.getConnection(wrongOrigin)).rejects.toThrow("No security parameters");
	}, 10000);

});
