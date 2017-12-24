// tslint:disable:no-console
// tslint:disable:no-unused-expression
import { expect } from "chai";

import { CoapClient as coap } from "./CoapClient";
import { Message, MessageCode, MessageCodes, MessageType } from "./Message";

describe("Message Tests =>", () => {

	it("serialize", () => {
		const msg = new Message(
			1, MessageType.ACK, MessageCodes.empty, 0x1234, null, null, Buffer.from("abcdef", "hex"),
		);
		const expected = Buffer.from([
			0b01100000, 0, 0x12, 0x34, 0xff, 0xab, 0xcd, 0xef,
		]);
		const output = msg.serialize();

		expect(output).to.deep.equal(expected, "data mismatch");
	});

	it("deserialize", () => {
		const raw = Buffer.from([
			0b01100000, 0, 0x12, 0x34, 0xff, 0xab, 0xcd, 0xef,
		]);
		const msg = Message.parse(raw);

		expect(msg.version).to.equal(1, "data mismatch (version)");
		expect(msg.type).to.equal(MessageType.ACK, "data mismatch (type)");
		expect(msg.code.value).to.equal(0, "data mismatch (code)");
		expect(msg.messageId).to.equal(0x1234, "data mismatch (messageId)");
		expect(msg.token).to.deep.equal(Buffer.from([]), "data mismatch (token)");
		expect(msg.options).to.deep.equal([], "data mismatch (options)");
		expect(msg.payload).to.deep.equal(Buffer.from("abcdef", "hex"), "data mismatch (payload)");
	});

	// This buffer from https://github.com/AlCalzone/node-coap-client/issues/21
	// is a raw message contains the Block option
	const blockwiseMsg = Buffer.from(
		"64450025018fccf460613223093a80910eff7b2239303031223a224556455259444159" +
		"222c2239303032223a313530383235303135392c2239303638223a312c223930303322" +
		"3a3230303436382c2239303537223a302c223135303133223a5b7b2235383530223a31" +
		"2c2235383531223a3230332c2235373037223a353432372c2235373038223a34323539" +
		"362c2235373039223a33303031352c2235373130223a32363837302c2235373131223a" +
		"302c2235373036223a22663165306235222c2239303033223a36353533397d2c7b2235" +
		"383530223a312c2235383531223a3230332c2235373037223a353432372c2235373038" +
		"223a34323539362c2235373039223a33303031352c2235373130223a32363837302c22" +
		"35373131223a302c2235373036223a22663165306235222c2239303033223a36353534" +
		"307d2c7b2235383530223a312c2235383531223a3230332c2235373037223a35343237" +
		"2c2235373038223a34323539362c2235373039223a33303031352c2235373130223a32" +
		"363837302c2235373131223a302c2235373036223a22663165306235222c2239303033" +
		"223a36353534317d2c7b2235383530223a312c2235383531223a3230332c2235373037" +
		"223a353432372c2235373038223a34323539362c2235373039223a33303031352c2235" +
		"373130223a32363837302c2235373131223a302c2235373036223a2266316530623522" +
		"2c2239303033223a36353534327d2c7b2235383530223a312c2235383531223a323033" +
		"2c2235373037223a353432372c2235373038223a34323539362c2235373039223a3330" +
		"3031352c2235373130223a32363837302c2235373131223a302c2235373036223a2266" +
		"3165306235222c2239303033223a36353534337d2c7b2235383530223a312c22353835" +
		"31223a3230332c2235373037223a353432372c2235373038223a34323539362c223537" +
		"3039223a33303031352c2235373130223a32363837302c2235373131223a302c223537" +
		"3036223a22663165306235222c2239303033223a36353534347d2c7b2235383530223a" +
		"312c2235383531223a3230332c2235373037223a353432372c2235373038223a343235" +
		"39362c2235373039223a33303031352c2235373130223a32363837302c223537313122" +
		"3a302c2235373036223a22663165306235222c2239303033223a36353534357d2c7b22" +
		"35383530223a312c2235383531223a3230332c2235373037223a353432372c22353730" +
		"38223a34323539362c2235373039223a33303031352c2235373130223a32363837302c" +
		"2235373131223a302c2235373036223a22663165306235222c2239303033223a363535" +
		"34367d2c7b2235383530223a312c2235383531223a3230332c2235373037223a353432" +
		"372c2235373038223a34323539362c2235373039223a3330303135",
		"hex",
	);

	it("should parse blockwise messages without crashing", () => {
		const msg = Message.parse(blockwiseMsg);
		// console.log(`code: ${msg.code}`);
		// console.log(`messageId: ${msg.messageId}`);
		// if (msg.token != null) {
		// 	console.log(`token: ${msg.token.toString("hex")}`);
		// }
		// console.log(`type: ${msg.type}`);
		// console.log(`version: ${msg.version}`);
		// console.log("options:");
		// for (const opt of msg.options) {
		// 	console.log(`  [${opt.constructor.name}] ${opt.toString()}`);
		// }
		// console.log("payload:");
		// console.log(msg.payload.toString("utf-8"));
	});

});
