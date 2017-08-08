import { expect } from "chai";

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

		expect(msg.version).to.equal(1, "data mismatch");
		expect(msg.type).to.equal(MessageType.ACK, "data mismatch");
		expect(msg.code).to.equal(0, "data mismatch");
		expect(msg.messageId).to.equal(0x1234, "data mismatch");
		expect(msg.token).to.deep.equal(Buffer.from([]), "data mismatch");
		expect(msg.options).to.deep.equal([], "data mismatch");
		expect(msg.payload).to.deep.equal(Buffer.from("abcdef", "hex"), "data mismatch");
	});

});
