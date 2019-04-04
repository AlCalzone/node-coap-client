// the URL object is only available on the global scope since Node 10
// tslint:disable-next-line: no-namespace
declare namespace global {
	export let URL: URL;
}
if (!global.URL) {
	// tslint:disable-next-line: no-var-requires
	global.URL = require("url").URL;
}

/**
 * Identifies another endpoint (similar to the new WhatWG URL API "origin" property)
 */
export class Origin {
	constructor(
		public protocol: string,
		public hostname: string,
		public port: number,
	) {}

	public toString(): string {
		return `${this.protocol}//${this.hostname}:${this.port}`;
	}

	public static fromUrl(url: URL): Origin {
		return new Origin(url.protocol, url.hostname, +url.port);
	}

	public static parse(origin: string): Origin {
		return Origin.fromUrl(new URL(origin));
	}
}
