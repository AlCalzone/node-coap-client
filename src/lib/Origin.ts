import * as nodeUrl from "url";

/**
 * Identifies another endpoint (similar to the new WhatWG URL API "origin" property)
 */
export class Origin {
	constructor(
		public protocol: string,
		public hostname: string,
		public port: number
	) {}

	public toString(): string {
		return `${this.protocol}//${this.hostname}:${this.port}`;
	}

	static fromUrl(url: nodeUrl.Url): Origin {
		return new Origin(url.protocol, url.hostname, +url.port);
	}
}
