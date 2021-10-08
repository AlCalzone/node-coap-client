import { getURLSafeHostname } from "./Hostname";
import { URL } from "url";

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
		return `${this.protocol}//${getURLSafeHostname(this.hostname)}:${this.port}`;
	}

	public static fromUrl(url: URL): Origin {
		return new Origin(url.protocol, url.hostname.replace(/(^\[|\]$)/g, ''), +url.port);
	}

	public static parse(origin: string): Origin {
		return Origin.fromUrl(new URL(origin));
	}
}
