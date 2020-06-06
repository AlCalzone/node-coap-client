/// <reference types="node" />
import { URL } from "url";
/**
 * Identifies another endpoint (similar to the new WhatWG URL API "origin" property)
 */
export declare class Origin {
    protocol: string;
    hostname: string;
    port: number;
    constructor(protocol: string, hostname: string, port: number);
    toString(): string;
    static fromUrl(url: URL): Origin;
    static parse(origin: string): Origin;
}
