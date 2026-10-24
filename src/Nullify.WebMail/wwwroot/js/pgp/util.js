// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0
//
// Byte helpers, Base64, ASCII armor (RFC 9580 section 6) and CRC-24.

export const utf8 = new TextEncoder();
const utf8d = new TextDecoder();

export const toText = (bytes) => utf8d.decode(bytes);

export function concat(...parts) {
    let length = 0;
    for (const p of parts) length += p.length;
    const out = new Uint8Array(length);
    let offset = 0;
    for (const p of parts) { out.set(p, offset); offset += p.length; }
    return out;
}

export const u16 = (n) => Uint8Array.of((n >>> 8) & 0xff, n & 0xff);
export const u32 = (n) => Uint8Array.of((n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff);
export const readU16 = (b, o) => (b[o] << 8) | b[o + 1];
export const readU32 = (b, o) => ((b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]) >>> 0;

export const toHex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
export function fromHex(s) {
    const clean = s.replace(/\s+/g, '');
    const out = new Uint8Array(clean.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.substr(i * 2, 2), 16);
    return out;
}

export function equal(a, b) {
    if (a.length !== b.length) return false;
    let diff = 0;
    for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
    return diff === 0;
}

export function randomBytes(n) {
    const out = new Uint8Array(n);
    for (let i = 0; i < n; i += 65536) crypto.getRandomValues(out.subarray(i, Math.min(n, i + 65536)));
    return out;
}

/** Random bytes with no zero octets (PKCS#1 v1.5 padding). */
export function randomNonZero(n) {
    const out = new Uint8Array(n);
    let filled = 0;
    while (filled < n) {
        for (const b of randomBytes(n - filled + 8)) {
            if (b !== 0 && filled < n) out[filled++] = b;
        }
    }
    return out;
}

export function b64encode(bytes) {
    let s = '';
    for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
    return btoa(s);
}

export function b64decode(s) {
    const bin = atob(s.replace(/[^A-Za-z0-9+/=]/g, ''));
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
}

export const b64url = (bytes) => b64encode(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
export const fromB64url = (s) => b64decode(s.replace(/-/g, '+').replace(/_/g, '/'));

// ---------------------------------------------------------------- CRC-24 and armor

export function crc24(bytes) {
    let crc = 0xb704ce;
    for (const b of bytes) {
        crc ^= b << 16;
        for (let i = 0; i < 8; i++) {
            crc <<= 1;
            if (crc & 0x1000000) crc ^= 0x1864cfb;
        }
    }
    return crc & 0xffffff;
}

export const ARMOR = {
    message: 'PGP MESSAGE',
    publicKey: 'PGP PUBLIC KEY BLOCK',
    privateKey: 'PGP PRIVATE KEY BLOCK',
    signature: 'PGP SIGNATURE',
};

export function armor(type, bytes, headers = {}) {
    const lines = [`-----BEGIN ${type}-----`];
    for (const [k, v] of Object.entries(headers)) lines.push(`${k}: ${v}`);
    lines.push('');
    const body = b64encode(bytes);
    for (let i = 0; i < body.length; i += 64) lines.push(body.slice(i, i + 64));
    const c = crc24(bytes);
    lines.push('=' + b64encode(Uint8Array.of(c >> 16, (c >> 8) & 0xff, c & 0xff)));
    lines.push(`-----END ${type}-----`);
    return lines.join('\r\n') + '\r\n';
}

/**
 * Parse the first armored block in `text`. Returns { type, headers, data }.
 * The checksum is verified when present (RFC 9580 makes it optional).
 */
export function dearmor(text) {
    const m = /-----BEGIN ([A-Z0-9 ,/]+)-----\r?\n([\s\S]*?)-----END \1-----/.exec(text);
    if (!m) throw new PgpError('No OpenPGP armor found.');
    const type = m[1];
    const lines = m[2].split(/\r?\n/);
    const headers = {};
    let i = 0;
    // Header lines run until the first blank line (if there is any "Key: value" line).
    if (lines.length && /^[A-Za-z][A-Za-z0-9-]*: /.test(lines[0])) {
        for (; i < lines.length && lines[i].trim() !== ''; i++) {
            const colon = lines[i].indexOf(': ');
            headers[lines[i].slice(0, colon)] = lines[i].slice(colon + 2);
        }
    }
    let body = '';
    let checksum = null;
    for (; i < lines.length; i++) {
        const line = lines[i].trim();
        if (line === '') continue;
        if (line.startsWith('=') && line.length === 5) { checksum = line.slice(1); continue; }
        body += line;
    }
    const data = b64decode(body);
    if (checksum !== null) {
        const c = b64decode(checksum);
        if (((c[0] << 16) | (c[1] << 8) | c[2]) !== crc24(data)) throw new PgpError('Armor checksum mismatch: the data is damaged.');
    }
    return { type, headers, data };
}

/** Accept armored text or raw packet bytes. */
export function toBinary(input) {
    if (input instanceof Uint8Array) {
        // Armored text delivered as bytes?
        if (input.length > 10 && input[0] === 0x2d /* '-' */) return dearmor(toText(input)).data;
        return input;
    }
    return dearmor(String(input)).data;
}

export class PgpError extends Error {
    constructor(message) { super(message); this.name = 'PgpError'; }
}
