// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0
//
// BigInt arithmetic for RSA, ElGamal and DSA. WebCrypto has RSA-OAEP but not the PKCS#1
// v1.5 encryption OpenPGP mandates, and no ElGamal/DSA at all.

export function toBig(bytes) {
    let n = 0n;
    for (const b of bytes) n = (n << 8n) | BigInt(b);
    return n;
}

/** Big-endian bytes; left-padded to `length` when given. */
export function toBytes(n, length) {
    let hex = n.toString(16);
    if (hex.length % 2) hex = '0' + hex;
    let bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
    if (length !== undefined) {
        if (bytes.length > length) throw new Error('Number too large for field');
        const padded = new Uint8Array(length);
        padded.set(bytes, length - bytes.length);
        bytes = padded;
    }
    return bytes;
}

export const bitLength = (n) => (n === 0n ? 0 : n.toString(2).length);

export function mod(a, m) {
    const r = a % m;
    return r < 0n ? r + m : r;
}

export function modPow(base, exp, m) {
    if (m === 1n) return 0n;
    let result = 1n;
    base = mod(base, m);
    while (exp > 0n) {
        if (exp & 1n) result = (result * base) % m;
        exp >>= 1n;
        base = (base * base) % m;
    }
    return result;
}

export function modInv(a, m) {
    let [r0, r1] = [mod(a, m), m];
    let [s0, s1] = [1n, 0n];
    while (r1 !== 0n) {
        const q = r0 / r1;
        [r0, r1] = [r1, r0 - q * r1];
        [s0, s1] = [s1, s0 - q * s1];
    }
    if (r0 !== 1n) throw new Error('Not invertible');
    return mod(s0, m);
}

/** Uniform random integer in [1, max). */
export function randomBelow(max, randomBytes) {
    const len = Math.ceil(bitLength(max) / 8) + 8; // extra bytes keep modulo bias negligible
    while (true) {
        const n = toBig(randomBytes(len)) % max;
        if (n > 0n) return n;
    }
}
