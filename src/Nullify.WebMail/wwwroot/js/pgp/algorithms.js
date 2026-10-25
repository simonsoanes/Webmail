// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0
//
// Algorithm registry and public-key operations. WebCrypto does the elliptic-curve work
// (ECDSA, ECDH, Ed25519, X25519) and AES key wrap; RSA/ElGamal/DSA use BigInt because
// OpenPGP needs PKCS#1 v1.5 encryption and raw primitives WebCrypto doesn't expose.

import { concat, toHex, utf8, equal, randomNonZero, randomBytes, b64url, PgpError } from './util.js';
import { toBig, toBytes, modPow, modInv, mod, bitLength, randomBelow } from './bigint.js';

const subtle = globalThis.crypto.subtle;

export const PK = { RSA: 1, RSA_ENCRYPT: 2, RSA_SIGN: 3, ELGAMAL: 16, DSA: 17, ECDH: 18, ECDSA: 19, EDDSA_LEGACY: 22 };
export const PK_NAMES = { 1: 'RSA', 2: 'RSA', 3: 'RSA', 16: 'ElGamal', 17: 'DSA', 18: 'ECDH', 19: 'ECDSA', 22: 'EdDSA', 25: 'X25519', 27: 'Ed25519' };

export const HASH = {
    2: { name: 'SHA-1', size: 20, prefix: '3021300906052b0e03021a05000414' },
    8: { name: 'SHA-256', size: 32, prefix: '3031300d060960864801650304020105000420' },
    9: { name: 'SHA-384', size: 48, prefix: '3041300d060960864801650304020205000430' },
    10: { name: 'SHA-512', size: 64, prefix: '3051300d060960864801650304020305000440' },
};
export const HASH_IDS = { 'SHA-1': 2, 'SHA-256': 8, 'SHA-384': 9, 'SHA-512': 10 };

export const SYM = {
    7: { name: 'AES-128', keySize: 16 },
    8: { name: 'AES-192', keySize: 24 },
    9: { name: 'AES-256', keySize: 32 },
};

export const COMPRESSION = { NONE: 0, ZIP: 1, ZLIB: 2, BZIP2: 3 };

/** Curves by OID (hex). `kdf` is the RFC 6637 default for new ECDH keys. */
export const CURVES = {
    '2a8648ce3d030107': { name: 'P-256', size: 32, web: 'P-256', kdf: [8, 7] },
    '2b81040022': { name: 'P-384', size: 48, web: 'P-384', kdf: [9, 8] },
    '2b81040023': { name: 'P-521', size: 66, web: 'P-521', kdf: [10, 9] },
    '2b06010401da470f01': { name: 'Ed25519', size: 32, legacy: 'ed25519' },
    '2b060104019755010501': { name: 'Curve25519', size: 32, legacy: 'x25519', kdf: [8, 7] },
};
export const CURVE_OIDS = Object.fromEntries(Object.entries(CURVES).map(([oid, c]) => [c.name, oid]));

export function curveOf(oidBytes) {
    const c = CURVES[toHex(oidBytes)];
    if (!c) throw new PgpError(`Unsupported elliptic curve (OID ${toHex(oidBytes)}). Brainpool and secp256k1 aren't available in browsers.`);
    return c;
}

export function hashInfo(id) {
    const h = HASH[id];
    if (!h) throw new PgpError(`Unsupported hash algorithm ${id}.`);
    return h;
}

export function symInfo(id) {
    const s = SYM[id];
    if (!s) throw new PgpError(`Unsupported cipher ${id}: only AES is supported (legacy CAST5, 3DES, IDEA and Blowfish are not; CAST5-protected secret keys can still be imported).`);
    return s;
}

export async function digest(hashId, data) {
    return new Uint8Array(await subtle.digest(hashInfo(hashId).name, data));
}

// ---------------------------------------------------------------- PKCS#1 v1.5

function emsaPkcs1(hashId, hash, k) {
    const info = concat(fromHexLocal(hashInfo(hashId).prefix), hash);
    if (k < info.length + 11) throw new PgpError('RSA key too small for this hash.');
    const em = new Uint8Array(k).fill(0xff);
    em[0] = 0; em[1] = 1;
    em[k - info.length - 1] = 0;
    em.set(info, k - info.length);
    return em;
}

function fromHexLocal(s) {
    const out = new Uint8Array(s.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(s.substr(i * 2, 2), 16);
    return out;
}

function emeEncode(message, k) {
    if (message.length > k - 11) throw new PgpError('Message too long for RSA/ElGamal key.');
    return concat(Uint8Array.of(0, 2), randomNonZero(k - message.length - 3), Uint8Array.of(0), message);
}

function emeDecode(em) {
    // Constant-ish scan; a bad padding is reported only as a generic failure.
    if (em[0] !== 0 || em[1] !== 2) throw new PgpError('Decryption failed.');
    let sep = -1;
    for (let i = 2; i < em.length; i++) if (em[i] === 0 && sep < 0) sep = i;
    if (sep < 10) throw new PgpError('Decryption failed.');
    return em.subarray(sep + 1);
}

// ---------------------------------------------------------------- RSA

export function rsaEncrypt({ n, e }, message) {
    const N = toBig(n), k = Math.ceil(bitLength(N) / 8);
    return toBytes(modPow(toBig(emeEncode(message, k)), toBig(e), N));
}

function rsaPrivate({ n, d, p, q }, c) {
    const P = toBig(p), Q = toBig(q), D = toBig(d), C = toBig(c);
    const m1 = modPow(C, D % (P - 1n), P);
    const m2 = modPow(C, D % (Q - 1n), Q);
    const h = mod(modInv(Q, P) * (m1 - m2), P);
    return m2 + h * Q;
}

export function rsaDecrypt(key, c) {
    const k = Math.ceil(bitLength(toBig(key.n)) / 8);
    return emeDecode(toBytes(rsaPrivate(key, c), k));
}

export function rsaSign(key, hashId, hash) {
    const N = toBig(key.n), k = Math.ceil(bitLength(N) / 8);
    return toBytes(rsaPrivate(key, emsaPkcs1(hashId, hash, k)), k);
}

export function rsaVerify({ n, e }, hashId, hash, signature) {
    const N = toBig(n), k = Math.ceil(bitLength(N) / 8);
    const S = toBig(signature);
    if (S >= N) return false;
    return equal(toBytes(modPow(S, toBig(e), N), k), emsaPkcs1(hashId, hash, k));
}

// ---------------------------------------------------------------- ElGamal / DSA

export function elgamalEncrypt({ p, g, y }, message) {
    const P = toBig(p), k = Math.ceil(bitLength(P) / 8);
    const m = toBig(emeEncode(message, k));
    const r = randomBelow(P - 1n, randomBytes);
    return [toBytes(modPow(toBig(g), r, P)), toBytes(mod(m * modPow(toBig(y), r, P), P))];
}

export function elgamalDecrypt({ p, x }, c1, c2) {
    const P = toBig(p), k = Math.ceil(bitLength(P) / 8);
    const s = modPow(toBig(c1), toBig(x), P);
    return emeDecode(toBytes(mod(toBig(c2) * modInv(s, P), P), k));
}

export function dsaVerify({ p, q, g, y }, hash, r, s) {
    const P = toBig(p), Q = toBig(q), R = toBig(r), S = toBig(s);
    if (R <= 0n || R >= Q || S <= 0n || S >= Q) return false;
    const qBits = bitLength(Q);
    let z = toBig(hash.subarray(0, Math.min(hash.length, Math.ceil(qBits / 8))));
    const extra = Math.min(hash.length, Math.ceil(qBits / 8)) * 8 - qBits;
    if (extra > 0) z >>= BigInt(extra);
    const w = modInv(S, Q);
    const v = mod(modPow(toBig(g), mod(z * w, Q), P) * modPow(toBig(y), mod(R * w, Q), P), P) % Q;
    return v === R;
}

// ---------------------------------------------------------------- elliptic curves (WebCrypto)

const pad = (bytes, len) => (bytes.length >= len ? bytes.subarray(bytes.length - len) : concat(new Uint8Array(len - bytes.length), bytes));

function ecJwk(curve, point, d) {
    if (point[0] !== 4) throw new PgpError('Only uncompressed EC points are supported.');
    const x = point.subarray(1, 1 + curve.size), y = point.subarray(1 + curve.size);
    const jwk = { kty: 'EC', crv: curve.web, x: b64url(x), y: b64url(y), ext: true };
    if (d) jwk.d = b64url(pad(d, curve.size));
    return jwk;
}

export async function ecdsaSign(curve, point, d, hashId, data) {
    const key = await subtle.importKey('jwk', ecJwk(curve, point, d), { name: 'ECDSA', namedCurve: curve.web }, false, ['sign']);
    const sig = new Uint8Array(await subtle.sign({ name: 'ECDSA', hash: hashInfo(hashId).name }, key, data));
    return [sig.subarray(0, curve.size), sig.subarray(curve.size)];
}

export async function ecdsaVerify(curve, point, hashId, data, r, s) {
    const key = await subtle.importKey('raw', point, { name: 'ECDSA', namedCurve: curve.web }, false, ['verify']);
    if (r.length > curve.size || s.length > curve.size) return false;
    return subtle.verify({ name: 'ECDSA', hash: hashInfo(hashId).name }, key, concat(pad(r, curve.size), pad(s, curve.size)), data);
}

/** EdDSALegacy (algorithm 22): signs the digest, point is 0x40 || 32 bytes. */
export async function ed25519Sign(point, seed, hash) {
    const jwk = { kty: 'OKP', crv: 'Ed25519', x: b64url(point.subarray(1)), d: b64url(pad(seed, 32)), ext: true };
    const key = await subtle.importKey('jwk', jwk, { name: 'Ed25519' }, false, ['sign']);
    const sig = new Uint8Array(await subtle.sign({ name: 'Ed25519' }, key, hash));
    return [sig.subarray(0, 32), sig.subarray(32)];
}

export async function ed25519Verify(point, hash, r, s) {
    if (point[0] !== 0x40 || point.length !== 33) return false;
    const key = await subtle.importKey('raw', point.subarray(1), { name: 'Ed25519' }, false, ['verify']);
    return subtle.verify({ name: 'Ed25519' }, key, concat(pad(r, 32), pad(s, 32)), hash);
}

/** Derive an Ed25519 public point (0x40-prefixed) from a seed. */
export async function ed25519PublicFromSeed(seed) {
    // WebCrypto can't derive a public key from a raw seed directly; go through PKCS#8.
    const pkcs8 = concat(fromHexLocal('302e020100300506032b657004220420'), pad(seed, 32));
    const key = await subtle.importKey('pkcs8', pkcs8, { name: 'Ed25519' }, true, ['sign']);
    const jwk = await subtle.exportKey('jwk', key);
    return concat(Uint8Array.of(0x40), fromB64urlLocal(jwk.x));
}

function fromB64urlLocal(s) {
    const bin = atob(s.replace(/-/g, '+').replace(/_/g, '/'));
    return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

/** Raw shared secret for ECDH. `point` is the peer public point; `d` our secret. */
async function ecdhShared(curve, peerPoint, privateKey) {
    const algo = curve.legacy === 'x25519' ? { name: 'X25519' } : { name: 'ECDH', namedCurve: curve.web };
    const raw = curve.legacy === 'x25519' ? peerPoint.subarray(1) : peerPoint;
    const pub = await subtle.importKey('raw', raw, algo, false, []);
    const bits = curve.legacy === 'x25519' ? 256 : curve.size * 8;
    return new Uint8Array(await subtle.deriveBits({ name: algo.name, public: pub }, privateKey, bits));
}

async function importEcdhPrivate(curve, point, d) {
    if (curve.legacy === 'x25519') {
        // OpenPGP stores the X25519 scalar byte-reversed (as a big-endian MPI).
        const native = pad(d, 32).slice().reverse();
        const jwk = { kty: 'OKP', crv: 'X25519', x: b64url(point.subarray(1)), d: b64url(native), ext: true };
        return subtle.importKey('jwk', jwk, { name: 'X25519' }, false, ['deriveBits']);
    }
    return subtle.importKey('jwk', ecJwk(curve, point, d), { name: 'ECDH', namedCurve: curve.web }, false, ['deriveBits']);
}

async function ephemeral(curve) {
    if (curve.legacy === 'x25519') {
        const kp = await subtle.generateKey({ name: 'X25519' }, true, ['deriveBits']);
        return { privateKey: kp.privateKey, point: concat(Uint8Array.of(0x40), new Uint8Array(await subtle.exportKey('raw', kp.publicKey))) };
    }
    const kp = await subtle.generateKey({ name: 'ECDH', namedCurve: curve.web }, true, ['deriveBits']);
    return { privateKey: kp.privateKey, point: new Uint8Array(await subtle.exportKey('raw', kp.publicKey)) };
}

/** RFC 6637 section 7 KDF parameters. */
function ecdhParam(oid, kdfHash, kdfSym, fingerprint) {
    return concat(Uint8Array.of(oid.length), oid, Uint8Array.of(PK.ECDH, 3, 1, kdfHash, kdfSym), utf8.encode('Anonymous Sender    '), fingerprint);
}

async function ecdhKek(shared, kdfHash, kdfSym, param) {
    const h = await digest(kdfHash, concat(Uint8Array.of(0, 0, 0, 1), shared, param));
    return h.subarray(0, symInfo(kdfSym).keySize);
}

async function aesKwWrap(kek, data) {
    const k = await subtle.importKey('raw', kek, 'AES-KW', false, ['wrapKey']);
    const toWrap = await subtle.importKey('raw', data, { name: 'HMAC', hash: 'SHA-256' }, true, ['sign']);
    return new Uint8Array(await subtle.wrapKey('raw', toWrap, k, 'AES-KW'));
}

async function aesKwUnwrap(kek, wrapped) {
    const k = await subtle.importKey('raw', kek, 'AES-KW', false, ['unwrapKey']);
    try {
        const key = await subtle.unwrapKey('raw', wrapped, k, 'AES-KW', { name: 'HMAC', hash: 'SHA-256' }, true, ['sign']);
        return new Uint8Array(await subtle.exportKey('raw', key));
    } catch {
        throw new PgpError('Decryption failed.');
    }
}

const pkcs5Pad = (m) => { const n = 8 - (m.length % 8); return concat(m, new Uint8Array(n).fill(n)); };
function pkcs5Unpad(m) {
    const n = m[m.length - 1];
    if (n < 1 || n > 8 || n > m.length) throw new PgpError('Decryption failed.');
    for (let i = m.length - n; i < m.length; i++) if (m[i] !== n) throw new PgpError('Decryption failed.');
    return m.subarray(0, m.length - n);
}

/** Encrypt `message` (sym algo || key || checksum) to an ECDH key. Returns [ephemeral point, wrapped]. */
export async function ecdhEncrypt({ oid, point, kdfHash, kdfSym }, fingerprint, message) {
    const curve = curveOf(oid);
    const eph = await ephemeral(curve);
    const shared = await ecdhShared(curve, point, eph.privateKey);
    const kek = await ecdhKek(shared, kdfHash, kdfSym, ecdhParam(oid, kdfHash, kdfSym, fingerprint));
    return [eph.point, await aesKwWrap(kek, pkcs5Pad(message))];
}

export async function ecdhDecrypt({ oid, point, kdfHash, kdfSym, d }, fingerprint, ephemeralPoint, wrapped) {
    const curve = curveOf(oid);
    const priv = await importEcdhPrivate(curve, point, d);
    const shared = await ecdhShared(curve, ephemeralPoint, priv);
    const kek = await ecdhKek(shared, kdfHash, kdfSym, ecdhParam(oid, kdfHash, kdfSym, fingerprint));
    return pkcs5Unpad(await aesKwUnwrap(kek, wrapped));
}

/** Check that a secret key really matches its public half (catches corrupt or wrong imports). */
export async function checkKeyPair(algo, pub, sec) {
    switch (algo) {
        case PK.RSA: case PK.RSA_ENCRYPT: case PK.RSA_SIGN: {
            const p = toBig(sec.p), q = toBig(sec.q);
            return p * q === toBig(pub.n);
        }
        case PK.EDDSA_LEGACY:
            return equal(await ed25519PublicFromSeed(sec.d), pub.point);
        case PK.ECDH: case PK.ECDSA: case PK.ELGAMAL: case PK.DSA:
            return true; // verified by use (a wrong key fails to decrypt/sign verifiably)
        default:
            return false;
    }
}
