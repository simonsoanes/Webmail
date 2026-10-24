// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0
//
// OpenPGP packet framing and (de)serialisation, RFC 9580 sections 4-5 (v4 keys/signatures).

import { concat, u16, u32, readU16, readU32, toHex, PgpError } from './util.js';
import { PK } from './algorithms.js';

export const TAG = {
    PKESK: 1, SIGNATURE: 2, ONE_PASS: 4, SECRET_KEY: 5, PUBLIC_KEY: 6, SECRET_SUBKEY: 7,
    COMPRESSED: 8, MARKER: 10, LITERAL: 11, TRUST: 12, USER_ID: 13, PUBLIC_SUBKEY: 14,
    USER_ATTRIBUTE: 17, SEIPD: 18, MDC: 19, OCB: 20, PADDING: 21,
};

// ---------------------------------------------------------------- framing

/** Split a packet sequence. Handles old- and new-format headers and partial body lengths. */
export function readPackets(bytes) {
    const out = [];
    let i = 0;
    const need = (n) => { if (i + n > bytes.length) throw new PgpError('The OpenPGP data is truncated.'); };
    while (i < bytes.length) {
        const start = i;
        const h = bytes[i++];
        if (!(h & 0x80)) throw new PgpError('This is not valid OpenPGP data.');
        let tag, body;
        if (h & 0x40) {
            tag = h & 0x3f;
            const parts = [];
            for (;;) {
                need(1);
                const l1 = bytes[i++];
                let len, partial = false;
                if (l1 < 192) len = l1;
                else if (l1 < 224) { need(1); len = ((l1 - 192) << 8) + bytes[i++] + 192; }
                else if (l1 === 255) { need(4); len = readU32(bytes, i); i += 4; }
                else { len = 1 << (l1 & 0x1f); partial = true; }
                need(len);
                parts.push(bytes.subarray(i, i + len));
                i += len;
                if (!partial) break;
            }
            body = parts.length === 1 ? parts[0] : concat(...parts);
        } else {
            tag = (h >> 2) & 0x0f;
            const lt = h & 3;
            let len;
            if (lt === 0) { need(1); len = bytes[i++]; }
            else if (lt === 1) { need(2); len = readU16(bytes, i); i += 2; }
            else if (lt === 2) { need(4); len = readU32(bytes, i); i += 4; }
            else len = bytes.length - i;
            need(len);
            body = bytes.subarray(i, i + len);
            i += len;
        }
        out.push({ tag, body, raw: bytes.subarray(start, i) });
    }
    return out;
}

function encodeLength(n) {
    if (n < 192) return Uint8Array.of(n);
    if (n < 8384) { const m = n - 192; return Uint8Array.of((m >> 8) + 192, m & 0xff); }
    return concat(Uint8Array.of(255), u32(n));
}

export const writePacket = (tag, body) => concat(Uint8Array.of(0xc0 | tag), encodeLength(body.length), body);

// ---------------------------------------------------------------- MPI

export function readMPI(b, o) {
    if (o + 2 > b.length) throw new PgpError('The OpenPGP data is truncated.');
    const bits = readU16(b, o);
    const len = (bits + 7) >> 3;
    if (o + 2 + len > b.length) throw new PgpError('The OpenPGP data is truncated.');
    return [b.subarray(o + 2, o + 2 + len), o + 2 + len];
}

export function writeMPI(bytes) {
    let i = 0;
    while (i < bytes.length - 1 && bytes[i] === 0) i++;
    const v = bytes.subarray(i);
    const bits = v.length === 0 || (v.length === 1 && v[0] === 0) ? 0 : (v.length - 1) * 8 + (32 - Math.clz32(v[0]));
    return concat(u16(bits), bits === 0 ? new Uint8Array(0) : v);
}

// ---------------------------------------------------------------- keys

/** Public key material field names per algorithm (in packet order). */
const PUBLIC_FIELDS = { 1: ['n', 'e'], 2: ['n', 'e'], 3: ['n', 'e'], 16: ['p', 'g', 'y'], 17: ['p', 'q', 'g', 'y'] };
export const SECRET_FIELDS = { 1: ['d', 'p', 'q', 'u'], 2: ['d', 'p', 'q', 'u'], 3: ['d', 'p', 'q', 'u'], 16: ['x'], 17: ['x'], 18: ['d'], 19: ['d'], 22: ['d'] };

/** Parse a (sub)key packet. Secret packets keep their (possibly encrypted) secret area for later. */
export function parseKeyPacket(tag, body) {
    const version = body[0];
    if (version !== 4) {
        throw new PgpError(version === 6 || version === 5
            ? `Version ${version} keys aren't supported yet; export a version 4 key instead.`
            : `Version ${version} keys are obsolete and not supported.`);
    }
    const created = readU32(body, 1);
    const algo = body[5];
    let o = 6;
    const pub = {};
    if (PUBLIC_FIELDS[algo]) {
        for (const f of PUBLIC_FIELDS[algo]) [pub[f], o] = readMPI(body, o);
    } else if (algo === PK.ECDSA || algo === PK.EDDSA_LEGACY || algo === PK.ECDH) {
        const oidLen = body[o++];
        pub.oid = body.subarray(o, o + oidLen); o += oidLen;
        [pub.point, o] = readMPI(body, o);
        if (algo === PK.ECDH) {
            const kdfLen = body[o];
            pub.kdfHash = body[o + 2];
            pub.kdfSym = body[o + 3];
            o += 1 + kdfLen;
        }
    } else {
        throw new PgpError(`Unsupported public-key algorithm ${algo}.`);
    }
    const key = { tag, version, created, algo, pub, publicBody: body.subarray(0, o) };
    if (tag === TAG.SECRET_KEY || tag === TAG.SECRET_SUBKEY) key.secretArea = body.subarray(o);
    return key;
}

/** Serialise the public part of a key (body only). */
export function writePublicKeyBody(key) {
    const parts = [Uint8Array.of(4), u32(key.created), Uint8Array.of(key.algo)];
    if (PUBLIC_FIELDS[key.algo]) {
        for (const f of PUBLIC_FIELDS[key.algo]) parts.push(writeMPI(key.pub[f]));
    } else {
        parts.push(Uint8Array.of(key.pub.oid.length), key.pub.oid, writeMPI(key.pub.point));
        if (key.algo === PK.ECDH) parts.push(Uint8Array.of(3, 1, key.pub.kdfHash, key.pub.kdfSym));
    }
    return concat(...parts);
}

// ---------------------------------------------------------------- S2K

/** Parse a string-to-key specifier at `o`. Returns [s2k, nextOffset]. */
export function readS2K(b, o) {
    const type = b[o];
    switch (type) {
        case 0: return [{ type, hash: b[o + 1] }, o + 2];
        case 1: return [{ type, hash: b[o + 1], salt: b.subarray(o + 2, o + 10) }, o + 10];
        case 3: {
            const c = b[o + 10];
            return [{ type, hash: b[o + 1], salt: b.subarray(o + 2, o + 10), countByte: c, count: (16 + (c & 15)) << ((c >> 4) + 6) }, o + 11];
        }
        case 101: {
            // GnuPG extension: "GNU" + mode. 1 = no secret (dummy), 2 = secret lives on a smart card.
            const mode = b[o + 5];
            let next = o + 6;
            let serial = null;
            if (mode === 2) { const len = b[next]; serial = toHex(b.subarray(next + 1, next + 1 + len)); next += 1 + len; }
            return [{ type, gnu: mode === 2 ? 'card' : 'dummy', serial }, next];
        }
        case 4: throw new PgpError('Argon2-protected keys are not supported yet.');
        default: throw new PgpError(`Unsupported key protection (S2K type ${type}).`);
    }
}

export function writeS2K(s2k) {
    return concat(Uint8Array.of(3, s2k.hash), s2k.salt, Uint8Array.of(s2k.countByte));
}

// ---------------------------------------------------------------- signatures

export const SIG = {
    BINARY: 0x00, TEXT: 0x01, STANDALONE: 0x02,
    CERT_GENERIC: 0x10, CERT_PERSONA: 0x11, CERT_CASUAL: 0x12, CERT_POSITIVE: 0x13,
    SUBKEY_BINDING: 0x18, PRIMARY_BINDING: 0x19, DIRECT_KEY: 0x1f,
    KEY_REVOCATION: 0x20, SUBKEY_REVOCATION: 0x28, CERT_REVOCATION: 0x30,
};

export const SUB = {
    CREATED: 2, SIG_EXPIRES: 3, EXPORTABLE: 4, REVOCABLE: 7, KEY_EXPIRES: 9, PREF_SYM: 11, REVOCATION_KEY: 12,
    ISSUER: 16, NOTATION: 20, PREF_HASH: 21, PREF_COMPRESSION: 22, KEYSERVER_PREFS: 23, PRIMARY_UID: 25,
    KEY_FLAGS: 27, SIGNER_UID: 28, REVOCATION_REASON: 29, FEATURES: 30, EMBEDDED_SIG: 32, ISSUER_FPR: 33,
};

function readSubpackets(b) {
    const subs = [];
    let o = 0;
    while (o < b.length) {
        let len;
        const l1 = b[o++];
        if (l1 < 192) len = l1;
        else if (l1 < 255) { len = ((l1 - 192) << 8) + b[o++] + 192; }
        else { len = readU32(b, o); o += 4; }
        if (len < 1 || o + len > b.length) throw new PgpError('Malformed signature subpacket.');
        const t = b[o];
        subs.push({ type: t & 0x7f, critical: !!(t & 0x80), data: b.subarray(o + 1, o + len) });
        o += len;
    }
    return subs;
}

export function writeSubpackets(list) {
    return concat(...list.map(({ type, data, critical }) =>
        concat(encodeLength(data.length + 1), Uint8Array.of(type | (critical ? 0x80 : 0)), data)));
}

/** Subpacket types we understand; an unknown *critical* one makes the signature invalid. */
const KNOWN_SUBS = new Set([2, 3, 4, 7, 9, 11, 12, 16, 20, 21, 22, 23, 25, 27, 28, 29, 30, 32, 33, 34, 39]);

export function parseSignature(body) {
    const version = body[0];
    if (version !== 4) return { version, unsupported: true };
    const type = body[1], pkAlgo = body[2], hashAlgo = body[3];
    const hashedLen = readU16(body, 4);
    const hashed = readSubpackets(body.subarray(6, 6 + hashedLen));
    let o = 6 + hashedLen;
    const unhashedLen = readU16(body, o);
    const unhashed = readSubpackets(body.subarray(o + 2, o + 2 + unhashedLen));
    o += 2 + unhashedLen;
    const left16 = body.subarray(o, o + 2);
    o += 2;
    const mpis = [];
    while (o < body.length) { let m; [m, o] = readMPI(body, o); mpis.push(m); }

    const sig = { version, type, pkAlgo, hashAlgo, hashed, unhashed, left16, mpis, hashedPart: body.subarray(0, 6 + hashedLen), body };
    const get = (t) => hashed.find((s) => s.type === t) ?? null;
    const any = (t) => get(t) ?? unhashed.find((s) => s.type === t) ?? null;
    sig.created = get(SUB.CREATED) ? readU32(get(SUB.CREATED).data, 0) : null;
    sig.expiresIn = get(SUB.SIG_EXPIRES) ? readU32(get(SUB.SIG_EXPIRES).data, 0) : 0;
    sig.keyExpiresIn = get(SUB.KEY_EXPIRES) ? readU32(get(SUB.KEY_EXPIRES).data, 0) : 0;
    sig.keyFlags = get(SUB.KEY_FLAGS)?.data[0] ?? null;
    sig.prefSym = get(SUB.PREF_SYM) ? Array.from(get(SUB.PREF_SYM).data) : null;
    sig.prefHash = get(SUB.PREF_HASH) ? Array.from(get(SUB.PREF_HASH).data) : null;
    sig.prefCompression = get(SUB.PREF_COMPRESSION) ? Array.from(get(SUB.PREF_COMPRESSION).data) : null;
    sig.features = get(SUB.FEATURES)?.data[0] ?? 0;
    sig.primaryUid = get(SUB.PRIMARY_UID)?.data[0] === 1;
    const fpr = any(SUB.ISSUER_FPR);
    sig.issuerFingerprint = fpr ? toHex(fpr.data.subarray(1)) : null;
    const issuer = any(SUB.ISSUER);
    sig.issuerKeyId = issuer ? toHex(issuer.data) : sig.issuerFingerprint ? sig.issuerFingerprint.slice(-16) : null;
    const embedded = any(SUB.EMBEDDED_SIG);
    sig.embedded = embedded ? parseSignature(embedded.data) : null;
    const reason = get(SUB.REVOCATION_REASON);
    sig.revocationReason = reason ? { code: reason.data[0], text: new TextDecoder().decode(reason.data.subarray(1)) } : null;
    sig.unknownCritical = hashed.some((s) => s.critical && !KNOWN_SUBS.has(s.type));
    return sig;
}

// ---------------------------------------------------------------- PKESK / literal / OPS / compressed

export function parsePKESK(body) {
    const version = body[0];
    if (version !== 3) return { version, unsupported: true };
    const keyId = toHex(body.subarray(1, 9));
    const algo = body[9];
    let o = 10;
    const fields = {};
    if (algo === PK.RSA || algo === PK.RSA_ENCRYPT) [fields.c, o] = readMPI(body, o);
    else if (algo === PK.ELGAMAL) { [fields.c1, o] = readMPI(body, o); [fields.c2, o] = readMPI(body, o); }
    else if (algo === PK.ECDH) {
        [fields.point, o] = readMPI(body, o);
        const len = body[o];
        fields.wrapped = body.subarray(o + 1, o + 1 + len);
    } else return { version, keyId, algo, unsupported: true };
    return { version, keyId, algo, ...fields };
}

export function writePKESK(keyIdBytes, algo, fields) {
    const parts = [Uint8Array.of(3), keyIdBytes, Uint8Array.of(algo)];
    if (algo === PK.ELGAMAL) parts.push(writeMPI(fields[0]), writeMPI(fields[1]));
    else if (algo === PK.ECDH) parts.push(writeMPI(fields[0]), Uint8Array.of(fields[1].length), fields[1]);
    else parts.push(writeMPI(fields[0]));
    return writePacket(TAG.PKESK, concat(...parts));
}

export function parseLiteral(body) {
    const format = String.fromCharCode(body[0]);
    const nameLen = body[1];
    const filename = new TextDecoder().decode(body.subarray(2, 2 + nameLen));
    const date = readU32(body, 2 + nameLen);
    return { format, filename, date, data: body.subarray(6 + nameLen) };
}

export function writeLiteral(data, { format = 'b', filename = '', date = 0 } = {}) {
    const name = new TextEncoder().encode(filename).subarray(0, 255);
    return writePacket(TAG.LITERAL, concat(Uint8Array.of(format.charCodeAt(0), name.length), name, u32(date), data));
}

export function parseOnePass(body) {
    return { version: body[0], type: body[1], hashAlgo: body[2], pkAlgo: body[3], keyId: toHex(body.subarray(4, 12)), nested: body[12] };
}

export function writeOnePass(type, hashAlgo, pkAlgo, keyIdBytes, last = true) {
    return writePacket(TAG.ONE_PASS, concat(Uint8Array.of(3, type, hashAlgo, pkAlgo), keyIdBytes, Uint8Array.of(last ? 1 : 0)));
}
