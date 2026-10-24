// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0
//
// OpenPGP messages (RFC 9580 section 10.3): encryption with SEIPD v1 (what GnuPG and
// every other implementation read), decryption, one-pass signed messages, detached and
// cleartext signatures.

import { concat, u16, utf8, toText, toHex, fromHex, equal, randomBytes, armor, ARMOR, toBinary, dearmor, PgpError } from './util.js';
import { cfbEncrypt, cfbDecrypt, ocbDecrypt } from './aes.js';
import { PK, COMPRESSION, symInfo, curveOf, rsaEncrypt, rsaDecrypt, elgamalEncrypt, elgamalDecrypt, ecdhEncrypt, ecdhDecrypt } from './algorithms.js';
import {
    TAG, SIG, readPackets, writePacket, parsePKESK, writePKESK, parseLiteral, writeLiteral,
    parseOnePass, writeOnePass, parseSignature,
} from './packets.js';
import { encryptionKeys, signingKey, keyParts, createSignature, verifyRaw } from './keys.js';

const subtle = globalThis.crypto.subtle;
const checksum16 = (bytes) => { let s = 0; for (const b of bytes) s = (s + b) & 0xffff; return u16(s); };

// ---------------------------------------------------------------- compression

async function pipe(data, stream) {
    const out = new Blob([data]).stream().pipeThrough(stream);
    return new Uint8Array(await new Response(out).arrayBuffer());
}

async function compress(algo, data) {
    if (algo === COMPRESSION.ZLIB) return pipe(data, new CompressionStream('deflate'));
    if (algo === COMPRESSION.ZIP) return pipe(data, new CompressionStream('deflate-raw'));
    return data;
}

async function decompress(algo, data) {
    try {
        if (algo === COMPRESSION.NONE) return data;
        if (algo === COMPRESSION.ZLIB) return await pipe(data, new DecompressionStream('deflate'));
        if (algo === COMPRESSION.ZIP) return await pipe(data, new DecompressionStream('deflate-raw'));
    } catch {
        throw new PgpError('The message is damaged (it could not be decompressed).');
    }
    throw new PgpError(algo === COMPRESSION.BZIP2 ? 'BZip2-compressed messages are not supported.' : `Unknown compression ${algo}.`);
}

// ---------------------------------------------------------------- helpers

/** Text-signature canonical form: CRLF line endings. */
export const canonicalText = (bytes) => utf8.encode(toText(bytes).replace(/\r?\n/g, '\r\n'));

function pickCommon(preferences, fallback, allowed) {
    for (const candidate of allowed) if (preferences.every((p) => p.includes(candidate))) return candidate;
    return fallback;
}

function hashFor(part) {
    if (part.algo === PK.ECDSA) {
        const name = curveOf(part.pub.oid).name;
        if (name === 'P-384') return 9;
        if (name === 'P-521') return 10;
    }
    return 8;
}

async function signPacket(type, signerPart, data) {
    const body = await createSignature({ type, signer: signerPart, hashAlgo: hashFor(signerPart), data });
    return writePacket(TAG.SIGNATURE, body);
}

/** The unlocked secret part to sign with, from { key, parts }. */
function signerPartOf(signer) {
    const part = signingKey(signer.key);
    if (!part) throw new PgpError('This key can\'t sign (it may have expired, been revoked, or its secret is on a smart card).');
    const unlocked = signer.parts[part.fingerprint];
    if (!unlocked) throw new PgpError('Unlock your key before signing.');
    return unlocked;
}

// ---------------------------------------------------------------- encryption

/**
 * Encrypt `data` to `recipients` (parsed public keys), optionally signing with
 * `signer` = { key, parts } (an unlocked secret key). Returns armored text, or bytes
 * with armor: false. `testing` lets the test-suite inject a session key and prefix so
 * output can be compared byte-for-byte with other implementations.
 */
export async function encrypt({ data, recipients, signer = null, filename = '', format = 'b', compression = true, armor: useArmor = true, testing = null }) {
    if (!recipients?.length) throw new PgpError('Choose at least one recipient.');
    const targets = recipients.map((key) => {
        const sub = encryptionKeys(key)[0];
        if (!sub) throw new PgpError(`${key.primaryUser?.userId ?? key.primary.keyId} has no valid encryption key (it may have expired or been revoked).`);
        return sub;
    });

    const sym = testing?.sym ?? pickCommon(recipients.map((k) => k.prefs.sym), 7, [9, 8, 7]);
    const compAlgo = !compression ? COMPRESSION.NONE
        : pickCommon(recipients.map((k) => [...k.prefs.compression, 0]), COMPRESSION.NONE, [COMPRESSION.ZLIB, COMPRESSION.ZIP, COMPRESSION.NONE]);

    const created = testing?.date ?? Math.floor(Date.now() / 1000);
    let inner = writeLiteral(data, { format, filename, date: created });
    if (signer) {
        const part = signerPartOf(signer);
        const sigType = format === 'b' ? SIG.BINARY : SIG.TEXT;
        const signed = sigType === SIG.TEXT ? canonicalText(data) : data;
        inner = concat(
            writeOnePass(sigType, hashFor(part), part.algo, fromHex(part.keyId)),
            inner,
            await signPacket(sigType, part, signed));
    }
    if (compAlgo !== COMPRESSION.NONE) inner = writePacket(TAG.COMPRESSED, concat(Uint8Array.of(compAlgo), await compress(compAlgo, inner)));

    const keySize = symInfo(sym).keySize;
    const sessionKey = testing?.sessionKey ?? randomBytes(keySize);
    const m = concat(Uint8Array.of(sym), sessionKey, checksum16(sessionKey));
    const pkesks = [];
    for (const t of targets) {
        const { algo, pub } = t.k;
        const keyId = fromHex(t.keyId);
        if (algo === PK.RSA || algo === PK.RSA_ENCRYPT) pkesks.push(writePKESK(keyId, algo, [rsaEncrypt(pub, m)]));
        else if (algo === PK.ELGAMAL) pkesks.push(writePKESK(keyId, algo, elgamalEncrypt(pub, m)));
        else if (algo === PK.ECDH) pkesks.push(writePKESK(keyId, algo, await ecdhEncrypt(pub, fromHex(t.fingerprint), m)));
        else throw new PgpError(`Can't encrypt to ${algo} keys.`);
    }

    const seipd = await seipdEncrypt(sessionKey, inner, testing?.prefix);
    const out = concat(...pkesks, seipd);
    return useArmor ? armor(ARMOR.message, out) : out;
}

async function seipdEncrypt(key, packets, testPrefix) {
    const random = testPrefix ?? randomBytes(16);
    const prefix = concat(random, random.subarray(14, 16));
    const plain = concat(prefix, packets, Uint8Array.of(0xd3, 0x14));
    const mdc = new Uint8Array(await subtle.digest('SHA-1', plain));
    return writePacket(TAG.SEIPD, concat(Uint8Array.of(1), cfbEncrypt(key, new Uint8Array(16), concat(plain, mdc))));
}

/** Symmetrically encrypt with a known session key (used by tests to compare implementations). */
export const encryptWithSessionKey = seipdEncrypt;

// ---------------------------------------------------------------- decryption

/** Key IDs a message is encrypted to (for "you need key X" messages). */
export function recipientsOf(message) {
    return readPackets(toBinary(message)).filter((p) => p.tag === TAG.PKESK).map((p) => parsePKESK(p.body).keyId).filter(Boolean);
}

async function decryptSessionKey(pkesk, part) {
    let m;
    if (pkesk.algo === PK.RSA || pkesk.algo === PK.RSA_ENCRYPT) m = rsaDecrypt({ ...part.pub, ...part.sec }, pkesk.c);
    else if (pkesk.algo === PK.ELGAMAL) m = elgamalDecrypt({ ...part.pub, ...part.sec }, pkesk.c1, pkesk.c2);
    else if (pkesk.algo === PK.ECDH) m = await ecdhDecrypt({ ...part.pub, ...part.sec }, fromHex(part.fingerprint), pkesk.point, pkesk.wrapped);
    else throw new PgpError('Unsupported session-key algorithm.');
    const sym = m[0];
    const key = m.subarray(1, m.length - 2);
    if (!equal(checksum16(key), m.subarray(m.length - 2)) || key.length !== symInfo(sym).keySize) throw new PgpError('Decryption failed.');
    return { sym, key };
}

/**
 * Decrypt with `decryptionKeys` = [{ key, parts }] (unlocked) and verify any signature
 * against `verificationKeys` (parsed public keys). Returns
 * { data, filename, format, signatures: [...], sessionKey }.
 */
export async function decrypt({ message, decryptionKeys, verificationKeys = [] }) {
    const packets = readPackets(toBinary(message));
    const pkesks = packets.filter((p) => p.tag === TAG.PKESK).map((p) => parsePKESK(p.body));
    const encrypted = packets.find((p) => p.tag === TAG.SEIPD || p.tag === TAG.OCB);
    if (packets.some((p) => p.tag === 9)) throw new PgpError('This message uses obsolete encryption without integrity protection and won\'t be decrypted.');
    if (!encrypted) throw new PgpError('This isn\'t an encrypted message.');
    if (encrypted.tag === TAG.SEIPD && encrypted.body[0] !== 1) throw new PgpError('This message uses RFC 9580 AEAD (SEIPD v2) encryption, which isn\'t supported yet.');

    const parts = decryptionKeys.flatMap(({ parts }) => Object.values(parts));
    let session = null;
    for (const pkesk of pkesks) {
        if (pkesk.unsupported) continue;
        const candidates = pkesk.keyId === '0000000000000000' ? parts : parts.filter((p) => p.keyId === pkesk.keyId);
        for (const part of candidates) {
            try { session = await decryptSessionKey(pkesk, part); break; } catch { /* try the next */ }
        }
        if (session) break;
    }
    if (!session) {
        const ids = pkesks.map((p) => p.keyId?.toUpperCase()).filter(Boolean);
        throw new PgpError(`None of your keys can decrypt this message.${ids.length ? ` It's encrypted to key ${ids.join(', ')}.` : ''}`);
    }

    const inner = encrypted.tag === TAG.OCB
        ? ocbPacketDecrypt(session, encrypted.body)
        : await seipdDecrypt(session.key, encrypted.body.subarray(1));
    const result = await readInner(inner, verificationKeys);
    return { ...result, sessionKey: session };
}

async function seipdDecrypt(key, data) {
    const dec = cfbDecrypt(key, new Uint8Array(16), data);
    if (dec.length < 16 + 2 + 22) throw new PgpError('The message is damaged.');
    // RFC 9580 5.13.1: an MDC failure must be fatal. The prefix "quick check" is not used as
    // a decision point (it would be a decryption oracle); the MDC covers it anyway.
    const body = dec.subarray(0, dec.length - 20);
    const mdc = new Uint8Array(await subtle.digest('SHA-1', body));
    if (dec[dec.length - 22] !== 0xd3 || dec[dec.length - 21] !== 0x14 || !equal(mdc, dec.subarray(dec.length - 20))) {
        throw new PgpError('The message has been modified or is corrupt (integrity check failed).');
    }
    return dec.subarray(18, dec.length - 22);
}

const u64 = (n) => { const b = new Uint8Array(8); let v = BigInt(n); for (let i = 7; i >= 0; i--) { b[i] = Number(v & 0xffn); v >>= 8n; } return b; };

/**
 * GnuPG 2.4's OCB Encrypted Data packet (tag 20, LibrePGP): chunks of ciphertext||tag, each
 * authenticated with its index, then a final tag over the total length (so truncation is
 * detected too). GnuPG writes it for keys whose features advertise its AEAD support.
 */
function ocbPacketDecrypt(session, body) {
    const [version, sym, aead, chunkByte] = body;
    if (version !== 1 || aead !== 2) throw new PgpError('Unsupported AEAD encryption (only OCB is supported).');
    if (sym !== session.sym) throw new PgpError('Decryption failed.');
    if (chunkByte > 56) throw new PgpError('The message is damaged.');
    const iv = body.subarray(4, 19);
    const data = body.subarray(19);
    if (data.length < 16) throw new PgpError('The message is damaged.');
    const header = Uint8Array.of(0xc0 | TAG.OCB, version, sym, aead, chunkByte);
    const chunkSize = 2 ** (chunkByte + 6);
    const nonceFor = (index) => { const n = iv.slice(); const c = u64(index); for (let i = 0; i < 8; i++) n[7 + i] ^= c[i]; return n; };
    const out = [];
    let offset = 0, index = 0, total = 0;
    const end = data.length - 16;
    while (offset < end) {
        const len = Math.min(chunkSize + 16, end - offset);
        const plain = ocbDecrypt(session.key, nonceFor(index), data.subarray(offset, offset + len), concat(header, u64(index)));
        if (!plain) throw new PgpError('The message has been modified or is corrupt (integrity check failed).');
        out.push(plain);
        total += plain.length;
        offset += len;
        index++;
    }
    const final = ocbDecrypt(session.key, nonceFor(index), data.subarray(end), concat(header, u64(index), u64(total)));
    if (!final) throw new PgpError('The message has been modified or truncated (integrity check failed).');
    return concat(...out);
}

/** Literal data plus signature results from a (possibly compressed, possibly signed) packet list. */
async function readInner(bytes, verificationKeys, depth = 0) {
    if (depth > 8) throw new PgpError('The message is nested too deeply.');
    const packets = readPackets(bytes);
    if (packets.length === 1 && packets[0].tag === TAG.COMPRESSED) {
        return readInner(await decompress(packets[0].body[0], packets[0].body.subarray(1)), verificationKeys, depth + 1);
    }
    const literals = packets.filter((p) => p.tag === TAG.LITERAL);
    if (literals.length !== 1) throw new PgpError('The message has an unexpected structure.');
    const literal = parseLiteral(literals[0].body);
    const sigs = packets.filter((p) => p.tag === TAG.SIGNATURE).map((p) => parseSignature(p.body));
    const signatures = [];
    for (const sig of sigs) signatures.push(await checkSignature(sig, literal.data, verificationKeys));
    return { data: literal.data, filename: literal.filename, format: literal.format, date: literal.date, signatures };
}

// ---------------------------------------------------------------- signatures

async function checkSignature(sig, data, keys) {
    const result = { keyId: sig.issuerKeyId?.toUpperCase() ?? null, fingerprint: sig.issuerFingerprint?.toUpperCase() ?? null, created: sig.created ? new Date(sig.created * 1000).toISOString() : null, valid: false, status: 'unknown-key', signer: null };
    if (sig.unsupported) return { ...result, status: 'unsupported' };
    if (sig.type !== SIG.BINARY && sig.type !== SIG.TEXT) return { ...result, status: 'unsupported' };
    const signed = sig.type === SIG.TEXT ? canonicalText(data) : data;
    for (const key of keys) {
        for (const part of keyParts(key)) {
            const match = sig.issuerFingerprint ? part.fingerprint === sig.issuerFingerprint : part.keyId === sig.issuerKeyId;
            if (!match) continue;
            result.fingerprint = key.primary.fingerprint.toUpperCase();
            result.signer = key.primaryUser?.userId ?? null;
            const ok = await verifyRaw(sig, part.k.algo, part.k.pub, signed);
            if (!ok) return { ...result, status: 'bad' };
            // The signature is genuine; is the key itself in good standing?
            const partValid = part === key.primary ? key.valid : part.valid && key.valid;
            if (key.revoked) return { ...result, status: 'revoked-key' };
            if (!partValid) return { ...result, status: key.expired ? 'expired-key' : 'invalid-key' };
            if (sig.hashAlgo === 2) return { ...result, valid: true, status: 'weak-hash' };
            return { ...result, valid: true, status: 'good' };
        }
    }
    return result;
}

/** Detached signature over `data` (binary, or text with CRLF canonicalisation). */
export async function signDetached({ data, signer, text = false, armor: useArmor = true }) {
    const part = signerPartOf(signer);
    const packet = await signPacket(text ? SIG.TEXT : SIG.BINARY, part, text ? canonicalText(data) : data);
    return useArmor ? armor(ARMOR.signature, packet) : packet;
}

export async function verifyDetached({ data, signature, keys }) {
    const sigs = readPackets(toBinary(signature)).filter((p) => p.tag === TAG.SIGNATURE).map((p) => parseSignature(p.body));
    if (!sigs.length) throw new PgpError('No signature found.');
    const out = [];
    for (const sig of sigs) out.push(await checkSignature(sig, data, keys));
    return out;
}

/** Sign without encrypting (inline, one-pass). */
export async function sign({ data, signer, filename = '', format = 'b', armor: useArmor = true }) {
    const part = signerPartOf(signer);
    const sigType = format === 'b' ? SIG.BINARY : SIG.TEXT;
    const out = concat(
        writeOnePass(sigType, hashFor(part), part.algo, fromHex(part.keyId)),
        writeLiteral(data, { format, filename, date: Math.floor(Date.now() / 1000) }),
        await signPacket(sigType, part, sigType === SIG.TEXT ? canonicalText(data) : data));
    return useArmor ? armor(ARMOR.message, out) : out;
}

/** Read a signed (not encrypted) OpenPGP message and verify it. */
export async function verifyMessage({ message, keys }) {
    return readInner(toBinary(message), keys);
}

/** Verify an inline "-----BEGIN PGP SIGNED MESSAGE-----" block. Returns { text, signatures }. */
export async function verifyCleartext({ message, keys }) {
    const m = /-----BEGIN PGP SIGNED MESSAGE-----\r?\n([\s\S]*?)\r?\n\r?\n([\s\S]*?)\r?\n(-----BEGIN PGP SIGNATURE-----[\s\S]*?-----END PGP SIGNATURE-----)/.exec(message);
    if (!m) throw new PgpError('No signed message found.');
    const lines = m[2].split(/\r?\n/).map((l) => (l.startsWith('- ') ? l.slice(2) : l));
    const text = lines.join('\n');
    // Cleartext signatures hash the text with trailing whitespace removed and CRLF endings.
    const canonical = utf8.encode(lines.map((l) => l.replace(/[ \t\r]+$/, '')).join('\r\n'));
    const sigs = readPackets(dearmor(m[3]).data).filter((p) => p.tag === TAG.SIGNATURE).map((p) => parseSignature(p.body));
    const signatures = [];
    for (const sig of sigs) {
        // checkSignature canonicalises again for TEXT signatures; the data is already canonical.
        signatures.push(await checkSignature({ ...sig, type: SIG.BINARY, _textType: true }, canonical, keys));
    }
    return { text, signatures };
}
