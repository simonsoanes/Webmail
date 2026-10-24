// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0
//
// Transferable keys (RFC 9580 section 10.1): parsing, self-signature validation, key
// selection, generation, and passphrase protection of secret key material.

import { concat, u16, u32, utf8, toHex, fromHex, equal, randomBytes, b64url, fromB64url, armor, ARMOR, toBinary, PgpError } from './util.js';
import { toBig, toBytes, modInv } from './bigint.js';
import { cfbEncrypt, cfbDecrypt } from './aes.js';
import {
    PK, PK_NAMES, HASH, CURVES, CURVE_OIDS, curveOf, symInfo, digest,
    rsaSign, rsaVerify, dsaVerify, ecdsaSign, ecdsaVerify, ed25519Sign, ed25519Verify, checkKeyPair,
} from './algorithms.js';
import {
    TAG, SIG, SUB, SECRET_FIELDS, readPackets, writePacket, readMPI, writeMPI, parseKeyPacket,
    writePublicKeyBody, readS2K, writeS2K, parseSignature, writeSubpackets,
} from './packets.js';

const subtle = globalThis.crypto.subtle;
const now = () => Math.floor(Date.now() / 1000);

export const FLAG = { CERTIFY: 0x01, SIGN: 0x02, ENCRYPT_COMMS: 0x04, ENCRYPT_STORAGE: 0x08, AUTH: 0x20 };

// ---------------------------------------------------------------- hashing helpers

export const keyData = (publicBody) => concat(Uint8Array.of(0x99), u16(publicBody.length), publicBody);
const uidData = (uid) => concat(Uint8Array.of(0xb4), u32(uid.length), uid);

export async function fingerprintOf(publicBody) {
    return toHex(new Uint8Array(await subtle.digest('SHA-1', keyData(publicBody))));
}

/** The bytes a v4 signature hashes: data || hashed header+subpackets || trailer. */
export const signedData = (sig, data) => concat(data, sig.hashedPart, Uint8Array.of(4, 0xff), u32(sig.hashedPart.length));

/** Verify a parsed v4 signature over `data` with a key's public material. */
export async function verifyRaw(sig, keyAlgo, pub, data) {
    if (sig.unsupported || sig.unknownCritical || !HASH[sig.hashAlgo]) return false;
    if (normaliseAlgo(sig.pkAlgo) !== normaliseAlgo(keyAlgo)) return false;
    const toHash = signedData(sig, data);
    const hash = await digest(sig.hashAlgo, toHash);
    if (hash[0] !== sig.left16[0] || hash[1] !== sig.left16[1]) return false;
    try {
        switch (sig.pkAlgo) {
            case PK.RSA: case PK.RSA_SIGN: return rsaVerify(pub, sig.hashAlgo, hash, sig.mpis[0]);
            case PK.DSA: return dsaVerify(pub, hash, sig.mpis[0], sig.mpis[1]);
            case PK.ECDSA: return await ecdsaVerify(curveOf(pub.oid), pub.point, sig.hashAlgo, toHash, sig.mpis[0], sig.mpis[1]);
            case PK.EDDSA_LEGACY: return await ed25519Verify(pub.point, hash, sig.mpis[0], sig.mpis[1]);
            default: return false;
        }
    } catch {
        return false;
    }
}

const normaliseAlgo = (a) => (a === PK.RSA_SIGN || a === PK.RSA_ENCRYPT ? PK.RSA : a);

/**
 * Create a v4 signature packet body. `signer` = { algo, pub, sec, fingerprint, keyId }.
 * `hashed`/`unhashed` are subpacket lists; creation time and issuer are added here.
 */
export async function createSignature({ type, signer, hashAlgo, data, hashed = [], unhashed = [], created = now() }) {
    const fpr = fromHex(signer.fingerprint);
    const hashedSubs = writeSubpackets([
        { type: SUB.CREATED, data: u32(created) },
        ...hashed,
        { type: SUB.ISSUER_FPR, data: concat(Uint8Array.of(4), fpr) },
    ]);
    const unhashedSubs = writeSubpackets([{ type: SUB.ISSUER, data: fpr.subarray(12) }, ...unhashed]);
    const hashedPart = concat(Uint8Array.of(4, type, signer.algo, hashAlgo), u16(hashedSubs.length), hashedSubs);
    const toHash = concat(data, hashedPart, Uint8Array.of(4, 0xff), u32(hashedPart.length));
    const hash = await digest(hashAlgo, toHash);
    let mpis;
    switch (signer.algo) {
        case PK.RSA: case PK.RSA_SIGN: mpis = [rsaSign({ ...signer.pub, ...signer.sec }, hashAlgo, hash)]; break;
        case PK.ECDSA: mpis = await ecdsaSign(curveOf(signer.pub.oid), signer.pub.point, signer.sec.d, hashAlgo, toHash); break;
        case PK.EDDSA_LEGACY: mpis = await ed25519Sign(signer.pub.point, signer.sec.d, hash); break;
        default: throw new PgpError(`Signing with ${PK_NAMES[signer.algo] ?? signer.algo} keys isn't supported.`);
    }
    return concat(hashedPart, u16(unhashedSubs.length), unhashedSubs, hash.subarray(0, 2), ...mpis.map(writeMPI));
}

// ---------------------------------------------------------------- reading keys

/** Parse one or more transferable keys (armored or binary). */
export async function readKeys(input) {
    const packets = readPackets(toBinary(input));
    const keys = [];
    let current = null, lastUser = null, lastSub = null;
    for (const p of packets) {
        if (p.tag === TAG.PUBLIC_KEY || p.tag === TAG.SECRET_KEY) {
            current = { packets: [], users: [], subkeys: [], keySigs: [], secret: p.tag === TAG.SECRET_KEY };
            const k = parseKeyPacket(p.tag, p.body);
            current.primary = { k, fingerprint: await fingerprintOf(k.publicBody), packet: p };
            current.primary.keyId = current.primary.fingerprint.slice(-16);
            keys.push(current);
            lastUser = lastSub = null;
        } else if (!current) {
            if (p.tag === TAG.MARKER || p.tag === TAG.TRUST || p.tag === TAG.PADDING) continue;
            throw new PgpError('This doesn\'t look like an OpenPGP key.');
        } else if (p.tag === TAG.USER_ID) {
            lastUser = { userId: new TextDecoder().decode(p.body), body: p.body, sigs: [], packet: p };
            current.users.push(lastUser);
            lastSub = null;
        } else if (p.tag === TAG.USER_ATTRIBUTE) {
            lastUser = { attribute: true, body: p.body, sigs: [], packet: p };
            lastSub = null;
        } else if (p.tag === TAG.PUBLIC_SUBKEY || p.tag === TAG.SECRET_SUBKEY) {
            let k;
            try { k = parseKeyPacket(p.tag, p.body); }
            catch {
                // Unsupported subkey (e.g. a curve browsers lack): unusable here, but kept so exports stay intact.
                lastSub = { skip: true, sigs: [] };
                current.packets.push(p);
                continue;
            }
            lastSub = { k, fingerprint: await fingerprintOf(k.publicBody), sigs: [], packet: p };
            lastSub.keyId = lastSub.fingerprint.slice(-16);
            current.subkeys.push(lastSub);
            lastUser = null;
        } else if (p.tag === TAG.SIGNATURE) {
            const sig = { ...parseSignature(p.body), packet: p };
            (lastSub ?? lastUser ?? { sigs: current.keySigs }).sigs.push(sig);
        }
        if (current && p.tag !== TAG.TRUST) current.packets.push(p);
    }
    for (const key of keys) await validate(key);
    return keys;
}

/**
 * Work out what a key may be used for right now: verified self-certifications,
 * bindings, revocations and expiry. Results are stored on the key object.
 */
async function validate(key, at = now()) {
    const P = key.primary;
    const primaryData = keyData(P.k.publicBody);
    const byPrimary = (s) => !s.issuerKeyId || s.issuerKeyId === P.keyId || s.issuerFingerprint === P.fingerprint;

    key.revoked = false;
    for (const s of key.keySigs) {
        if (s.type === SIG.KEY_REVOCATION && byPrimary(s) && await verifyRaw(s, P.k.algo, P.k.pub, primaryData)) key.revoked = true;
    }
    const directs = [];
    for (const s of key.keySigs) {
        if (s.type === SIG.DIRECT_KEY && byPrimary(s) && await verifyRaw(s, P.k.algo, P.k.pub, primaryData)) directs.push(s);
    }

    for (const u of key.users) {
        u.valid = false;
        const data = concat(primaryData, uidData(u.body));
        let best = null;
        for (const s of u.sigs) {
            if (!byPrimary(s)) continue;
            if (s.type >= SIG.CERT_GENERIC && s.type <= SIG.CERT_POSITIVE && await verifyRaw(s, P.k.algo, P.k.pub, data)) {
                if (!best || s.created > best.created) best = s;
            }
        }
        let revoked = false;
        for (const s of u.sigs) {
            if (s.type === SIG.CERT_REVOCATION && byPrimary(s) && await verifyRaw(s, P.k.algo, P.k.pub, data)
                && (!best || s.created >= best.created)) revoked = true;
        }
        u.selfSig = best;
        u.valid = !!best && !revoked;
        u.revoked = revoked;
    }

    const users = key.users.filter((u) => u.valid);
    key.primaryUser = users.find((u) => u.selfSig.primaryUid) ?? users.sort((a, b) => b.selfSig.created - a.selfSig.created)[0] ?? null;
    const prefsSig = key.primaryUser?.selfSig ?? directs.sort((a, b) => b.created - a.created)[0] ?? null;
    key.prefs = {
        sym: prefsSig?.prefSym ?? [9, 8, 7],
        hash: prefsSig?.prefHash ?? [8],
        compression: prefsSig?.prefCompression ?? [0],
        features: prefsSig?.features ?? 0,
    };
    key.primaryFlags = prefsSig?.keyFlags ?? null;
    const expiresIn = prefsSig?.keyExpiresIn ?? 0;
    key.expires = expiresIn ? P.k.created + expiresIn : null;
    key.expired = key.expires !== null && key.expires <= at;
    key.valid = !!prefsSig && !key.revoked && !key.expired;

    for (const sk of key.subkeys) {
        const data = concat(primaryData, keyData(sk.k.publicBody));
        let binding = null, revoked = false;
        for (const s of sk.sigs) {
            if (!byPrimary(s)) continue;
            if (s.type === SIG.SUBKEY_BINDING && await verifyRaw(s, P.k.algo, P.k.pub, data)) {
                // A signing-capable subkey must cross-certify the primary (back-signature).
                if ((s.keyFlags ?? 0) & FLAG.SIGN) {
                    const back = s.embedded;
                    if (!back || back.type !== SIG.PRIMARY_BINDING || !await verifyRaw(back, sk.k.algo, sk.k.pub, data)) continue;
                }
                if (!binding || s.created > binding.created) binding = s;
            } else if (s.type === SIG.SUBKEY_REVOCATION && await verifyRaw(s, P.k.algo, P.k.pub, data)) {
                revoked = true;
            }
        }
        sk.binding = binding;
        sk.flags = binding?.keyFlags ?? defaultFlags(sk.k.algo, false);
        sk.expires = binding?.keyExpiresIn ? sk.k.created + binding.keyExpiresIn : null;
        sk.revoked = revoked;
        sk.valid = !!binding && !revoked && (sk.expires === null || sk.expires > at);
    }
    key.stubs = secretStubs(key);
}

function defaultFlags(algo, primary) {
    if (algo === PK.RSA) return primary ? FLAG.CERTIFY | FLAG.SIGN : FLAG.ENCRYPT_COMMS | FLAG.ENCRYPT_STORAGE | FLAG.SIGN;
    if (algo === PK.ELGAMAL || algo === PK.ECDH || algo === PK.RSA_ENCRYPT) return FLAG.ENCRYPT_COMMS | FLAG.ENCRYPT_STORAGE;
    return primary ? FLAG.CERTIFY | FLAG.SIGN : FLAG.SIGN;
}

/** Which key parts have no usable secret (GnuPG "dummy" or on-smart-card stubs). */
function secretStubs(key) {
    if (!key.secret) return {};
    const out = {};
    for (const part of [key.primary, ...key.subkeys]) {
        const area = part.k.secretArea;
        if (!area || area.length === 0) { out[part.fingerprint] = 'missing'; continue; }
        if ((area[0] === 254 || area[0] === 255) && area[2] === 101) {
            try { out[part.fingerprint] = readS2K(area, 2)[0].gnu; } catch { out[part.fingerprint] = 'missing'; }
        }
    }
    return out;
}

const canEncrypt = (algo) => [PK.RSA, PK.RSA_ENCRYPT, PK.ELGAMAL, PK.ECDH].includes(algo);
const canSign = (algo) => [PK.RSA, PK.RSA_SIGN, PK.DSA, PK.ECDSA, PK.EDDSA_LEGACY].includes(algo);

/** Valid encryption (sub)keys, newest first. */
export function encryptionKeys(key) {
    if (!key.valid) return [];
    const out = key.subkeys
        .filter((s) => s.valid && canEncrypt(s.k.algo) && (s.flags & (FLAG.ENCRYPT_COMMS | FLAG.ENCRYPT_STORAGE)))
        .sort((a, b) => b.k.created - a.k.created);
    const pf = key.primaryFlags ?? defaultFlags(key.primary.k.algo, true);
    if (canEncrypt(key.primary.k.algo) && (pf & (FLAG.ENCRYPT_COMMS | FLAG.ENCRYPT_STORAGE))) out.push(key.primary);
    return out;
}

/** The (sub)key to sign messages with (must have a usable secret). */
export function signingKey(key) {
    if (!key.valid) return null;
    const usable = (part) => key.secret && !key.stubs[part.fingerprint];
    const subs = key.subkeys
        .filter((s) => s.valid && canSign(s.k.algo) && (s.flags & FLAG.SIGN) && usable(s))
        .sort((a, b) => b.k.created - a.k.created);
    if (subs.length) return subs[0];
    const pf = key.primaryFlags ?? defaultFlags(key.primary.k.algo, true);
    return canSign(key.primary.k.algo) && (pf & FLAG.SIGN) && usable(key.primary) ? key.primary : null;
}

/** All parts (primary + subkeys) — used to match signatures and PKESKs by key ID. */
export const keyParts = (key) => [key.primary, ...key.subkeys];

// ---------------------------------------------------------------- describing keys

export function describeAlgo(part) {
    const { algo, pub } = part.k;
    if (algo === PK.RSA || algo === PK.RSA_ENCRYPT || algo === PK.RSA_SIGN) return `RSA ${toBig(pub.n).toString(2).length}`;
    if (algo === PK.DSA || algo === PK.ELGAMAL) return `${PK_NAMES[algo]} ${toBig(pub.p).toString(2).length}`;
    try { return curveOf(pub.oid).name; } catch { return PK_NAMES[algo] ?? String(algo); }
}

/** A plain summary for the UI. */
export function summarise(key) {
    const enc = encryptionKeys(key)[0];
    const parts = keyParts(key);
    const onCard = Object.values(key.stubs).includes('card');
    return {
        fingerprint: key.primary.fingerprint.toUpperCase(),
        keyId: key.primary.keyId.toUpperCase(),
        algorithm: [describeAlgo(key.primary), ...key.subkeys.filter((s) => s.valid).map(describeAlgo)]
            .filter((v, i, a) => a.indexOf(v) === i).join(' + '),
        userIds: key.users.filter((u) => u.valid).map((u) => u.userId),
        primaryUserId: key.primaryUser?.userId ?? key.users[0]?.userId ?? null,
        created: new Date(key.primary.k.created * 1000).toISOString(),
        expires: key.expires ? new Date(key.expires * 1000).toISOString() : null,
        expired: key.expired,
        revoked: key.revoked,
        valid: key.valid,
        canEncrypt: !!enc,
        canSign: parts.some((p) => canSign(p.k.algo)),
        hasSecret: key.secret && parts.some((p) => !key.stubs[p.fingerprint]),
        secretOnCard: onCard,
        isSecret: key.secret,
        keyIds: parts.map((p) => p.keyId.toUpperCase()),
        emails: emailsOf(key),
    };
}

export function emailsOf(key) {
    return key.users.filter((u) => u.valid)
        .map((u) => (/<([^>]+)>/.exec(u.userId)?.[1] ?? (u.userId.includes('@') ? u.userId : null)))
        .filter(Boolean).map((e) => e.trim().toLowerCase());
}

// ---------------------------------------------------------------- export

/** Public key packets only (secret packets converted to their public form). */
export function publicPackets(key) {
    return concat(...key.packets.map((p) => {
        if (p.tag === TAG.SECRET_KEY) return writePacket(TAG.PUBLIC_KEY, parseKeyPacket(p.tag, p.body).publicBody);
        if (p.tag === TAG.SECRET_SUBKEY) return writePacket(TAG.PUBLIC_SUBKEY, parseKeyPacket(p.tag, p.body).publicBody);
        return p.raw;
    }));
}

export const armorPublic = (key) => armor(ARMOR.publicKey, publicPackets(key));
export const armorSecret = (key) => armor(ARMOR.privateKey, concat(...key.packets.map((p) => p.raw)));

// ---------------------------------------------------------------- S2K and secret protection

async function s2kDerive(passphrase, s2k, keySize) {
    const pass = typeof passphrase === 'string' ? utf8.encode(passphrase) : passphrase;
    const hashName = HASH[s2k.hash]?.name;
    if (!hashName) throw new PgpError(`Unsupported key-protection hash ${s2k.hash}.`);
    const base = s2k.type === 0 ? pass : concat(s2k.salt, pass);
    let input = base;
    if (s2k.type === 3) {
        const count = Math.max(s2k.count, base.length);
        input = new Uint8Array(count);
        let filled = Math.min(base.length, count);
        input.set(base.subarray(0, filled));
        while (filled < count) {
            const n = Math.min(filled, count - filled);
            input.copyWithin(filled, 0, n);
            filled += n;
        }
    }
    const out = new Uint8Array(keySize);
    for (let done = 0, zeros = 0; done < keySize; zeros++) {
        const h = new Uint8Array(await subtle.digest(hashName, zeros ? concat(new Uint8Array(zeros), input) : input));
        out.set(h.subarray(0, keySize - done), done);
        done += h.length;
    }
    return out;
}

function readSecretFields(algo, clear) {
    const sec = {};
    let o = 0;
    for (const f of SECRET_FIELDS[algo] ?? []) [sec[f], o] = readMPI(clear, o);
    return [sec, o];
}

function writeSecretFields(algo, sec) {
    return concat(...(SECRET_FIELDS[algo] ?? []).map((f) => writeMPI(sec[f])));
}

const checksum16 = (bytes) => { let s = 0; for (const b of bytes) s = (s + b) & 0xffff; return u16(s); };

/** Decrypt a key packet's secret area. */
export async function unlockPart(part, passphrase) {
    const area = part.k.secretArea;
    if (!area || area.length === 0) throw new PgpError('This key has no secret part.');
    const usage = area[0];
    let clear;
    if (usage === 0) {
        clear = area.subarray(1);
        const [sec, o] = readSecretFields(part.k.algo, clear);
        if (!equal(checksum16(clear.subarray(0, o)), clear.subarray(o, o + 2))) throw new PgpError('The secret key is damaged.');
        return sec;
    }
    if (usage !== 254 && usage !== 255) throw new PgpError('This secret key uses an obsolete protection scheme.');
    const sym = area[1];
    const [s2k, o] = readS2K(area, 2);
    if (s2k.type === 101) throw new PgpError(s2k.gnu === 'card' ? 'This key is stored on a smart card.' : 'This key has no secret part.');
    const info = symInfo(sym);
    const iv = area.subarray(o, o + 16);
    const enc = area.subarray(o + 16);
    const dec = cfbDecrypt(await s2kDerive(passphrase, s2k, info.keySize), iv, enc);
    if (usage === 254) {
        const body = dec.subarray(0, dec.length - 20);
        const sha = new Uint8Array(await subtle.digest('SHA-1', body));
        if (!equal(sha, dec.subarray(dec.length - 20))) throw new PgpError('Wrong passphrase.');
        clear = body;
    } else {
        const body = dec.subarray(0, dec.length - 2);
        if (!equal(checksum16(body), dec.subarray(dec.length - 2))) throw new PgpError('Wrong passphrase.');
        clear = body;
    }
    const [sec] = readSecretFields(part.k.algo, clear);
    if (!await checkKeyPair(part.k.algo, part.k.pub, sec)) throw new PgpError('The secret key doesn\'t match its public key.');
    return sec;
}

/** Secret area protected with AES-256 + iterated-salted SHA-256 S2K (or cleartext if no passphrase). */
async function protectArea(algo, sec, passphrase) {
    const clear = writeSecretFields(algo, sec);
    if (!passphrase) return concat(Uint8Array.of(0), clear, checksum16(clear));
    const s2k = { type: 3, hash: 8, salt: randomBytes(8), countByte: 224, count: 16 << 20 };
    const iv = randomBytes(16);
    const sha = new Uint8Array(await subtle.digest('SHA-1', clear));
    const enc = cfbEncrypt(await s2kDerive(passphrase, s2k, 32), iv, concat(clear, sha));
    return concat(Uint8Array.of(254, 9), writeS2K(s2k), iv, enc);
}

/**
 * Unlock every usable secret part with `oldPassphrase` and re-protect with `newPassphrase`.
 * Smart-card stubs are kept as they are. Returns the new armored secret key.
 */
export async function reprotect(key, oldPassphrase, newPassphrase) {
    const out = [];
    for (const p of key.packets) {
        if (p.tag !== TAG.SECRET_KEY && p.tag !== TAG.SECRET_SUBKEY) { out.push(p.raw); continue; }
        const part = [key.primary, ...key.subkeys].find((x) => x.packet === p);
        if (!part || key.stubs[part.fingerprint]) { out.push(p.raw); continue; }
        const sec = await unlockPart(part, oldPassphrase);
        out.push(writePacket(p.tag, concat(part.k.publicBody, await protectArea(part.k.algo, sec, newPassphrase))));
    }
    return armor(ARMOR.privateKey, concat(...out));
}

/** Unlock all usable secret parts. Returns { fingerprint -> {algo, pub, sec, fingerprint, keyId} }. */
export async function unlockKey(key, passphrase) {
    const parts = {};
    let any = false;
    for (const part of keyParts(key)) {
        if (key.stubs[part.fingerprint]) continue;
        parts[part.fingerprint] = { algo: part.k.algo, pub: part.k.pub, sec: await unlockPart(part, passphrase), fingerprint: part.fingerprint, keyId: part.keyId };
        any = true;
    }
    if (!any) throw new PgpError(Object.values(key.stubs).includes('card') ? 'This key\'s secrets are on a smart card.' : 'This key has no secret part.');
    return parts;
}

// ---------------------------------------------------------------- generation

async function generateMaterial(kind, purpose) {
    if (kind === 'curve25519') {
        if (purpose === 'sign') {
            const kp = await subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
            const jwk = await subtle.exportKey('jwk', kp.privateKey);
            return { algo: PK.EDDSA_LEGACY, pub: { oid: fromHex(CURVE_OIDS.Ed25519), point: concat(Uint8Array.of(0x40), fromB64url(jwk.x)) }, sec: { d: fromB64url(jwk.d) } };
        }
        const kp = await subtle.generateKey({ name: 'X25519' }, true, ['deriveBits']);
        const jwk = await subtle.exportKey('jwk', kp.privateKey);
        const d = fromB64url(jwk.d);
        d[0] &= 248; d[31] &= 127; d[31] |= 64; // clamp, as RFC 9580 section 5.5.5.6 requires
        return { algo: PK.ECDH, pub: { oid: fromHex(CURVE_OIDS.Curve25519), point: concat(Uint8Array.of(0x40), fromB64url(jwk.x)), kdfHash: 8, kdfSym: 7 }, sec: { d: d.reverse() } };
    }
    if (kind.startsWith('rsa')) {
        const bits = parseInt(kind.slice(3), 10);
        const kp = await subtle.generateKey({ name: 'RSASSA-PKCS1-v1_5', modulusLength: bits, publicExponent: Uint8Array.of(1, 0, 1), hash: 'SHA-256' }, true, ['sign']);
        const jwk = await subtle.exportKey('jwk', kp.privateKey);
        let p = fromB64url(jwk.p), q = fromB64url(jwk.q);
        if (toBig(p) > toBig(q)) [p, q] = [q, p]; // OpenPGP wants p < q, u = p^-1 mod q
        const u = toBytes(modInv(toBig(p), toBig(q)));
        return { algo: PK.RSA, pub: { n: fromB64url(jwk.n), e: fromB64url(jwk.e) }, sec: { d: fromB64url(jwk.d), p, q, u } };
    }
    const curveName = { p256: 'P-256', p384: 'P-384', p521: 'P-521' }[kind];
    if (!curveName) throw new PgpError(`Unknown key type ${kind}.`);
    const oid = fromHex(CURVE_OIDS[curveName]);
    const curve = CURVES[CURVE_OIDS[curveName]];
    const name = purpose === 'sign' ? 'ECDSA' : 'ECDH';
    const kp = await subtle.generateKey({ name, namedCurve: curveName }, true, purpose === 'sign' ? ['sign'] : ['deriveBits']);
    const jwk = await subtle.exportKey('jwk', kp.privateKey);
    const point = concat(Uint8Array.of(4), fromB64url(jwk.x), fromB64url(jwk.y));
    const pub = purpose === 'sign' ? { oid, point } : { oid, point, kdfHash: curve.kdf[0], kdfSym: curve.kdf[1] };
    return { algo: purpose === 'sign' ? PK.ECDSA : PK.ECDH, pub, sec: { d: fromB64url(jwk.d) } };
}

/**
 * Generate a primary signing key + encryption subkey, self-certified for `userIds`.
 * kind: curve25519 | rsa3072 | rsa4096 | p256 | p384 | p521.
 * Returns { publicKey, privateKey } armored; the private key is protected with `passphrase`.
 */
export async function generateKey({ userIds, kind = 'curve25519', passphrase, expiresInDays = 0, created = now() }) {
    if (!userIds?.length) throw new PgpError('A key needs at least one user ID.');
    const primary = { ...(await generateMaterial(kind, 'sign')), created };
    const sub = { ...(await generateMaterial(kind, 'encrypt')), created };
    const primaryBody = writePublicKeyBody(primary);
    const subBody = writePublicKeyBody(sub);
    const signer = { ...primary, fingerprint: await fingerprintOf(primaryBody) };
    const hashAlgo = kind === 'p521' ? 10 : kind === 'p384' ? 9 : 8;
    const expiry = expiresInDays > 0 ? [{ type: SUB.KEY_EXPIRES, data: u32(expiresInDays * 86400) }] : [];

    const packets = [writePacket(TAG.SECRET_KEY, concat(primaryBody, await protectArea(primary.algo, primary.sec, passphrase)))];
    const publicPackets = [writePacket(TAG.PUBLIC_KEY, primaryBody)];
    for (let i = 0; i < userIds.length; i++) {
        const uid = utf8.encode(userIds[i]);
        const sig = await createSignature({
            type: SIG.CERT_POSITIVE, signer, hashAlgo, created,
            data: concat(keyData(primaryBody), uidData(uid)),
            hashed: [
                { type: SUB.KEY_FLAGS, data: Uint8Array.of(FLAG.CERTIFY | FLAG.SIGN) },
                ...expiry,
                { type: SUB.PREF_SYM, data: Uint8Array.of(9, 8, 7) },
                { type: SUB.PREF_HASH, data: Uint8Array.of(10, 9, 8) },
                { type: SUB.PREF_COMPRESSION, data: Uint8Array.of(2, 1, 0) },
                { type: SUB.FEATURES, data: Uint8Array.of(0x01) },
                { type: SUB.KEYSERVER_PREFS, data: Uint8Array.of(0x80) },
                ...(i === 0 ? [{ type: SUB.PRIMARY_UID, data: Uint8Array.of(1) }] : []),
            ],
        });
        for (const list of [packets, publicPackets]) list.push(writePacket(TAG.USER_ID, uid), writePacket(TAG.SIGNATURE, sig));
    }
    const binding = await createSignature({
        type: SIG.SUBKEY_BINDING, signer, hashAlgo, created,
        data: concat(keyData(primaryBody), keyData(subBody)),
        hashed: [{ type: SUB.KEY_FLAGS, data: Uint8Array.of(FLAG.ENCRYPT_COMMS | FLAG.ENCRYPT_STORAGE) }, ...expiry],
    });
    packets.push(writePacket(TAG.SECRET_SUBKEY, concat(subBody, await protectArea(sub.algo, sub.sec, passphrase))), writePacket(TAG.SIGNATURE, binding));
    publicPackets.push(writePacket(TAG.PUBLIC_SUBKEY, subBody), writePacket(TAG.SIGNATURE, binding));

    return {
        fingerprint: signer.fingerprint.toUpperCase(),
        publicKey: armor(ARMOR.publicKey, concat(...publicPackets)),
        privateKey: armor(ARMOR.privateKey, concat(...packets)),
    };
}
