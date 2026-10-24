// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0
//
// AES (FIPS-197) block encryption plus the CFB mode OpenPGP uses. WebCrypto offers
// AES-CBC/CTR/GCM/KW but not CFB, and building CFB from single-block WebCrypto calls is far
// too slow for attachments, so the block cipher lives here. The tests check it against
// WebCrypto AES and against GnuPG output.

const SBOX = new Uint8Array(256);
const T0 = new Uint32Array(256), T1 = new Uint32Array(256), T2 = new Uint32Array(256), T3 = new Uint32Array(256);

(function init() {
    // Build the S-box from GF(2^8) inverses and the affine transform.
    const exp = new Uint8Array(256), log = new Uint8Array(256);
    for (let i = 0, x = 1; i < 255; i++) {
        exp[i] = x; log[x] = i;
        x ^= (x << 1) ^ ((x & 0x80) ? 0x11b : 0); // multiply by 3
        x &= 0xff;
    }
    for (let i = 0; i < 256; i++) {
        let s = i === 0 ? 0 : exp[(255 - log[i]) % 255];
        s = s ^ ((s << 1) | (s >> 7)) ^ ((s << 2) | (s >> 6)) ^ ((s << 3) | (s >> 5)) ^ ((s << 4) | (s >> 4)) ^ 0x63;
        SBOX[i] = s & 0xff;
    }
    const xtime = (b) => ((b << 1) ^ ((b & 0x80) ? 0x1b : 0)) & 0xff;
    for (let i = 0; i < 256; i++) {
        const s = SBOX[i], s2 = xtime(s), s3 = s2 ^ s;
        const t = ((s2 << 24) | (s << 16) | (s << 8) | s3) >>> 0;
        T0[i] = t;
        T1[i] = ((t >>> 8) | (t << 24)) >>> 0;
        T2[i] = ((t >>> 16) | (t << 16)) >>> 0;
        T3[i] = ((t >>> 24) | (t << 8)) >>> 0;
    }
})();

/** Expanded encryption key schedule for a 16/24/32-byte key. */
export function expandKey(key) {
    const nk = key.length / 4;
    if (![4, 6, 8].includes(nk)) throw new Error('AES key must be 16, 24 or 32 bytes');
    const rounds = nk + 6;
    const w = new Uint32Array(4 * (rounds + 1));
    for (let i = 0; i < nk; i++) w[i] = ((key[4 * i] << 24) | (key[4 * i + 1] << 16) | (key[4 * i + 2] << 8) | key[4 * i + 3]) >>> 0;
    let rcon = 1;
    for (let i = nk; i < w.length; i++) {
        let t = w[i - 1];
        if (i % nk === 0) {
            t = ((SBOX[(t >>> 16) & 0xff] << 24) | (SBOX[(t >>> 8) & 0xff] << 16) | (SBOX[t & 0xff] << 8) | SBOX[t >>> 24]) ^ (rcon << 24);
            rcon = ((rcon << 1) ^ ((rcon & 0x80) ? 0x1b : 0)) & 0xff;
        } else if (nk > 6 && i % nk === 4) {
            t = (SBOX[t >>> 24] << 24) | (SBOX[(t >>> 16) & 0xff] << 16) | (SBOX[(t >>> 8) & 0xff] << 8) | SBOX[t & 0xff];
        }
        w[i] = (w[i - nk] ^ t) >>> 0;
    }
    return { w, rounds };
}

/** Encrypt one 16-byte block from `input[inOff..]` into `out[outOff..]`. */
export function encryptBlock(ks, input, inOff, out, outOff) {
    const { w, rounds } = ks;
    let s0 = (((input[inOff] << 24) | (input[inOff + 1] << 16) | (input[inOff + 2] << 8) | input[inOff + 3]) ^ w[0]) >>> 0;
    let s1 = (((input[inOff + 4] << 24) | (input[inOff + 5] << 16) | (input[inOff + 6] << 8) | input[inOff + 7]) ^ w[1]) >>> 0;
    let s2 = (((input[inOff + 8] << 24) | (input[inOff + 9] << 16) | (input[inOff + 10] << 8) | input[inOff + 11]) ^ w[2]) >>> 0;
    let s3 = (((input[inOff + 12] << 24) | (input[inOff + 13] << 16) | (input[inOff + 14] << 8) | input[inOff + 15]) ^ w[3]) >>> 0;
    let k = 4;
    for (let r = 1; r < rounds; r++) {
        const t0 = T0[s0 >>> 24] ^ T1[(s1 >>> 16) & 0xff] ^ T2[(s2 >>> 8) & 0xff] ^ T3[s3 & 0xff] ^ w[k];
        const t1 = T0[s1 >>> 24] ^ T1[(s2 >>> 16) & 0xff] ^ T2[(s3 >>> 8) & 0xff] ^ T3[s0 & 0xff] ^ w[k + 1];
        const t2 = T0[s2 >>> 24] ^ T1[(s3 >>> 16) & 0xff] ^ T2[(s0 >>> 8) & 0xff] ^ T3[s1 & 0xff] ^ w[k + 2];
        const t3 = T0[s3 >>> 24] ^ T1[(s0 >>> 16) & 0xff] ^ T2[(s1 >>> 8) & 0xff] ^ T3[s2 & 0xff] ^ w[k + 3];
        s0 = t0 >>> 0; s1 = t1 >>> 0; s2 = t2 >>> 0; s3 = t3 >>> 0;
        k += 4;
    }
    const f = (a, b, c, d, rk) =>
        (((SBOX[a >>> 24] << 24) | (SBOX[(b >>> 16) & 0xff] << 16) | (SBOX[(c >>> 8) & 0xff] << 8) | SBOX[d & 0xff]) ^ rk) >>> 0;
    const o0 = f(s0, s1, s2, s3, w[k]), o1 = f(s1, s2, s3, s0, w[k + 1]);
    const o2 = f(s2, s3, s0, s1, w[k + 2]), o3 = f(s3, s0, s1, s2, w[k + 3]);
    for (const [i, v] of [[0, o0], [4, o1], [8, o2], [12, o3]]) {
        out[outOff + i] = v >>> 24; out[outOff + i + 1] = (v >>> 16) & 0xff;
        out[outOff + i + 2] = (v >>> 8) & 0xff; out[outOff + i + 3] = v & 0xff;
    }
}

/** Standard CFB-128 encryption (no OpenPGP resync), as used by SEIPD v1 and S2K-protected keys. */
export function cfbEncrypt(key, iv, data) {
    const ks = expandKey(key);
    const out = new Uint8Array(data.length);
    const fr = new Uint8Array(16), fre = new Uint8Array(16);
    fr.set(iv);
    for (let i = 0; i < data.length; i += 16) {
        encryptBlock(ks, fr, 0, fre, 0);
        const n = Math.min(16, data.length - i);
        for (let j = 0; j < n; j++) out[i + j] = data[i + j] ^ fre[j];
        if (n === 16) fr.set(out.subarray(i, i + 16));
    }
    return out;
}

export function cfbDecrypt(key, iv, data) {
    const ks = expandKey(key);
    const out = new Uint8Array(data.length);
    const fr = new Uint8Array(16), fre = new Uint8Array(16);
    fr.set(iv);
    for (let i = 0; i < data.length; i += 16) {
        encryptBlock(ks, fr, 0, fre, 0);
        const n = Math.min(16, data.length - i);
        for (let j = 0; j < n; j++) out[i + j] = data[i + j] ^ fre[j];
        if (n === 16) fr.set(data.subarray(i, i + 16));
    }
    return out;
}

// ---------------------------------------------------------------- decryption (equivalent inverse cipher)

const INV_SBOX = new Uint8Array(256);
const D0 = new Uint32Array(256), D1 = new Uint32Array(256), D2 = new Uint32Array(256), D3 = new Uint32Array(256);

(function initInverse() {
    for (let i = 0; i < 256; i++) INV_SBOX[SBOX[i]] = i;
    const mul = (a, b) => {
        let r = 0;
        for (; b; b >>= 1) {
            if (b & 1) r ^= a;
            a = ((a << 1) ^ ((a & 0x80) ? 0x1b : 0)) & 0xff;
        }
        return r;
    };
    for (let i = 0; i < 256; i++) {
        const s = INV_SBOX[i];
        const t = ((mul(s, 14) << 24) | (mul(s, 9) << 16) | (mul(s, 13) << 8) | mul(s, 11)) >>> 0;
        D0[i] = t;
        D1[i] = ((t >>> 8) | (t << 24)) >>> 0;
        D2[i] = ((t >>> 16) | (t << 16)) >>> 0;
        D3[i] = ((t >>> 24) | (t << 8)) >>> 0;
    }
})();

/** Decryption schedule: encryption round keys reversed, InvMixColumns applied to the inner rounds. */
export function expandDecryptKey(key) {
    const ks = expandKey(key);
    const { w, rounds } = ks;
    const dw = new Uint32Array(w.length);
    for (let r = 0; r <= rounds; r++) {
        for (let c = 0; c < 4; c++) {
            const v = w[4 * (rounds - r) + c];
            dw[4 * r + c] = r === 0 || r === rounds ? v
                : (D0[SBOX[v >>> 24]] ^ D1[SBOX[(v >>> 16) & 0xff]] ^ D2[SBOX[(v >>> 8) & 0xff]] ^ D3[SBOX[v & 0xff]]) >>> 0;
        }
    }
    return { w: dw, rounds };
}

export function decryptBlock(dks, input, inOff, out, outOff) {
    const { w, rounds } = dks;
    let s0 = (((input[inOff] << 24) | (input[inOff + 1] << 16) | (input[inOff + 2] << 8) | input[inOff + 3]) ^ w[0]) >>> 0;
    let s1 = (((input[inOff + 4] << 24) | (input[inOff + 5] << 16) | (input[inOff + 6] << 8) | input[inOff + 7]) ^ w[1]) >>> 0;
    let s2 = (((input[inOff + 8] << 24) | (input[inOff + 9] << 16) | (input[inOff + 10] << 8) | input[inOff + 11]) ^ w[2]) >>> 0;
    let s3 = (((input[inOff + 12] << 24) | (input[inOff + 13] << 16) | (input[inOff + 14] << 8) | input[inOff + 15]) ^ w[3]) >>> 0;
    let k = 4;
    for (let r = 1; r < rounds; r++) {
        const t0 = D0[s0 >>> 24] ^ D1[(s3 >>> 16) & 0xff] ^ D2[(s2 >>> 8) & 0xff] ^ D3[s1 & 0xff] ^ w[k];
        const t1 = D0[s1 >>> 24] ^ D1[(s0 >>> 16) & 0xff] ^ D2[(s3 >>> 8) & 0xff] ^ D3[s2 & 0xff] ^ w[k + 1];
        const t2 = D0[s2 >>> 24] ^ D1[(s1 >>> 16) & 0xff] ^ D2[(s0 >>> 8) & 0xff] ^ D3[s3 & 0xff] ^ w[k + 2];
        const t3 = D0[s3 >>> 24] ^ D1[(s2 >>> 16) & 0xff] ^ D2[(s1 >>> 8) & 0xff] ^ D3[s0 & 0xff] ^ w[k + 3];
        s0 = t0 >>> 0; s1 = t1 >>> 0; s2 = t2 >>> 0; s3 = t3 >>> 0;
        k += 4;
    }
    const f = (a, b, c, d, rk) =>
        (((INV_SBOX[a >>> 24] << 24) | (INV_SBOX[(b >>> 16) & 0xff] << 16) | (INV_SBOX[(c >>> 8) & 0xff] << 8) | INV_SBOX[d & 0xff]) ^ rk) >>> 0;
    const o0 = f(s0, s3, s2, s1, w[k]), o1 = f(s1, s0, s3, s2, w[k + 1]);
    const o2 = f(s2, s1, s0, s3, w[k + 2]), o3 = f(s3, s2, s1, s0, w[k + 3]);
    for (const [i, v] of [[0, o0], [4, o1], [8, o2], [12, o3]]) {
        out[outOff + i] = v >>> 24; out[outOff + i + 1] = (v >>> 16) & 0xff;
        out[outOff + i + 2] = (v >>> 8) & 0xff; out[outOff + i + 3] = v & 0xff;
    }
}

// ---------------------------------------------------------------- OCB (RFC 7253), 128-bit tags

function xorInto(a, b) { for (let i = 0; i < 16; i++) a[i] ^= b[i]; return a; }
function double(block) {
    const out = new Uint8Array(16);
    for (let i = 0; i < 15; i++) out[i] = ((block[i] << 1) | (block[i + 1] >>> 7)) & 0xff;
    out[15] = ((block[15] << 1) & 0xff) ^ ((block[0] & 0x80) ? 0x87 : 0);
    return out;
}
const ntz = (n) => { let z = 0; while ((n & 1) === 0) { n >>>= 1; z++; } return z; };

function ocbSetup(key) {
    const ks = expandKey(key);
    const enc = (b) => { const o = new Uint8Array(16); encryptBlock(ks, b, 0, o, 0); return o; };
    const lStar = enc(new Uint8Array(16));
    const lDollar = double(lStar);
    const L = [double(lDollar)];
    const l = (i) => { while (L.length <= i) L.push(double(L[L.length - 1])); return L[i]; };
    return { ks, enc, lStar, lDollar, l };
}

function ocbInitialOffset(ctx, nonce) {
    const n = new Uint8Array(16);
    n.set(nonce, 16 - nonce.length);
    n[15 - nonce.length] |= 0x01; // TAGLEN mod 128 = 0, then the 1 bit before N
    const bottom = n[15] & 0x3f;
    n[15] &= 0xc0;
    const ktop = ctx.enc(n);
    const stretch = new Uint8Array(24);
    stretch.set(ktop);
    for (let i = 0; i < 8; i++) stretch[16 + i] = ktop[i] ^ ktop[i + 1];
    const offset = new Uint8Array(16);
    const byteShift = bottom >>> 3, bitShift = bottom & 7;
    for (let i = 0; i < 16; i++) {
        offset[i] = ((stretch[i + byteShift] << bitShift) | (bitShift ? stretch[i + byteShift + 1] >>> (8 - bitShift) : 0)) & 0xff;
    }
    return offset;
}

function ocbHash(ctx, ad) {
    const sum = new Uint8Array(16), offset = new Uint8Array(16);
    const full = Math.floor(ad.length / 16);
    for (let i = 1; i <= full; i++) {
        xorInto(offset, ctx.l(ntz(i)));
        xorInto(sum, ctx.enc(xorInto(ad.slice((i - 1) * 16, i * 16), offset)));
    }
    if (ad.length % 16) {
        xorInto(offset, ctx.lStar);
        const block = new Uint8Array(16);
        block.set(ad.subarray(full * 16));
        block[ad.length % 16] = 0x80;
        xorInto(sum, ctx.enc(xorInto(block, offset)));
    }
    return sum;
}

function ocbCore(key, nonce, input, ad, decrypting) {
    const ctx = ocbSetup(key);
    const dks = decrypting ? expandDecryptKey(key) : null;
    const offset = ocbInitialOffset(ctx, nonce);
    const checksum = new Uint8Array(16);
    const out = new Uint8Array(input.length);
    const full = Math.floor(input.length / 16);
    const tmp = new Uint8Array(16);
    for (let i = 1; i <= full; i++) {
        xorInto(offset, ctx.l(ntz(i)));
        const block = xorInto(input.slice((i - 1) * 16, i * 16), offset);
        if (decrypting) decryptBlock(dks, block, 0, tmp, 0); else encryptBlock(ctx.ks, block, 0, tmp, 0);
        const res = xorInto(tmp.slice(), offset);
        out.set(res, (i - 1) * 16);
        xorInto(checksum, decrypting ? res : input.subarray((i - 1) * 16, i * 16));
    }
    const rest = input.length % 16;
    if (rest) {
        xorInto(offset, ctx.lStar);
        const pad = ctx.enc(offset);
        const plainTail = new Uint8Array(16);
        for (let j = 0; j < rest; j++) {
            out[full * 16 + j] = input[full * 16 + j] ^ pad[j];
            plainTail[j] = decrypting ? out[full * 16 + j] : input[full * 16 + j];
        }
        plainTail[rest] = 0x80;
        xorInto(checksum, plainTail);
    }
    const tag = xorInto(ctx.enc(xorInto(xorInto(checksum, offset), ctx.lDollar)), ocbHash(ctx, ad));
    return { out, tag };
}

/** OCB-AES encryption: returns ciphertext || 16-byte tag. */
export function ocbEncrypt(key, nonce, plaintext, ad) {
    const { out, tag } = ocbCore(key, nonce, plaintext, ad, false);
    const r = new Uint8Array(out.length + 16);
    r.set(out); r.set(tag, out.length);
    return r;
}

/** OCB-AES decryption of ciphertext || tag; returns null if authentication fails. */
export function ocbDecrypt(key, nonce, data, ad) {
    if (data.length < 16) return null;
    const { out, tag } = ocbCore(key, nonce, data.subarray(0, data.length - 16), ad, true);
    let diff = 0;
    for (let i = 0; i < 16; i++) diff |= tag[i] ^ data[data.length - 16 + i];
    return diff === 0 ? out : null;
}
