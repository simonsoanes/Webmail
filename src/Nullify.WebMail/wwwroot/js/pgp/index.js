// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0
//
// Nullify OpenPGP: a small RFC 9580 (v4 keys, SEIPD v1) implementation on WebCrypto,
// with RSA, ElGamal and DSA via BigInt. Runs unchanged in browsers and Node 22+.
//
// Supported: RSA, ECDSA/ECDH on P-256/P-384/P-521, Ed25519/Curve25519 (legacy v4 form),
// ElGamal encryption, DSA verification; AES-128/192/256; SHA-1/256/384/512; ZIP/ZLIB.
// CAST5 only to open secret keys exported by GnuPG before 2.1.
// Not supported: v5/v6 keys, SEIPD v2 (AEAD), Argon2, brainpool/secp256k1, BZip2, and the
// legacy ciphers (3DES, IDEA, Blowfish; CAST5 for messages).

export { PgpError, armor, dearmor, ARMOR } from './util.js';
export { readKeys, generateKey, summarise, emailsOf, unlockKey, reprotect, armorPublic, armorSecret, encryptionKeys, signingKey } from './keys.js';
export { encrypt, decrypt, sign, signDetached, verifyDetached, verifyMessage, verifyCleartext, recipientsOf } from './message.js';
