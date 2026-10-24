// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0
//
// Blazor <-> OpenPGP engine bridge. Secret keys arrive here still protected (passphrase or
// security key) and are only ever unlocked in this page's memory. Unlocked keys are dropped
// after 30 idle minutes, on lock(), and on reload. Large data moves as streams.
//
// Passphrases (typed, or derived from a security key) and unprotected secret keys must never
// reach the server, and with Blazor Server anything handed to .NET does. So .NET passes the
// input elements in, this module reads, validates, uses and clears them, and only protected
// keys go back. Nothing exported here takes or returns a passphrase.

import * as pgp from './pgp/index.js';
import { b64encode, b64decode, b64url, fromB64url, randomBytes, toText } from './pgp/util.js';

const IDLE_MS = 30 * 60 * 1000;
const unlocked = new Map(); // fingerprint -> { key, parts, timer }
const pending = new Map();  // result id -> Uint8Array (fetched by .NET as a stream)
let nextId = 1;

const enc = new TextEncoder();
const fail = (e) => { throw new Error(e?.message ?? String(e)); };

function touch(fingerprint) {
    const entry = unlocked.get(fingerprint);
    if (!entry) return;
    clearTimeout(entry.timer);
    entry.timer = setTimeout(() => unlocked.delete(fingerprint), IDLE_MS);
}

async function keysFrom(armoredList) {
    const out = [];
    for (const a of armoredList ?? []) {
        try { out.push(...await pgp.readKeys(a)); } catch { /* skip unreadable contact keys */ }
    }
    return out;
}

function signerFor(fingerprint) {
    const entry = unlocked.get(fingerprint);
    if (!entry) throw new Error('LOCKED: Unlock your key first.');
    touch(fingerprint);
    return { key: entry.key, parts: entry.parts };
}

const stash = (bytes) => { const id = nextId++; pending.set(id, bytes); return id; };

/** .NET pulls a stashed result as a stream (avoids the SignalR message size limit). */
export function take(id) {
    const bytes = pending.get(id);
    pending.delete(id);
    return bytes ?? new Uint8Array(0);
}

// ---------------------------------------------------------------- keys

export async function inspect(armored) {
    try { return (await pgp.readKeys(armored)).map(pgp.summarise); } catch (e) { fail(e); }
}

/** Unlock a stored (protected) secret key into page memory. Module-private: takes a passphrase. */
async function unlock(fingerprint, secretArmored, passphrase) {
    try {
        const [key] = await pgp.readKeys(secretArmored);
        const parts = await pgp.unlockKey(key, passphrase);
        unlocked.set(fingerprint, { key, parts, timer: null });
        touch(fingerprint);
        return pgp.summarise(key);
    } catch (e) { fail(e); }
}

export const isUnlocked = (fingerprint) => unlocked.has(fingerprint);
export function lock(fingerprint) { clearTimeout(unlocked.get(fingerprint)?.timer); unlocked.delete(fingerprint); }
export function lockAll() { for (const f of [...unlocked.keys()]) lock(f); }

// ---------------------------------------------------------------- secrets typed by the user

const valueOf = (el) => el?.value ?? '';
const clear = (...els) => { for (const el of els) if (el) el.value = ''; };

/** What .NET may know about a protection: never the passphrase itself. */
const shareable = ({ securityKey, credentialId, salt }) => ({ securityKey, credentialId, salt });

/** The protection chosen on the form: a new passphrase (typed twice) or a newly registered security key. */
async function newProtection(choice, label, passEl, confirmEl) {
    if (choice === 'SecurityKey') {
        const reg = await registerSecurityKey(label);
        return { passphrase: reg.passphrase, securityKey: true, credentialId: reg.credentialId, salt: reg.salt };
    }
    const passphrase = valueOf(passEl);
    if (passphrase.length < 8) throw new Error('Choose a passphrase of at least 8 characters.');
    if (passphrase !== valueOf(confirmEl)) throw new Error('The two passphrases don\'t match.');
    return { passphrase, securityKey: false, credentialId: null, salt: null };
}

/** The passphrase a stored key is protected with: typed into `passEl`, or derived by its security key. */
const currentPassphrase = (current, passEl) =>
    current.securityKey ? securityKeyPassphrase(current.credentialId, current.salt) : valueOf(passEl);

/** Unlock with the passphrase typed into `passEl`. */
export async function unlockFromInput(fingerprint, secretArmored, passEl) {
    const passphrase = valueOf(passEl);
    if (!passphrase) fail(new Error('Enter the key passphrase.'));
    const summary = await unlock(fingerprint, secretArmored, passphrase);
    clear(passEl);
    return summary;
}

/** Generate a key protected as chosen on the form, and keep it unlocked. Returns only the protected key. */
export async function generate({ userIds, kind, expiresInDays, protection }, passEl, confirmEl) {
    try {
        const prot = await newProtection(protection, userIds[0], passEl, confirmEl);
        const k = await pgp.generateKey({ userIds, kind, expiresInDays, passphrase: prot.passphrase });
        const summary = await unlock(k.fingerprint.toUpperCase(), k.privateKey, prot.passphrase);
        clear(passEl, confirmEl);
        return { summary, publicKey: k.publicKey, secretKey: k.privateKey, ...shareable(prot) };
    } catch (e) { fail(e); }
}

/**
 * Import the secret key pasted into `textEl`, unlocking it with the passphrase in `passEl` (which
 * proves it), then keep that protection or apply a new one. `existing` lists fingerprints already held.
 */
export async function importKey({ existing, protection }, textEl, passEl, newPassEl, confirmEl) {
    try {
        const text = valueOf(textEl).trim();
        if (!text) throw new Error('Paste a secret key or choose its file.');
        const [key] = await pgp.readKeys(text).catch(() => []);
        if (!key) throw new Error('No key found.');
        const info = pgp.summarise(key);
        if (!info.isSecret) throw new Error('That\'s a public key. Add it to a contact instead (Contacts → Edit → OpenPGP key).');
        if (!info.hasSecret) throw new Error(info.secretOnCard ? 'This key\'s secrets are on a smart card, so they can\'t be used in the browser.' : 'This export has no secret key material.');
        if ((existing ?? []).includes(info.fingerprint)) throw new Error('You already have this key.');

        const current = valueOf(passEl);
        if (protection === 'Keep' && !current) throw new Error('This key has no passphrase. Choose one, or protect it with a security key.');
        await unlock(info.fingerprint, text, current);

        let secretKey = text, prot = { securityKey: false, credentialId: null, salt: null };
        if (protection !== 'Keep') {
            prot = await newProtection(protection, info.primaryUserId ?? info.fingerprint, newPassEl, confirmEl);
            secretKey = await pgp.reprotect(key, current, prot.passphrase);
        }
        clear(textEl, passEl, newPassEl, confirmEl);
        return { summary: info, publicKey: pgp.armorPublic(key), secretKey, ...shareable(prot) };
    } catch (e) { fail(e); }
}

/** Re-protect a stored key. `current` is its stored protection ({ securityKey, credentialId, salt }). */
export async function changeProtection({ secretArmored, current, protection, label }, oldPassEl, newPassEl, confirmEl) {
    try {
        const [key] = await pgp.readKeys(secretArmored);
        const old = await currentPassphrase(current, oldPassEl);
        const prot = await newProtection(protection, label, newPassEl, confirmEl);
        const secretKey = await pgp.reprotect(key, old, prot.passphrase);
        clear(oldPassEl, newPassEl, confirmEl);
        return { secretKey, ...shareable(prot) };
    } catch (e) { fail(e); }
}

/** Save a copy of a stored key protected with a new backup passphrase, straight from the browser. */
export async function backup({ secretArmored, current, filename }, oldPassEl, newPassEl, confirmEl) {
    try {
        const prot = await newProtection('Passphrase', '', newPassEl, confirmEl);
        const [key] = await pgp.readKeys(secretArmored);
        const armored = await pgp.reprotect(key, await currentPassphrase(current, oldPassEl), prot.passphrase);
        saveFile(filename, enc.encode(armored), 'application/pgp-keys');
        clear(oldPassEl, newPassEl, confirmEl);
    } catch (e) { fail(e); }
}

/** Fill `textEl` from a key file chosen in `fileEl`, without the file passing through .NET. */
export function attachKeyFile(fileEl, textEl) {
    if (!fileEl || fileEl.dataset.pgpBound) return;
    fileEl.dataset.pgpBound = '1';
    fileEl.addEventListener('change', async () => {
        const file = fileEl.files?.[0];
        fileEl.value = '';
        if (!file || file.size > 1024 * 1024) return;
        const bytes = new Uint8Array(await file.arrayBuffer());
        // Binary keys are armored so the engine and storage see one format.
        textEl.value = bytes[0] === 0x2d ? toText(bytes) : pgp.armor(pgp.ARMOR.privateKey, bytes);
    });
}

export async function publicOf(armored) {
    try { const [key] = await pgp.readKeys(armored); return pgp.armorPublic(key); } catch (e) { fail(e); }
}

// ---------------------------------------------------------------- messages

/** Encrypt (and optionally sign) a MIME entity. Returns a stash id for the armored result. */
export async function encrypt(dataRef, recipientsArmored, signerFingerprint) {
    try {
        const data = new Uint8Array(await dataRef.arrayBuffer());
        const recipients = await keysFrom(recipientsArmored);
        const signer = signerFingerprint ? signerFor(signerFingerprint) : null;
        const armored = await pgp.encrypt({ data, recipients, signer, format: 'b', filename: '' });
        return stash(enc.encode(armored));
    } catch (e) { fail(e); }
}

export async function signDetached(dataRef, signerFingerprint) {
    try {
        const data = new Uint8Array(await dataRef.arrayBuffer());
        return await pgp.signDetached({ data, signer: signerFor(signerFingerprint) });
    } catch (e) { fail(e); }
}

/** Key IDs an encrypted message is addressed to. */
export function recipients(armored) {
    try { return pgp.recipientsOf(armored).map((k) => k.toUpperCase()); } catch (e) { fail(e); }
}

/** Decrypt with whichever unlocked keys fit. Returns metadata plus a stash id for the plaintext. */
export async function decrypt(armored, verificationArmored) {
    try {
        const decryptionKeys = [...unlocked.values()].map(({ key, parts }) => ({ key, parts }));
        if (!decryptionKeys.length) throw new Error('LOCKED: Unlock your key to read this message.');
        const out = await pgp.decrypt({ message: armored, decryptionKeys, verificationKeys: await keysFrom(verificationArmored) });
        for (const f of unlocked.keys()) touch(f);
        return { id: stash(out.data), filename: out.filename, format: out.format, signatures: out.signatures };
    } catch (e) { fail(e); }
}

export async function verifyDetached(dataRef, signature, keysArmored) {
    try {
        const data = new Uint8Array(await dataRef.arrayBuffer());
        return await pgp.verifyDetached({ data, signature, keys: await keysFrom(keysArmored) });
    } catch (e) { fail(e); }
}

export async function verifyCleartext(text, keysArmored) {
    try { return await pgp.verifyCleartext({ message: text, keys: await keysFrom(keysArmored) }); } catch (e) { fail(e); }
}

// ---------------------------------------------------------------- security keys (WebAuthn PRF)

/** PRF lets a security key derive a secret only it can reproduce; we use that as the key passphrase. */
export function securityKeySupported() {
    return !!(globalThis.isSecureContext && globalThis.PublicKeyCredential && navigator.credentials);
}

const prfToPassphrase = (bytes) => 'webauthn-prf:' + b64encode(new Uint8Array(bytes));

// Module-private: the result carries the derived passphrase.
async function registerSecurityKey(userName) {
    const salt = randomBytes(32);
    let credential;
    try {
        credential = await navigator.credentials.create({
            publicKey: {
                rp: { name: 'Nullify WebMail', id: location.hostname },
                user: { id: randomBytes(16), name: userName, displayName: userName },
                challenge: randomBytes(32),
                pubKeyCredParams: [{ type: 'public-key', alg: -8 }, { type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }],
                authenticatorSelection: { userVerification: 'preferred', residentKey: 'discouraged' },
                attestation: 'none',
                timeout: 120000,
                extensions: { prf: { eval: { first: salt } } },
            },
        });
    } catch (e) {
        throw new Error(e?.name === 'NotAllowedError' ? 'The security key request was cancelled or timed out.' : `Couldn't use the security key: ${e?.message ?? e}`);
    }
    const credentialId = b64url(new Uint8Array(credential.rawId));
    const prf = credential.getClientExtensionResults?.().prf;
    if (!prf?.enabled && !prf?.results?.first) {
        throw new Error('This security key or browser doesn\'t support the PRF extension needed to protect keys (a YubiKey 5 in a current Chrome, Edge, Safari or Firefox does).');
    }
    // Some browsers return the PRF output at registration; otherwise ask the key once more.
    const passphrase = prf.results?.first ? prfToPassphrase(prf.results.first) : await securityKeyPassphrase(credentialId, b64url(salt));
    return { credentialId, salt: b64url(salt), passphrase };
}

// Module-private: returns the derived passphrase.
async function securityKeyPassphrase(credentialId, salt) {
    let assertion;
    try {
        assertion = await navigator.credentials.get({
            publicKey: {
                challenge: randomBytes(32),
                rpId: location.hostname,
                allowCredentials: [{ type: 'public-key', id: fromB64url(credentialId) }],
                userVerification: 'preferred',
                timeout: 120000,
                extensions: { prf: { eval: { first: fromB64url(salt) } } },
            },
        });
    } catch (e) {
        throw new Error(e?.name === 'NotAllowedError' ? 'The security key request was cancelled or timed out.' : `Couldn't use the security key: ${e?.message ?? e}`);
    }
    const first = assertion.getClientExtensionResults?.().prf?.results?.first;
    if (!first) throw new Error('The security key didn\'t return its secret (PRF unsupported in this browser?).');
    return prfToPassphrase(first);
}

export async function unlockWithSecurityKey(fingerprint, secretArmored, credentialId, salt) {
    return unlock(fingerprint, secretArmored, await securityKeyPassphrase(credentialId, salt));
}

// ---------------------------------------------------------------- downloads

export async function download(filename, dataRef, mime) {
    saveFile(filename, await dataRef.arrayBuffer(), mime);
}

function saveFile(filename, bytes, mime) {
    const blob = new Blob([bytes], { type: mime || 'application/octet-stream' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = filename; a.rel = 'noopener';
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 30000);
}

export const textOf = (bytes) => toText(bytes);
export const fromBase64 = (s) => b64decode(s);
