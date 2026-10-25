// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0
//
// Passkey sign-in: WebAuthn with the PRF extension, which lets a passkey derive a secret only it
// can reproduce. This page turns that secret into a key that unlocks the mail login the server
// keeps wrapped for the passkey (see PasskeyService), and sends the key straight to the server by
// fetch, never through Blazor. What goes back to .NET is only { ok, error } (plus, when a phone
// signs in a computer, the revoke token and login the server returned).
//
// Kept apart from the PGP code on purpose: a security key's PRF output is a PGP passphrase, and
// that must never reach the server. So nothing here imports the PGP module, the server's salts
// are always hashed with a label before PRF sees them (the server would need a SHA-256 preimage
// to get the PGP output), and only an HKDF-derived key leaves this page, never PRF output.

const enc = new TextEncoder();
const WRAP_LABEL = enc.encode('nullify-webmail/imap-wrap/v1');
const KEK_INFO = enc.encode('imap-kek/v1');
const REMEMBERED = 'nullify.passkeys';
const TIMEOUT = 120000;

const NO_PRF = 'This passkey or browser can\'t unlock your mail password, because it doesn\'t support the WebAuthn PRF extension. Current Chrome, Edge and Safari support it with most passkey managers and security keys.';
const NOT_USED = 'No passkey was used. If you haven\'t set one up for this address yet, sign in with your password and add one in Settings.';

export const b64url = (bytes) => btoa(String.fromCharCode(...new Uint8Array(bytes)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

export const fromB64url = (s) => {
    const bin = atob(s.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - s.length % 4) % 4));
    return Uint8Array.from(bin, (c) => c.charCodeAt(0));
};

const concat = (...parts) => {
    const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
    let at = 0;
    for (const p of parts) { out.set(p, at); at += p.length; }
    return out;
};

/** What PRF evaluates for a server salt: SHA-256(label | salt), never the salt itself. */
export async function prfInput(serverSalt) {
    return new Uint8Array(await crypto.subtle.digest('SHA-256', concat(WRAP_LABEL, new Uint8Array(serverSalt))));
}

/** The key that leaves the browser: HKDF-SHA256 of the PRF output, bound to the credential. */
export async function deriveKek(prfOutput, credentialId) {
    const key = await crypto.subtle.importKey('raw', new Uint8Array(prfOutput), 'HKDF', false, ['deriveBits']);
    return new Uint8Array(await crypto.subtle.deriveBits(
        { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: concat(KEK_INFO, new Uint8Array(credentialId)) },
        key, 256));
}

export const supported = () => typeof PublicKeyCredential !== 'undefined' && !!navigator.credentials;

async function post(url, body) {
    const resp = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body ?? {}),
        credentials: 'same-origin'
    });
    let data = null;
    try { data = await resp.json(); } catch { }
    if (!resp.ok || data?.success === false) {
        throw new Error(data?.error ?? (resp.status === 429
            ? 'Too many attempts. Wait a minute and try again.'
            : `The server refused the request (HTTP ${resp.status}).`));
    }
    return data;
}

// Credential ids (not secret) of passkeys used in this browser, so it can offer them without the address being typed.
const remembered = () => {
    try {
        const v = JSON.parse(localStorage.getItem(REMEMBERED) || '[]');
        return Array.isArray(v) ? v.filter((x) => typeof x === 'string') : [];
    } catch { return []; }
};
const remember = (id) => {
    try { localStorage.setItem(REMEMBERED, JSON.stringify([id, ...remembered().filter((x) => x !== id)].slice(0, 10))); } catch { }
};

const descriptor = (c) => ({ type: 'public-key', id: fromB64url(c.id), ...(c.transports ? { transports: c.transports } : {}) });

async function outcome(run, cancelled) {
    try {
        return { ok: true, error: null, ...(await run()) };
    } catch (e) {
        if (e?.name === 'NotAllowedError' || e?.name === 'AbortError') return { ok: false, error: cancelled };
        if (e?.name === 'InvalidStateError') return { ok: false, error: 'That passkey is already set up for your account.' };
        return { ok: false, error: e?.message ?? String(e) };
    }
}

/** Run a get() ceremony against server options and build the request for the server. */
async function assertWith(options) {
    const evalByCredential = {};
    for (const [id, s] of Object.entries(options.salts)) {
        evalByCredential[id] = { first: await prfInput(fromB64url(s.first)) };
        if (s.second) evalByCredential[id].second = await prfInput(fromB64url(s.second));
    }

    const credential = await navigator.credentials.get({
        publicKey: {
            challenge: fromB64url(options.challenge),
            rpId: options.rpId,
            allowCredentials: options.allow.map(descriptor),
            userVerification: 'required',
            timeout: TIMEOUT,
            extensions: { prf: { evalByCredential } }
        }
    });

    const id = b64url(credential.rawId);
    const results = credential.getClientExtensionResults?.().prf?.results;
    if (!results?.first || (options.salts[id]?.second && !results.second)) throw new Error(NO_PRF);

    const rawId = new Uint8Array(credential.rawId);
    const r = credential.response;
    return {
        handle: options.handle,
        credentialId: id,
        clientDataJson: b64url(r.clientDataJSON),
        authenticatorData: b64url(r.authenticatorData),
        signature: b64url(r.signature),
        userHandle: r.userHandle ? b64url(r.userHandle) : null,
        kek: b64url(await deriveKek(results.first, rawId)),
        nextKek: results.second ? b64url(await deriveKek(results.second, rawId)) : null
    };
}

/** Sign in with a passkey for the typed address, or one used in this browser before. */
export const signIn = (username) => outcome(async () => {
    const options = await post('/api/auth/passkey/signin/options', { username: username || null, credentialIds: remembered() });
    const request = await assertWith(options);
    await post('/api/auth/passkey/signin', request);
    remember(request.credentialId);
}, NOT_USED);

/**
 * On the phone page of the QR flow: approve the computer's sign-in with a passkey on this phone,
 * instead of typing the password. The key that unlocks the password stays on the phone and the server.
 */
export const approveQr = (id, phoneToken, username) => outcome(async () => {
    const options = await post('/api/auth/passkey/signin/options', { username: username || null, credentialIds: remembered() });
    const assertion = await assertWith(options);
    const result = await post(`/api/auth/qr/${encodeURIComponent(id)}/approve-passkey`, { phoneToken, assertion });
    remember(assertion.credentialId);
    return { revokeToken: result.revokeToken, login: result.login };
}, NOT_USED);

/** Add a passkey for the signed-in account, which keeps this session's mail login wrapped under it. */
export const register = () => outcome(async () => {
    const o = await post('/api/auth/passkey/register/options');
    const input = await prfInput(fromB64url(o.salt));

    const credential = await navigator.credentials.create({
        publicKey: {
            challenge: fromB64url(o.challenge),
            rp: { id: o.rpId, name: o.rpName },
            user: { id: fromB64url(o.userId), name: o.userName, displayName: o.userName },
            pubKeyCredParams: o.algorithms.map((alg) => ({ type: 'public-key', alg })),
            excludeCredentials: o.exclude.map(descriptor),
            authenticatorSelection: { residentKey: 'required', requireResidentKey: true, userVerification: 'required' },
            attestation: 'none',
            timeout: TIMEOUT,
            extensions: { prf: { eval: { first: input } } }
        }
    });

    const prf = credential.getClientExtensionResults?.().prf;
    if (prf?.enabled === false) throw new Error(NO_PRF + ' You can delete the passkey this just made from your passkey manager.');
    // Some authenticators only give the PRF output when the passkey is used, not when it's made: ask once more.
    let first = prf?.results?.first;
    if (!first) {
        const again = await navigator.credentials.get({
            publicKey: {
                challenge: crypto.getRandomValues(new Uint8Array(32)),
                rpId: o.rpId,
                allowCredentials: [{ type: 'public-key', id: credential.rawId }],
                userVerification: 'required',
                timeout: TIMEOUT,
                extensions: { prf: { eval: { first: input } } }
            }
        });
        first = again.getClientExtensionResults?.().prf?.results?.first;
        if (!first) throw new Error(NO_PRF + ' You can delete the passkey this just made from your passkey manager.');
    }

    const r = credential.response;
    await post('/api/auth/passkey/register', {
        handle: o.handle,
        clientDataJson: b64url(r.clientDataJSON),
        attestationObject: b64url(r.attestationObject),
        transports: r.getTransports?.() ?? [],
        kek: b64url(await deriveKek(first, new Uint8Array(credential.rawId)))
    });
    remember(b64url(credential.rawId));
}, 'The passkey wasn\'t created (cancelled or timed out).');

/** After the mail password changed: wrap this session's login under the passkey again. */
export const update = (passkeyId) => outcome(async () => {
    const options = await post(`/api/auth/passkey/${encodeURIComponent(passkeyId)}/update/options`);
    await post('/api/auth/passkey/update', await assertWith(options));
}, 'The passkey wasn\'t used (cancelled or timed out).');
