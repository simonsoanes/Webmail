// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0
//
// passkey.js sends a PRF-derived key to the server, so it must never let the server choose what
// PRF evaluates: otherwise a hostile server could ask for a PGP security key's passphrase. These
// tests drive signIn and register with a stand-in WebAuthn and fetch, and check the PRF inputs
// are labelled hashes of the server's salts, and that only HKDF output leaves the page.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash, createHmac, hkdfSync, randomBytes } from 'node:crypto';

import * as passkey from '../../src/Nullify.WebMail/wwwroot/js/passkey.js';

const source = readFileSync(new URL('../../src/Nullify.WebMail/wwwroot/js/passkey.js', import.meta.url), 'utf8');
const b64url = (b) => Buffer.from(b).toString('base64url');
const label = (salt) => createHash('sha256').update('nullify-webmail/imap-wrap/v1').update(salt).digest();

test('passkey.js has nothing to do with the PGP code', () => {
  assert.doesNotMatch(source, /import\s/);
  assert.doesNotMatch(source, /pgp-bridge|\/pgp\//);
});

test('prfInput is SHA-256(label | salt), never the salt', async () => {
  const salt = randomBytes(32);
  const input = await passkey.prfInput(salt);
  assert.notDeepEqual(Buffer.from(input), salt);
  assert.deepEqual(Buffer.from(input), label(salt));
});

test('deriveKek is HKDF-SHA256 bound to the credential, not the PRF output', async () => {
  const prf = randomBytes(32), id = randomBytes(16);
  const kek = Buffer.from(await passkey.deriveKek(prf, id));
  assert.equal(kek.length, 32);
  assert.notDeepEqual(kek, prf);
  assert.deepEqual(kek, Buffer.from(hkdfSync('sha256', prf, Buffer.alloc(0), Buffer.concat([Buffer.from('imap-kek/v1'), id]), 32)));
});

// A browser for the module: WebAuthn evaluates PRF as HMAC(secret, input) and records the inputs; fetch records the bodies.
function fakeBrowser(responses) {
  const secret = randomBytes(32), rawId = randomBytes(16), seen = { prfInputs: [], bodies: [], prfOutputs: [] };
  const prf = (input) => { seen.prfInputs.push(Buffer.from(input)); const out = createHmac('sha256', secret).update(input).digest(); seen.prfOutputs.push(out); return out; };
  const evalPrf = (ext) => ({ first: prf(ext.first), ...(ext.second ? { second: prf(ext.second) } : {}) });
  const credential = (prfExt) => ({
    rawId: rawId.buffer.slice(rawId.byteOffset, rawId.byteOffset + rawId.length),
    response: { clientDataJSON: Buffer.from('{}'), authenticatorData: Buffer.alloc(37), signature: Buffer.alloc(8), attestationObject: Buffer.alloc(4), userHandle: null, getTransports: () => ['internal'] },
    getClientExtensionResults: () => ({ prf: prfExt })
  });
  Object.defineProperty(globalThis, 'navigator', { configurable: true, value: { credentials: {
    get: async ({ publicKey }) => {
      const ext = publicKey.extensions.prf;
      return credential({ results: evalPrf(ext.eval ?? ext.evalByCredential[b64url(rawId)]) });
    },
    create: async () => credential({ enabled: true }) // no output at creation: the module must ask again with get
  } } });
  globalThis.fetch = async (url, init) => {
    seen.bodies.push(init.body);
    const body = responses[url](rawId);
    return { ok: true, status: 200, json: async () => body };
  };
  return seen;
}

test('signIn evaluates only labelled salts and sends only derived keys', async () => {
  const s1 = randomBytes(32), s2 = randomBytes(32);
  const seen = fakeBrowser({
    '/api/auth/passkey/signin/options': (id) => ({ handle: 'h', challenge: b64url(randomBytes(32)), rpId: 'localhost',
      allow: [{ id: b64url(id), transports: null }], salts: { [b64url(id)]: { first: b64url(s1), second: b64url(s2) } } }),
    '/api/auth/passkey/signin': () => ({ success: true })
  });
  assert.deepEqual(await passkey.signIn('a@x.test'), { ok: true, error: null });
  assert.deepEqual(seen.prfInputs, [label(s1), label(s2)]);
  for (const out of seen.prfOutputs) for (const body of seen.bodies) assert.ok(!body.includes(b64url(out)), 'PRF output left the page');
  const sent = JSON.parse(seen.bodies[1]);
  assert.equal(Buffer.from(sent.kek, 'base64url').length, 32);
  assert.notEqual(sent.kek, sent.nextKek);
});

test('register evaluates only the labelled salt and sends only a derived key', async () => {
  const salt = randomBytes(32);
  const seen = fakeBrowser({
    '/api/auth/passkey/register/options': () => ({ handle: 'h', challenge: b64url(randomBytes(32)), rpId: 'localhost', rpName: 'x',
      userId: b64url(randomBytes(32)), userName: 'a@x.test', algorithms: [-7], exclude: [], salt: b64url(salt) }),
    '/api/auth/passkey/register': () => ({ success: true })
  });
  assert.deepEqual(await passkey.register(), { ok: true, error: null });
  assert.deepEqual(seen.prfInputs, [label(salt)]);
  assert.ok(!seen.bodies[1].includes(b64url(seen.prfOutputs[0])));
});

test('approveQr sends the assertion with the phone token and returns only the revoke token and login', async () => {
  const s1 = randomBytes(32), s2 = randomBytes(32);
  const seen = fakeBrowser({
    '/api/auth/passkey/signin/options': (id) => ({ handle: 'h', challenge: b64url(randomBytes(32)), rpId: 'localhost',
      allow: [{ id: b64url(id), transports: null }], salts: { [b64url(id)]: { first: b64url(s1), second: b64url(s2) } } }),
    '/api/auth/qr/abc/approve-passkey': () => ({ success: true, revokeToken: 'rt', login: 'a@x.test', expiresUtc: 'x' })
  });
  assert.deepEqual(await passkey.approveQr('abc', 'pt', ''), { ok: true, error: null, revokeToken: 'rt', login: 'a@x.test' });
  assert.deepEqual(seen.prfInputs, [label(s1), label(s2)]);
  const sent = JSON.parse(seen.bodies[1]);
  assert.equal(sent.phoneToken, 'pt');
  assert.equal(Buffer.from(sent.assertion.kek, 'base64url').length, 32);
  for (const out of seen.prfOutputs) assert.ok(!seen.bodies[1].includes(b64url(out)), 'PRF output left the page');
});

test('a server error comes back as a message, not an exception', async () => {
  globalThis.fetch = async () => ({ ok: false, status: 400, json: async () => ({ success: false, error: 'Nope.' }) });
  assert.deepEqual(await passkey.signIn(''), { ok: false, error: 'Nope.' });
});
