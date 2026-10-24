// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0
//
// PGP passphrases and unprotected secret keys must never reach the server. With Blazor Server,
// anything pgp-bridge.js hands to .NET does, so these tests drive the bridge with stand-in input
// elements and check that it validates, uses and clears them itself and only returns protected keys.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import * as bridge from '../../src/Nullify.WebMail/wwwroot/js/pgp-bridge.js';
import * as pgp from '../../src/Nullify.WebMail/wwwroot/js/pgp/index.js';
const field = (value = '') => ({ value });
const PASS = 'correct horse battery', PASS2 = 'another long passphrase';
const leaks = (obj, ...secrets) => secrets.some((s) => JSON.stringify(obj).includes(s));

test('only shareable members are exported', () => {
  for (const name of ['unlock', 'reprotect', 'registerSecurityKey', 'securityKeyPassphrase']) assert.equal(bridge[name], undefined, name);
});

let gen;
test('generate: validates in the browser, returns a protected key, clears fields', async () => {
  await assert.rejects(bridge.generate({ userIds: ['A <a@x.test>'], kind: 'curve25519', expiresInDays: 0, protection: 'Passphrase' }, field('short'), field('short')), /at least 8/);
  await assert.rejects(bridge.generate({ userIds: ['A <a@x.test>'], kind: 'curve25519', expiresInDays: 0, protection: 'Passphrase' }, field(PASS), field('different!!')), /don't match/);
  const p = field(PASS), c = field(PASS);
  gen = await bridge.generate({ userIds: ['A <a@x.test>'], kind: 'curve25519', expiresInDays: 0, protection: 'Passphrase' }, p, c);
  assert.equal(p.value, ''); assert.equal(c.value, '');
  assert.ok(!leaks(gen, PASS));
  assert.equal(gen.securityKey, false);
  assert.match(gen.secretKey, /BEGIN PGP PRIVATE KEY BLOCK/);
  assert.ok(bridge.isUnlocked(gen.summary.fingerprint), 'stays unlocked in the browser');
  // The returned secret key really is protected: the engine refuses it without the passphrase.
  const [k] = await pgp.readKeys(gen.secretKey);
  await assert.rejects(pgp.unlockKey(k, 'wrong passphrase'));
});

test('unlockFromInput: wrong passphrase keeps the field, right one clears it', async () => {
  bridge.lockAll();
  const bad = field('wrong passphrase');
  await assert.rejects(bridge.unlockFromInput(gen.summary.fingerprint, gen.secretKey, bad));
  assert.equal(bad.value, 'wrong passphrase');
  const good = field(PASS);
  const info = await bridge.unlockFromInput(gen.summary.fingerprint, gen.secretKey, good);
  assert.equal(good.value, ''); assert.equal(info.fingerprint, gen.summary.fingerprint);
  assert.ok(bridge.isUnlocked(gen.summary.fingerprint));
});

test('changeProtection: new passphrase, never returned', async () => {
  const old = field(PASS), n = field(PASS2), c = field(PASS2);
  const r = await bridge.changeProtection({ secretArmored: gen.secretKey, current: { securityKey: false }, protection: 'Passphrase', label: 'A' }, old, n, c);
  assert.ok(!leaks(r, PASS, PASS2)); assert.equal(old.value + n.value + c.value, '');
  const [k] = await pgp.readKeys(r.secretKey);
  await pgp.unlockKey(k, PASS2);
  await assert.rejects(pgp.unlockKey((await pgp.readKeys(r.secretKey))[0], PASS));
});

test('importKey: unprotected key must be protected before it leaves the browser', async () => {
  const fresh = await pgp.generateKey({ userIds: ['B <b@x.test>'], kind: 'curve25519', passphrase: PASS });
  const [k] = await pgp.readKeys(fresh.privateKey);
  const plainArmored = await pgp.reprotect(k, PASS, ''); // a key with no passphrase, as gpg might export
  await assert.rejects(bridge.importKey({ existing: [], protection: 'Keep' }, field(plainArmored), field(''), null, null), /no passphrase/);
  const text = field(plainArmored), cur = field(''), n = field(PASS2), c = field(PASS2);
  const r = await bridge.importKey({ existing: [], protection: 'Passphrase' }, text, cur, n, c);
  assert.ok(!leaks(r, PASS2)); assert.notEqual(r.secretKey, plainArmored);
  assert.equal(text.value, ''); assert.equal(n.value, '');
  await assert.rejects(pgp.unlockKey((await pgp.readKeys(r.secretKey))[0], ''), 'stored copy needs the passphrase');
  await assert.rejects(bridge.importKey({ existing: [r.summary.fingerprint], protection: 'Keep' }, field(fresh.privateKey), field(PASS), null, null), /already have/);
  await assert.rejects(bridge.importKey({ existing: [], protection: 'Keep' }, field(fresh.publicKey), field(''), null, null), /public key/);
});

// The bridge's 30-minute auto-lock timers would keep Node alive.
test.after(() => bridge.lockAll());
