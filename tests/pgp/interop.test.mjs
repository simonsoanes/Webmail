// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0
//
// Interoperability tests for the WebMail OpenPGP engine (src/Nullify.WebMail/wwwroot/js/pgp)
// against GnuPG and OpenPGP.js. Run:  cd tests/pgp && npm install && npm test
// GnuPG 2.2+ must be installed; set GPG to its path if it isn't on PATH.

import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, existsSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import * as openpgp from 'openpgp';

import * as pgp from '../../src/Nullify.WebMail/wwwroot/js/pgp/index.js';
import { expandKey, encryptBlock, expandDecryptKey, decryptBlock, ocbEncrypt, ocbDecrypt, cfbDecrypt } from '../../src/Nullify.WebMail/wwwroot/js/pgp/aes.js';
import * as cast5 from '../../src/Nullify.WebMail/wwwroot/js/pgp/cast5.js';
import { readPackets, parseSignature, TAG } from '../../src/Nullify.WebMail/wwwroot/js/pgp/packets.js';
import { signedData, keyParts } from '../../src/Nullify.WebMail/wwwroot/js/pgp/keys.js';
import { digest, rsaSign, ed25519Sign } from '../../src/Nullify.WebMail/wwwroot/js/pgp/algorithms.js';
import { encryptWithSessionKey } from '../../src/Nullify.WebMail/wwwroot/js/pgp/message.js';
import { fromHex, toHex, toBinary, crc24, armor, dearmor } from '../../src/Nullify.WebMail/wwwroot/js/pgp/util.js';

const enc = new TextEncoder();
const dec = new TextDecoder();
const PASS = 'correct horse battery staple';
const TEXT = 'Grüße aus Nullify ✓\nSecond line with trailing spaces   \n\nend';

// ---------------------------------------------------------------- GnuPG harness

const GPG = process.env.GPG ?? ['C:\\Program Files\\GnuPG\\bin\\gpg.exe', 'C:\\Program Files (x86)\\GnuPG\\bin\\gpg.exe']
    .find(existsSync) ?? 'gpg';
let home;

// MSYS builds (e.g. the GnuPG bundled with Git for Windows) want /c/... paths.
const msys = /[\\/]usr[\\/]bin[\\/]gpg/i.test(GPG);
const gpgPath = (p) => (msys ? p.replace(/^([A-Za-z]):\\/, (_, d) => `/${d.toLowerCase()}/`).replace(/\\/g, '/') : p);

function gpg(args, input) {
    args = args.map((a) => (/^[A-Za-z]:\\/.test(a) ? gpgPath(a) : a));
    const r = spawnSync(GPG, ['--homedir', gpgPath(home), '--batch', '--yes', '--no-tty', '--pinentry-mode', 'loopback',
        '--passphrase', PASS, '--trust-model', 'always', '--status-fd', '2', ...args], { input, maxBuffer: 64 << 20 });
    const status = r.stderr.toString();
    if (r.status !== 0 && !args.includes('--verify')) throw new Error(`gpg ${args.join(' ')} failed:\n${status}`);
    return { out: r.stdout, status, code: r.status };
}

function gpgFingerprint(uid) {
    const colons = gpg(['--with-colons', '--list-keys', uid]).out.toString();
    return /^fpr:+([0-9A-F]+):/m.exec(colons)[1];
}

/** gpg key spec -> [primary algo, subkey algo]. */
const GPG_KINDS = {
    'ed25519/cv25519': ['ed25519', 'cv25519'],
    'rsa3072': ['rsa3072', 'rsa3072'],
    'nistp256': ['nistp256', 'nistp256'],
    'nistp384': ['nistp384', 'nistp384'],
    'nistp521': ['nistp521', 'nistp521'],
    'dsa2048/elg2048': ['dsa2048', 'elg2048'],
};

before(() => {
    home = mkdtempSync(join(tmpdir(), 'nullify-gpg-'));
    const v = spawnSync(GPG, ['--version']).stdout.toString().split('\n')[0];
    console.log(`# Using ${v} (${GPG})`);
});

after(() => {
    spawnSync('gpgconf', ['--homedir', home, '--kill', 'gpg-agent']);
    try { rmSync(home, { recursive: true, force: true }); } catch { /* agent may hold files briefly */ }
});

// ---------------------------------------------------------------- primitives

describe('primitives', () => {
    test('AES matches FIPS-197 appendix C vectors', () => {
        const pt = fromHex('00112233445566778899aabbccddeeff');
        for (const [key, ct] of [
            ['000102030405060708090a0b0c0d0e0f', '69c4e0d86a7b0430d8cdb78070b4c55a'],
            ['000102030405060708090a0b0c0d0e0f1011121314151617', 'dda97ca4864cdfe06eaf70a0ec0d7191'],
            ['000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f', '8ea2b7ca516745bfeafc49904b496089'],
        ]) {
            const out = new Uint8Array(16);
            encryptBlock(expandKey(fromHex(key)), pt, 0, out, 0);
            assert.equal(toHex(out), ct);
        }
    });

    test('AES agrees with WebCrypto on random keys and blocks', async () => {
        for (const size of [16, 24, 32]) {
            for (let i = 0; i < 25; i++) {
                const key = crypto.getRandomValues(new Uint8Array(size));
                const block = crypto.getRandomValues(new Uint8Array(16));
                const out = new Uint8Array(16);
                encryptBlock(expandKey(key), block, 0, out, 0);
                const ck = await crypto.subtle.importKey('raw', key, 'AES-CBC', false, ['encrypt']);
                const ref = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-CBC', iv: new Uint8Array(16) }, ck, block)).subarray(0, 16);
                assert.equal(toHex(out), toHex(ref));
            }
        }
    });

    test('AES decryption inverts encryption for every key size', () => {
        for (const size of [16, 24, 32]) {
            const key = crypto.getRandomValues(new Uint8Array(size));
            const block = crypto.getRandomValues(new Uint8Array(16));
            const ct = new Uint8Array(16), back = new Uint8Array(16);
            encryptBlock(expandKey(key), block, 0, ct, 0);
            decryptBlock(expandDecryptKey(key), ct, 0, back, 0);
            assert.equal(toHex(back), toHex(block));
        }
    });

    test('OCB matches RFC 7253 appendix A vectors and rejects forgeries', () => {
        const K = fromHex('000102030405060708090A0B0C0D0E0F');
        const vectors = [
            ['BBAA99887766554433221100', '', '', '785407BFFFC8AD9EDCC5520AC9111EE6'],
            ['BBAA99887766554433221101', '0001020304050607', '0001020304050607', '6820B3657B6F615A5725BDA0D3B4EB3A257C9AF1F8F03009'],
            ['BBAA99887766554433221102', '0001020304050607', '', '81017F8203F081277152FADE694A0A00'],
            ['BBAA99887766554433221103', '', '0001020304050607', '45DD69F8F5AAE72414054CD1F35D82760B2CD00D2F99BFA9'],
        ];
        for (const [n, a, p, c] of vectors) {
            const out = ocbEncrypt(K, fromHex(n), fromHex(p), fromHex(a));
            assert.equal(toHex(out), c.toLowerCase(), `nonce ${n}`);
            assert.equal(toHex(ocbDecrypt(K, fromHex(n), out, fromHex(a))), p.toLowerCase());
            const forged = out.slice(); forged[0] ^= 1;
            assert.equal(ocbDecrypt(K, fromHex(n), forged, fromHex(a)), null);
        }
        // Longer inputs (multiple full blocks plus a partial one) round-trip.
        const long = crypto.getRandomValues(new Uint8Array(1000)), ad = crypto.getRandomValues(new Uint8Array(37));
        const nonce = crypto.getRandomValues(new Uint8Array(15));
        assert.deepEqual(ocbDecrypt(K, nonce, ocbEncrypt(K, nonce, long, ad), ad), long);
    });

    test('CAST5 matches the RFC 2144 vector and maintenance test', () => {
        const out = new Uint8Array(8);
        cast5.encryptBlock(cast5.expandKey(fromHex('0123456712345678234567893456789a')), fromHex('0123456789abcdef'), 0, out, 0);
        assert.equal(toHex(out), '238b4fe5847e44b2');
        const a = fromHex('0123456712345678234567893456789a'), b = a.slice();
        for (let i = 0; i < 1000000; i++) {
            const kb = cast5.expandKey(b);
            cast5.encryptBlock(kb, a, 0, a, 0); cast5.encryptBlock(kb, a, 8, a, 8);
            const ka = cast5.expandKey(a);
            cast5.encryptBlock(ka, b, 0, b, 0); cast5.encryptBlock(ka, b, 8, b, 8);
        }
        assert.equal(toHex(a), 'eea9d0a249fd3ba6b3436fb89d6dca92');
        assert.equal(toHex(b), 'b2c95eb00c31ad7180ac05b8e83d696e');
    });

    test('armor round-trips and CRC-24 matches the RFC check value', () => {
        assert.equal(crc24(enc.encode('123456789')), 0x21cf02);
        const data = crypto.getRandomValues(new Uint8Array(1000));
        assert.deepEqual(dearmor(armor('PGP MESSAGE', data)).data, data);
        const broken = armor('PGP MESSAGE', data).replace(/\n[A-Za-z0-9+/]{10}/, (m) => m.slice(0, 5) + (m[5] === 'A' ? 'B' : 'A') + m.slice(6));
        assert.throws(() => dearmor(broken));
    });
});

// ---------------------------------------------------------------- GnuPG keys

for (const [label, [primaryAlgo, subAlgo]] of Object.entries(GPG_KINDS)) {
    describe(`GnuPG ${label} key`, () => {
        const uid = `GnuPG ${label} <gpg-${label.replace(/\W/g, '')}@example.org>`;
        let fpr, pub, sec, parts;

        before(async () => {
            gpg(['--quick-gen-key', uid, primaryAlgo, 'cert,sign', 'never']);
            fpr = gpgFingerprint(uid);
            gpg(['--quick-add-key', fpr, subAlgo, 'encr', 'never']);
            [pub] = await pgp.readKeys(gpg(['--armor', '--export', fpr]).out.toString());
            [sec] = await pgp.readKeys(gpg(['--armor', '--export-secret-keys', fpr]).out.toString());
        });

        test('reads and validates the public key', () => {
            const s = pgp.summarise(pub);
            assert.equal(s.fingerprint, fpr);
            assert.ok(s.valid, 'self-signatures verify');
            assert.ok(s.canEncrypt);
            assert.deepEqual(s.userIds, [uid]);
        });

        test('unlocks the passphrase-protected secret key', async () => {
            parts = await pgp.unlockKey(sec, PASS);
            assert.equal(Object.keys(parts).length, 2);
            await assert.rejects(() => pgp.unlockKey(sec, 'wrong'), /Wrong passphrase/);
        });

        test('decrypts and verifies a message GnuPG encrypted and signed', async () => {
            const message = gpg(['--armor', '--encrypt', '--sign', '--recipient', fpr, '--local-user', fpr], enc.encode(TEXT)).out.toString();
            const out = await pgp.decrypt({ message, decryptionKeys: [{ key: sec, parts }], verificationKeys: [pub] });
            assert.equal(dec.decode(out.data), TEXT);
            assert.equal(out.signatures[0]?.status, 'good');
        });

        test('GnuPG decrypts and verifies our encrypted, signed message', async () => {
            if (primaryAlgo.startsWith('dsa')) {
                // DSA is deprecated (RFC 9580): verify only. Our unsigned message must still decrypt.
                await assert.rejects(() => pgp.encrypt({ data: enc.encode(TEXT), recipients: [pub], signer: { key: sec, parts } }), /DSA/);
                const plain = await pgp.encrypt({ data: enc.encode(TEXT), recipients: [pub] });
                assert.equal(gpg(['--decrypt'], enc.encode(plain)).out.toString(), TEXT);
                return;
            }
            const message = await pgp.encrypt({ data: enc.encode(TEXT), recipients: [pub], signer: { key: sec, parts } });
            const r = gpg(['--decrypt'], enc.encode(message));
            assert.equal(r.out.toString(), TEXT);
            assert.match(r.status, /\[GNUPG:\] GOODSIG/);
            assert.match(r.status, /\[GNUPG:\] DECRYPTION_OKAY/);
            assert.doesNotMatch(r.status, /DECRYPTION_FAILED|BADSIG|NO_SECKEY/);
        });

        test('decrypts GnuPG\'s OCB format, checking every chunk tag and the final length tag', async (t) => {
            // GnuPG 2.5 (and some 2.4 builds) use their OCB packet for their own keys; the
            // authentication tags are the cross-check.
            const message = gpg(['--encrypt', '--recipient', fpr], enc.encode(TEXT)).out;
            if (!readPackets(message).some((p) => p.tag === TAG.OCB)) return t.skip('this GnuPG build writes SEIPD v1 here');
            const out = await pgp.decrypt({ message, decryptionKeys: [{ key: sec, parts }] });
            assert.equal(dec.decode(out.data), TEXT);
            await assert.rejects(() => pgp.decrypt({ message: message.subarray(0, message.length - 8), decryptionKeys: [{ key: sec, parts }] }));
        });

        test('verifies a GnuPG detached signature and GnuPG verifies ours', async () => {
            const data = enc.encode(TEXT);
            const theirs = gpg(['--armor', '--detach-sign', '--local-user', fpr], data).out.toString();
            assert.equal((await pgp.verifyDetached({ data, signature: theirs, keys: [pub] }))[0].status, 'good');
            if (primaryAlgo.startsWith('dsa')) return;

            const ours = await pgp.signDetached({ data, signer: { key: sec, parts } });
            const sigFile = join(home, `sig-${Date.now()}.asc`);
            (await import('node:fs')).writeFileSync(sigFile, ours);
            const r = gpg(['--verify', sigFile, '-'], data);
            assert.match(r.status, /\[GNUPG:\] GOODSIG/);
        });

        test('rejects a signature over altered data', async () => {
            const data = enc.encode(TEXT);
            const theirs = gpg(['--detach-sign', '--local-user', fpr], data).out;
            const altered = enc.encode(TEXT + '!');
            assert.equal((await pgp.verifyDetached({ data: altered, signature: theirs, keys: [pub] }))[0].status, 'bad');
        });

        test('verifies a GnuPG cleartext signature', async () => {
            const signed = gpg(['--clearsign', '--local-user', fpr], enc.encode(TEXT)).out.toString();
            const out = await pgp.verifyCleartext({ message: signed, keys: [pub] });
            assert.equal(out.signatures[0].status, 'good');
            assert.equal(out.text.trimEnd(), TEXT.trimEnd());
        });

        if (primaryAlgo.startsWith('rsa') || primaryAlgo === 'ed25519') {
            test('produces the identical signature for GnuPG\'s signed data (deterministic scheme)', async () => {
                const data = enc.encode(TEXT);
                const theirs = parseSignature(readPackets(gpg(['--detach-sign', '--local-user', fpr], data).out)[0].body);
                const part = parts[pub.primary.fingerprint];
                const hash = await digest(theirs.hashAlgo, signedData(theirs, data));
                const mpis = primaryAlgo === 'ed25519'
                    ? await ed25519Sign(part.pub.point, part.sec.d, hash)
                    : [rsaSign({ ...part.pub, ...part.sec }, theirs.hashAlgo, hash)];
                const strip = (b) => toHex(b).replace(/^(00)+/, '');
                assert.deepEqual(mpis.map(strip), theirs.mpis.map(strip));
            });
        }
    });
}

describe('GnuPG 1.4 key protected with CAST5', () => {
    // Modern GnuPG always exports with AES, so this fixture comes from gpg 1.4.23
    // (`--s2k-cipher-algo CAST5 --gen-key`, passphrase PASS).
    const armored = readFileSync(new URL('./fixtures/gnupg1-cast5-secret.asc', import.meta.url), 'utf8');
    let fpr, sec;

    before(async () => {
        [sec] = await pgp.readKeys(armored);
        fpr = pgp.summarise(sec).fingerprint;
        gpg(['--import'], enc.encode(armored));
    });

    test('the fixture really is CAST5-protected, and OpenPGP.js opens it', async () => {
        for (const part of [sec.primary, ...sec.subkeys]) assert.equal(part.k.secretArea[1], 3);
        const theirs = await openpgp.decryptKey({ privateKey: await openpgp.readPrivateKey({ armoredKey: armored }), passphrase: PASS });
        assert.ok(theirs.isDecrypted());
    });

    test('unlocks it, rejects a wrong passphrase, and decrypts what GnuPG encrypts to it', async () => {
        const parts = await pgp.unlockKey(sec, PASS);
        assert.equal(Object.keys(parts).length, 2);
        await assert.rejects(() => pgp.unlockKey(sec, 'wrong'), /Wrong passphrase/);
        const message = gpg(['--armor', '--encrypt', '--recipient', fpr], enc.encode(TEXT)).out.toString();
        assert.equal(dec.decode((await pgp.decrypt({ message, decryptionKeys: [{ key: sec, parts }] })).data), TEXT);
    });

    test('re-protecting under the same passphrase moves it to AES-256', async () => {
        const [again] = await pgp.readKeys(await pgp.reprotect(sec, PASS, PASS));
        for (const part of [again.primary, ...again.subkeys]) assert.equal(part.k.secretArea[1], 9);
        assert.equal(Object.keys(await pgp.unlockKey(again, PASS)).length, 2);
    });
});

// ---------------------------------------------------------------- our keys in GnuPG

for (const kind of ['curve25519', 'rsa3072', 'p256', 'p384', 'p521']) {
    describe(`our ${kind} key in GnuPG`, () => {
        const uid = `Nullify ${kind} <ours-${kind}@example.org>`;
        let generated, pub, sec, parts;

        before(async () => {
            generated = await pgp.generateKey({ userIds: [uid], kind, passphrase: PASS });
            [pub] = await pgp.readKeys(generated.publicKey);
            [sec] = await pgp.readKeys(generated.privateKey);
            parts = await pgp.unlockKey(sec, PASS);
        });

        test('GnuPG imports it and accepts every self-signature', () => {
            gpg(['--import'], enc.encode(generated.privateKey));
            const checked = gpg(['--with-colons', '--check-signatures', generated.fingerprint]).out.toString();
            const sigs = checked.split('\n').filter((l) => l.startsWith('sig:'));
            assert.ok(sigs.length >= 2, 'UID certification + subkey binding');
            for (const line of sigs) assert.equal(line.split(':')[1], '!', `GnuPG verified: ${line}`);
            const listing = gpg(['--with-colons', '--list-secret-keys', generated.fingerprint]).out.toString();
            assert.match(listing, /^sec:/m);
            assert.match(listing, /^ssb:/m);
        });

        test('GnuPG encrypts and signs to it, we decrypt and verify', async () => {
            const message = gpg(['--armor', '--encrypt', '--sign', '--recipient', generated.fingerprint, '--local-user', generated.fingerprint], enc.encode(TEXT)).out.toString();
            const out = await pgp.decrypt({ message, decryptionKeys: [{ key: sec, parts }], verificationKeys: [pub] });
            assert.equal(dec.decode(out.data), TEXT);
            assert.equal(out.signatures[0]?.status, 'good');
        });

        test('re-encrypting with GnuPG\'s session key and prefix reproduces its ciphertext byte-for-byte', async () => {
            // Our keys don't advertise OCB, so GnuPG writes the classic SEIPD v1 packet here.
            const message = gpg(['--encrypt', '--recipient', generated.fingerprint], enc.encode(TEXT)).out;
            const seipd = readPackets(message).find((p) => p.tag === TAG.SEIPD)?.body;
            assert.ok(seipd, 'GnuPG chose SEIPD v1 for our key');
            const out = await pgp.decrypt({ message, decryptionKeys: [{ key: sec, parts }] });
            const plain = cfbDecrypt(out.sessionKey.key, new Uint8Array(16), seipd.subarray(1));
            const ours = await encryptWithSessionKey(out.sessionKey.key, plain.subarray(18, plain.length - 22), plain.subarray(0, 16));
            assert.equal(toHex(readPackets(ours)[0].body), toHex(seipd));
        });

        test('GnuPG decrypts our message using our protected secret key', async () => {
            const message = await pgp.encrypt({ data: enc.encode(TEXT), recipients: [pub], signer: { key: sec, parts } });
            const r = gpg(['--decrypt'], enc.encode(message));
            assert.equal(r.out.toString(), TEXT);
            assert.match(r.status, /GOODSIG/);
        });
    });
}

// ---------------------------------------------------------------- OpenPGP.js

const OPENPGP_KINDS = {
    'curve25519 (legacy)': { type: 'ecc', curve: 'curve25519Legacy' },
    'rsa 3072': { type: 'rsa', rsaBits: 3072 },
    'nistP256': { type: 'ecc', curve: 'nistP256' },
    'nistP521': { type: 'ecc', curve: 'nistP521' },
};

for (const [label, options] of Object.entries(OPENPGP_KINDS)) {
    describe(`OpenPGP.js ${label} key`, () => {
        let theirs, pub, sec, parts;

        before(async () => {
            theirs = await openpgp.generateKey({ ...options, userIDs: [{ name: 'OpenPGP.js', email: 'ojs@example.org' }], passphrase: PASS, format: 'object' });
            [pub] = await pgp.readKeys(theirs.publicKey.armor());
            [sec] = await pgp.readKeys(theirs.privateKey.armor());
            parts = await pgp.unlockKey(sec, PASS);
        });

        test('reads, validates and unlocks the key', () => {
            const s = pgp.summarise(pub);
            assert.equal(s.fingerprint, theirs.publicKey.getFingerprint().toUpperCase());
            assert.ok(s.valid && s.canEncrypt);
        });

        test('decrypts and verifies OpenPGP.js output', async () => {
            const privateKey = await openpgp.decryptKey({ privateKey: theirs.privateKey, passphrase: PASS });
            const message = await openpgp.encrypt({ message: await openpgp.createMessage({ text: TEXT }), encryptionKeys: theirs.publicKey, signingKeys: privateKey });
            const out = await pgp.decrypt({ message, decryptionKeys: [{ key: sec, parts }], verificationKeys: [pub] });
            assert.equal(dec.decode(out.data).replace(/\r\n/g, '\n'), TEXT);
            assert.equal(out.signatures[0]?.status, 'good');
        });

        test('OpenPGP.js decrypts and verifies our output', async () => {
            const armored = await pgp.encrypt({ data: enc.encode(TEXT), recipients: [pub], signer: { key: sec, parts } });
            const privateKey = await openpgp.decryptKey({ privateKey: theirs.privateKey, passphrase: PASS });
            const { data, signatures } = await openpgp.decrypt({
                message: await openpgp.readMessage({ armoredMessage: armored }),
                decryptionKeys: privateKey, verificationKeys: theirs.publicKey, format: 'binary',
            });
            assert.equal(dec.decode(data), TEXT);
            assert.equal(await signatures[0].verified, true);
        });

        test('detached signatures verify both ways', async () => {
            const data = enc.encode(TEXT);
            const privateKey = await openpgp.decryptKey({ privateKey: theirs.privateKey, passphrase: PASS });
            const theirSig = await openpgp.sign({ message: await openpgp.createMessage({ binary: data }), signingKeys: privateKey, detached: true });
            assert.equal((await pgp.verifyDetached({ data, signature: theirSig, keys: [pub] }))[0].status, 'good');

            const ours = await pgp.signDetached({ data, signer: { key: sec, parts } });
            const { signatures } = await openpgp.verify({
                message: await openpgp.createMessage({ binary: data }),
                signature: await openpgp.readSignature({ armoredSignature: ours }), verificationKeys: theirs.publicKey,
            });
            assert.equal(await signatures[0].verified, true);
        });
    });
}

describe('our keys in OpenPGP.js', () => {
    for (const kind of ['curve25519', 'rsa3072', 'p384']) {
        test(`${kind}: OpenPGP.js reads, unlocks and round-trips with our key`, async () => {
            const generated = await pgp.generateKey({ userIds: [`Ours <ours-ojs-${kind}@example.org>`], kind, passphrase: PASS });
            const theirPub = await openpgp.readKey({ armoredKey: generated.publicKey });
            const theirPriv = await openpgp.decryptKey({ privateKey: await openpgp.readPrivateKey({ armoredKey: generated.privateKey }), passphrase: PASS });
            await theirPub.verifyPrimaryKey(); // throws if our self-signatures are invalid

            const message = await openpgp.encrypt({ message: await openpgp.createMessage({ binary: enc.encode(TEXT) }), encryptionKeys: theirPub, signingKeys: theirPriv });
            const [pub] = await pgp.readKeys(generated.publicKey);
            const [sec] = await pgp.readKeys(generated.privateKey);
            const parts = await pgp.unlockKey(sec, PASS);
            const out = await pgp.decrypt({ message, decryptionKeys: [{ key: sec, parts }], verificationKeys: [pub] });
            assert.equal(dec.decode(out.data), TEXT);
            assert.equal(out.signatures[0].status, 'good');

            const ours = await pgp.encrypt({ data: enc.encode(TEXT), recipients: [pub], signer: { key: sec, parts } });
            const r = await openpgp.decrypt({ message: await openpgp.readMessage({ armoredMessage: ours }), decryptionKeys: theirPriv, verificationKeys: theirPub, format: 'binary' });
            assert.equal(dec.decode(r.data), TEXT);
            assert.equal(await r.signatures[0].verified, true);
        });
    }
});

// ---------------------------------------------------------------- multiple recipients & failures

describe('multi-recipient and failure handling', () => {
    test('one message to a GnuPG key, an OpenPGP.js key and our key — all three decrypt', async () => {
        const gUid = 'Multi GnuPG <multi-gpg@example.org>';
        gpg(['--quick-gen-key', gUid, 'ed25519', 'cert,sign', 'never']);
        const gFpr = gpgFingerprint(gUid);
        gpg(['--quick-add-key', gFpr, 'cv25519', 'encr', 'never']);
        const [gPub] = await pgp.readKeys(gpg(['--armor', '--export', gFpr]).out.toString());
        const o = await openpgp.generateKey({ type: 'rsa', rsaBits: 2048, userIDs: [{ email: 'multi-ojs@example.org' }], format: 'object' });
        const [oPub] = await pgp.readKeys(o.publicKey.armor());
        const mine = await pgp.generateKey({ userIds: ['Multi Ours <multi-ours@example.org>'], kind: 'p256', passphrase: PASS });
        const [mPub] = await pgp.readKeys(mine.publicKey);
        const [mSec] = await pgp.readKeys(mine.privateKey);

        const message = await pgp.encrypt({ data: enc.encode(TEXT), recipients: [gPub, oPub, mPub] });
        assert.equal(gpg(['--decrypt'], enc.encode(message)).out.toString(), TEXT);
        const r = await openpgp.decrypt({ message: await openpgp.readMessage({ armoredMessage: message }), decryptionKeys: o.privateKey, format: 'binary' });
        assert.equal(dec.decode(r.data), TEXT);
        const out = await pgp.decrypt({ message, decryptionKeys: [{ key: mSec, parts: await pgp.unlockKey(mSec, PASS) }] });
        assert.equal(dec.decode(out.data), TEXT);
    });

    test('tampered ciphertext is rejected by the integrity check', async () => {
        const k = await pgp.generateKey({ userIds: ['T <t@example.org>'], passphrase: PASS });
        const [pub] = await pgp.readKeys(k.publicKey);
        const [sec] = await pgp.readKeys(k.privateKey);
        const parts = await pgp.unlockKey(sec, PASS);
        const bytes = await pgp.encrypt({ data: enc.encode(TEXT), recipients: [pub], armor: false });
        bytes[bytes.length - 30] ^= 0x01;
        await assert.rejects(() => pgp.decrypt({ message: bytes, decryptionKeys: [{ key: sec, parts }] }), /modified|corrupt|damaged/);
    });

    test('a message for someone else names the key it needs', async () => {
        const a = await pgp.generateKey({ userIds: ['A <a@example.org>'], passphrase: PASS });
        const b = await pgp.generateKey({ userIds: ['B <b@example.org>'], passphrase: PASS });
        const [aPub] = await pgp.readKeys(a.publicKey);
        const [bSec] = await pgp.readKeys(b.privateKey);
        const message = await pgp.encrypt({ data: enc.encode('x'), recipients: [aPub] });
        const bParts = await pgp.unlockKey(bSec, PASS);
        await assert.rejects(() => pgp.decrypt({ message, decryptionKeys: [{ key: bSec, parts: bParts }] }), /None of your keys/);
    });

    test('re-protecting a key changes the passphrase', async () => {
        const k = await pgp.generateKey({ userIds: ['R <r@example.org>'], passphrase: 'old' });
        const [sec] = await pgp.readKeys(k.privateKey);
        const [again] = await pgp.readKeys(await pgp.reprotect(sec, 'old', 'new'));
        await assert.rejects(() => pgp.unlockKey(again, 'old'));
        assert.equal(Object.keys(await pgp.unlockKey(again, 'new')).length, 2);
    });
});
