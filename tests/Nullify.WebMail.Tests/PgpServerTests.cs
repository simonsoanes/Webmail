// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using System.Text;
using Nullify.WebMail.Services;
using Nullify.WebMail.Shared;

namespace Nullify.WebMail.Tests;

/// <summary>
/// Server-side OpenPGP plumbing: armor, vCard KEY and the RFC 3156 wrappers.
/// The cryptography itself runs in the browser and is tested in tests/pgp.
/// </summary>
[TestClass]
public class PgpServerTests
{
    [ClassInitialize]
    public static void Init(TestContext _) =>
        Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);

    private static readonly byte[] KeyBytes = Enumerable.Range(0, 300).Select(i => (byte)(i * 7)).ToArray();

    [TestMethod]
    public void Armor_RoundTripsWithChecksum()
    {
        var armored = OpenPgpArmor.Armor("PGP PUBLIC KEY BLOCK", KeyBytes);
        StringAssert.StartsWith(armored, "-----BEGIN PGP PUBLIC KEY BLOCK-----");
        StringAssert.Contains(armored, "-----END PGP PUBLIC KEY BLOCK-----");
        CollectionAssert.AreEqual(KeyBytes, OpenPgpArmor.Dearmor(armored));
    }

    [TestMethod]
    public void Armor_Crc24MatchesRfc4880()
    {
        // CRC-24 of "123456789" with the RFC 4880 init/poly is 0x21CF02.
        var armored = OpenPgpArmor.Armor("PGP MESSAGE", Encoding.ASCII.GetBytes("123456789"));
        StringAssert.Contains(armored, "=" + Convert.ToBase64String([0x21, 0xCF, 0x02]));
    }

    [TestMethod]
    public void Dearmor_IgnoresHeadersAndCrc_AsRfc9580Requires()
    {
        // RFC 9580 6.1: a missing or wrong CRC must not cause rejection (packets carry their own integrity).
        var b64 = Convert.ToBase64String(KeyBytes);
        var text = "junk before\n-----BEGIN PGP PUBLIC KEY BLOCK-----\nComment: from somewhere\nVersion: X\n\n"
                   + b64[..64] + "\n" + b64[64..] + "\n=AAAA\n-----END PGP PUBLIC KEY BLOCK-----\ntrailer";
        CollectionAssert.AreEqual(KeyBytes, OpenPgpArmor.Dearmor(text));
        Assert.IsNull(OpenPgpArmor.Dearmor("-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n!!notbase64\n-----END PGP PUBLIC KEY BLOCK-----"));
    }

    private static ContactEdit Edit(string? key) =>
        new("Bob", "Builder", null, null, [new ContactValue("bob@example.org", "Work")], [], null, null) { PublicKey = key };

    [TestMethod]
    public void VCard3_WritesAndReadsPgpKey()
    {
        var armored = OpenPgpArmor.Armor("PGP PUBLIC KEY BLOCK", KeyBytes);
        var card = VCard.Write(null, Edit(armored), "bob-1");
        StringAssert.Contains(card, "KEY;TYPE=PGP;ENCODING=b:");
        var parsed = VCard.Parse(card).Single();
        Assert.IsNotNull(parsed.PublicKey);
        CollectionAssert.AreEqual(KeyBytes, OpenPgpArmor.Dearmor(parsed.PublicKey));
    }

    [TestMethod]
    public void VCard4_WritesDataUriKey()
    {
        var existing = "BEGIN:VCARD\r\nVERSION:4.0\r\nUID:bob-1\r\nFN:Bob\r\nEND:VCARD\r\n";
        var card = VCard.Write(existing, Edit(OpenPgpArmor.Armor("PGP PUBLIC KEY BLOCK", KeyBytes)), "bob-1");
        StringAssert.Contains(card.Replace("\r\n ", ""), "KEY:data:application/pgp-keys;base64,");
        CollectionAssert.AreEqual(KeyBytes, OpenPgpArmor.Dearmor(VCard.Parse(card).Single().PublicKey!));
    }

    [TestMethod]
    public void VCard_KeyKeptWhenEditLeavesItAlone_RemovedWhenEmpty_OtherKeysKept()
    {
        var b64 = Convert.ToBase64String(KeyBytes);
        var existing = "BEGIN:VCARD\r\nVERSION:3.0\r\nUID:bob-1\r\nFN:Bob\r\n" +
                       "KEY;TYPE=PGP;ENCODING=b:" + b64 + "\r\n" +
                       "KEY;TYPE=X509;ENCODING=b:MIIBAA==\r\nEND:VCARD\r\n";

        var kept = VCard.Write(existing, Edit(null), "bob-1");
        Assert.IsNotNull(VCard.Parse(kept).Single().PublicKey);
        StringAssert.Contains(kept, "TYPE=X509");

        var removed = VCard.Write(existing, Edit(""), "bob-1");
        Assert.IsNull(VCard.Parse(removed).Single().PublicKey);
        StringAssert.Contains(removed, "TYPE=X509");
    }

    [TestMethod]
    public void VCard_ReadsArmoredAndDataUriKeysFromOtherClients()
    {
        var armored = OpenPgpArmor.Armor("PGP PUBLIC KEY BLOCK", KeyBytes);
        var dataUri = "BEGIN:VCARD\r\nVERSION:4.0\r\nUID:a\r\nFN:A\r\nKEY;MEDIATYPE=application/pgp-keys:data:application/pgp-keys;base64,"
                      + Convert.ToBase64String(Encoding.ASCII.GetBytes(armored)) + "\r\nEND:VCARD\r\n";
        CollectionAssert.AreEqual(KeyBytes, OpenPgpArmor.Dearmor(VCard.Parse(dataUri).Single().PublicKey!));
    }

    [TestMethod]
    public void SignedEntity_ParsesBackToTheExactSignedBytes()
    {
        var req = new SendRequest("a@example.org", ["bob@example.org"], null, null, "Hi", "Hello Bob\nSecond line — café", null, null,
            false, false, null);
        var entity = MailService.BuildBodyEntity(req).TrimEnd('\r', '\n'); // what Compose signs
        var wrapped = MailService.PgpSignedEntity(entity, "-----BEGIN PGP SIGNATURE-----\r\n\r\nAAAA\r\n-----END PGP SIGNATURE-----", "pgp-sha256");
        var raw = Encoding.UTF8.GetBytes("From: a@example.org\r\nSubject: Hi\r\nMIME-Version: 1.0\r\n" + wrapped);

        var parsed = MimeParser.Parse(raw);
        Assert.AreEqual(entity, parsed.PgpSignedEntity);
        StringAssert.Contains(parsed.PgpSignature, "BEGIN PGP SIGNATURE");
        StringAssert.Contains(parsed.TextBody, "Hello Bob");

        var info = MailService.DetectPgp(parsed)!;
        Assert.AreEqual(PgpMessageKind.Signed, info.Kind);
        CollectionAssert.AreEqual(Encoding.UTF8.GetBytes(entity), Convert.FromBase64String(info.SignedEntityBase64!));
    }

    [TestMethod]
    public void EncryptedEntity_ExposesArmoredMessageOnly()
    {
        var armored = OpenPgpArmor.Armor("PGP MESSAGE", KeyBytes);
        var raw = Encoding.UTF8.GetBytes("From: a@example.org\r\nSubject: Secret\r\nMIME-Version: 1.0\r\n" + MailService.PgpEncryptedEntity(armored));
        var parsed = MimeParser.Parse(raw);
        var info = MailService.DetectPgp(parsed)!;
        Assert.AreEqual(PgpMessageKind.Encrypted, info.Kind);
        CollectionAssert.AreEqual(KeyBytes, OpenPgpArmor.Dearmor(info.Armored!));
        Assert.IsTrue(string.IsNullOrEmpty(parsed.TextBody));
    }

    [TestMethod]
    public void InlineBlocks_AreDetected()
    {
        var msg = MimeParser.Parse(Encoding.UTF8.GetBytes("Subject: x\r\n\r\nhi\r\n" + OpenPgpArmor.Armor("PGP MESSAGE", KeyBytes)));
        Assert.AreEqual(PgpMessageKind.InlineEncrypted, MailService.DetectPgp(msg)!.Kind);

        var signed = "Subject: x\r\n\r\n-----BEGIN PGP SIGNED MESSAGE-----\r\nHash: SHA256\r\n\r\nhi\r\n" +
                     "-----BEGIN PGP SIGNATURE-----\r\n\r\nAAAA\r\n-----END PGP SIGNATURE-----\r\n";
        Assert.AreEqual(PgpMessageKind.InlineSigned, MailService.DetectPgp(MimeParser.Parse(Encoding.UTF8.GetBytes(signed)))!.Kind);
        Assert.IsNull(MailService.DetectPgp(MimeParser.Parse(Encoding.UTF8.GetBytes("Subject: x\r\n\r\nplain\r\n"))));
    }
}
