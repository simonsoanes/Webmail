// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using System.Buffers.Text;
using System.Formats.Cbor;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Nullify.WebMail.Controllers;
using Nullify.WebMail.Data;
using Nullify.WebMail.Services;

namespace Nullify.WebMail.Tests;

/// <summary>
/// Passkey sign-in end to end, with a software authenticator standing in for the browser and the
/// passkey, against a fake IMAP server. The authenticator derives keys exactly as passkey.js does.
/// </summary>
[TestClass]
public class PasskeyTests
{
    private const string User = "passkey@example.test";
    private const string Password = "pw-wrapped-under-the-passkey";
    private const string Origin = "http://localhost";

    private static WebApplicationFactory<Program> _factory = null!;
    private static FakeImapServer _imap = null!;
    private static string _dataDir = null!;
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    [ClassInitialize]
    public static void Setup(TestContext _)
    {
        _imap = new FakeImapServer(User, Password);
        _dataDir = Path.Combine(Path.GetTempPath(), "nullify-webmail-passkey-tests-" + Guid.NewGuid().ToString("N"));
        _factory = new WebApplicationFactory<Program>().WithWebHostBuilder(b =>
        {
            b.UseSetting("Storage:DataDirectory", _dataDir);
            b.UseSetting("Imap:Host", "127.0.0.1");
            b.UseSetting("Imap:Port", _imap.Port.ToString());
            b.UseSetting("Imap:Security", "None");
        });
    }

    [ClassCleanup]
    public static void Cleanup()
    {
        _factory.Dispose();
        _imap.Dispose();
        try { Directory.Delete(_dataDir, recursive: true); } catch { }
    }

    [TestInitialize]
    public void ResetPassword() => _imap.Password = Password;

    [TestMethod]
    public async Task Passkey_SignsIn_AndTheSaltChangesEveryTime()
    {
        using var authenticator = await Registered();

        var browser = _factory.CreateClient();
        var first = await SignInOptions(browser, User);
        var salt1 = first.Salts[authenticator.Id].First;
        Assert.IsTrue((await Post<PasskeyResponse>(browser, "/api/auth/passkey/signin", authenticator.Assert(first))).Success);
        Assert.AreEqual(System.Net.HttpStatusCode.OK, (await browser.GetAsync("/api/auth/session")).StatusCode);

        // The next sign-in uses the salt the last one rewrapped with, so the old key no longer opens the login.
        var second = await SignInOptions(_factory.CreateClient(), User);
        Assert.AreEqual(first.Salts[authenticator.Id].Second, second.Salts[authenticator.Id].First);
        Assert.AreNotEqual(salt1, second.Salts[authenticator.Id].First);
        var stale = authenticator.Assert(second) with { Kek = authenticator.Kek(salt1) };
        var refused = await Post<PasskeyResponse>(_factory.CreateClient(), "/api/auth/passkey/signin", stale);
        Assert.IsFalse(refused.Success);
        StringAssert.Contains(refused.Error, "couldn't unlock");

        // The database never holds the password in the clear.
        await using var db = await Db();
        var row = await db.Passkeys.SingleAsync(p => p.CredentialId == authenticator.Id);
        Assert.DoesNotContain(Password, Encoding.UTF8.GetString(row.WrappedCredential));
        Assert.AreEqual(2, row.WrapVersion, "Wrapped at registration and again at the one successful sign-in.");
    }

    [TestMethod]
    public async Task Answers_AreSingleUse_AndMustBeSignedByThePasskey()
    {
        using var authenticator = await Registered();

        var options = await SignInOptions(_factory.CreateClient(), User);
        var request = authenticator.Assert(options);
        var forged = request with { Signature = authenticator.Assert(options, tamper: true).Signature };
        Assert.IsFalse((await Post<PasskeyResponse>(_factory.CreateClient(), "/api/auth/passkey/signin", forged)).Success);
        // The forged attempt used up the challenge, so even the genuine answer is now refused.
        Assert.IsFalse((await Post<PasskeyResponse>(_factory.CreateClient(), "/api/auth/passkey/signin", request)).Success);

        options = await SignInOptions(_factory.CreateClient(), User);
        request = authenticator.Assert(options);
        Assert.IsTrue((await Post<PasskeyResponse>(_factory.CreateClient(), "/api/auth/passkey/signin", request)).Success);
        Assert.IsFalse((await Post<PasskeyResponse>(_factory.CreateClient(), "/api/auth/passkey/signin", request)).Success, "Replayed");
    }

    [TestMethod]
    [DataRow("https://evil.example")]
    [DataRow("https://evil.localhost")] // a subdomain may claim the parent as RP id; its origin is still refused
    [DataRow("https://localhost:8443")]
    [DataRow("http://localhost.evil.example")]
    public async Task Assertion_FromAnotherSite_IsRefused(string origin)
    {
        using var authenticator = await Registered();
        var options = await SignInOptions(_factory.CreateClient(), User);
        var response = await Post<PasskeyResponse>(_factory.CreateClient(), "/api/auth/passkey/signin",
            authenticator.Assert(options, origin: origin));
        Assert.IsFalse(response.Success);
        StringAssert.Contains(response.Error, "isn't this site's address");
        StringAssert.Contains(response.Error, origin);
    }

    [TestMethod]
    public async Task HttpsOrigin_IsAccepted_BehindAProxyThatHidesTheScheme()
    {
        // The test server sees plain http, as the app does behind a TLS proxy whose X-Forwarded-Proto isn't trusted.
        using var authenticator = await Registered();
        var options = await SignInOptions(_factory.CreateClient(), User);
        var response = await Post<PasskeyResponse>(_factory.CreateClient(), "/api/auth/passkey/signin",
            authenticator.Assert(options, origin: "https://localhost"));
        Assert.IsTrue(response.Success, response.Error);
    }

    [TestMethod]
    public async Task ChangedPassword_MarksThePasskeyStale_UntilItIsUpdated()
    {
        var (authenticator, owner) = await RegisteredWithClient();
        using var _ = authenticator;
        const string changed = "pw-changed-on-the-mail-server";
        _imap.Password = changed;

        var response = await Post<PasskeyResponse>(_factory.CreateClient(), "/api/auth/passkey/signin",
            authenticator.Assert(await SignInOptions(_factory.CreateClient(), User)));
        Assert.IsFalse(response.Success);
        StringAssert.Contains(response.Error, "changed");
        await using (var db = await Db())
            Assert.IsTrue((await db.Passkeys.SingleAsync(p => p.CredentialId == authenticator.Id)).Stale);

        // Signed in with the new password, the user updates the passkey, and it works again.
        await SignInWithPassword(owner, changed);
        var row = await RowFor(authenticator);
        var update = await Post<PasskeyAssertionOptions>(owner, $"/api/auth/passkey/{row.Id}/update/options");
        Assert.IsTrue((await Post<PasskeyResponse>(owner, "/api/auth/passkey/update", authenticator.Assert(update))).Success);
        Assert.IsTrue((await Post<PasskeyResponse>(_factory.CreateClient(), "/api/auth/passkey/signin",
            authenticator.Assert(await SignInOptions(_factory.CreateClient(), User)))).Success);
        Assert.IsFalse((await RowFor(authenticator)).Stale);
    }

    [TestMethod]
    public async Task UnknownAddress_GetsOptionsThatLookTheSame()
    {
        var options = await SignInOptions(_factory.CreateClient(), "nobody@example.test");
        Assert.HasCount(1, options.Allow);
        Assert.IsNotNull(options.Salts[options.Allow[0].Id].Second);
        // The made-up credential and its current salt are stable, as a real passkey's are, so asking twice doesn't give it away.
        var again = await SignInOptions(_factory.CreateClient(), "NOBODY@example.test");
        Assert.AreEqual(options.Allow[0].Id, again.Allow[0].Id);
        Assert.AreEqual(options.Salts[options.Allow[0].Id].First, again.Salts[again.Allow[0].Id].First);
    }

    [TestMethod]
    public async Task Registration_NeedsASession()
    {
        var response = await _factory.CreateClient().PostAsync("/api/auth/passkey/register/options", JsonContent.Create(new { }));
        Assert.AreEqual(System.Net.HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [TestMethod]
    public async Task RemovingAPasskey_EndsItsSessions()
    {
        using var authenticator = await Registered();
        var browser = _factory.CreateClient();
        Assert.IsTrue((await Post<PasskeyResponse>(browser, "/api/auth/passkey/signin",
            authenticator.Assert(await SignInOptions(browser, User)))).Success);

        using (var scope = _factory.Services.CreateScope())
            await scope.ServiceProvider.GetRequiredService<PasskeyService>().RemoveAsync(User, (await RowFor(authenticator)).Id);

        Assert.AreEqual(System.Net.HttpStatusCode.Unauthorized, (await browser.GetAsync("/api/auth/session")).StatusCode);
    }

    [TestMethod]
    public async Task PhonePasskey_SignsInADesktop_ByQr()
    {
        using var authenticator = await Registered();
        var (desktop, phone, id, phoneToken) = await ConfirmedQrRequest();

        var approve = await Post<QrApproveResponse>(phone, $"/api/auth/qr/{id}/approve-passkey",
            new { phoneToken, assertion = authenticator.Assert(await SignInOptions(phone, User)) });
        Assert.IsTrue(approve.Success, approve.Error);
        Assert.AreEqual(User, approve.Login);
        Assert.IsNotNull(approve.RevokeToken);
        Assert.AreEqual(System.Net.HttpStatusCode.Unauthorized, (await phone.GetAsync("/api/auth/session")).StatusCode, "The phone isn't signed in.");

        Assert.IsTrue((await Post<Shared.LoginResponse>(desktop, $"/api/auth/qr/{id}/redeem")).Success);
        Assert.AreEqual(System.Net.HttpStatusCode.OK, (await desktop.GetAsync("/api/auth/session")).StatusCode);

        // The desktop's session came from the passkey, so removing the passkey ends it too.
        using (var scope = _factory.Services.CreateScope())
            await scope.ServiceProvider.GetRequiredService<PasskeyService>().RemoveAsync(User, (await RowFor(authenticator)).Id);
        Assert.AreEqual(System.Net.HttpStatusCode.Unauthorized, (await desktop.GetAsync("/api/auth/session")).StatusCode);
    }

    [TestMethod]
    public async Task FailedPasskeyApprovals_UseUpTheQrRequest()
    {
        using var authenticator = await Registered();
        var (_, phone, id, phoneToken) = await ConfirmedQrRequest();

        // Without the phone token nothing is checked or counted.
        Assert.IsFalse((await Post<QrApproveResponse>(phone, $"/api/auth/qr/{id}/approve-passkey",
            new { phoneToken = "wrong", assertion = authenticator.Assert(await SignInOptions(phone, User)) })).Success);

        QrApproveResponse last = null!;
        for (var i = 0; i < 3; i++)
        {
            var options = await SignInOptions(phone, User);
            var forged = authenticator.Assert(options) with { Signature = authenticator.Assert(options, tamper: true).Signature };
            last = await Post<QrApproveResponse>(phone, $"/api/auth/qr/{id}/approve-passkey", new { phoneToken, assertion = forged });
            Assert.IsFalse(last.Success);
        }
        StringAssert.StartsWith(last.Error, "Too many");

        var genuine = await Post<QrApproveResponse>(phone, $"/api/auth/qr/{id}/approve-passkey",
            new { phoneToken, assertion = authenticator.Assert(await SignInOptions(phone, User)) });
        Assert.IsFalse(genuine.Success, "The request was cancelled after three failures.");
    }

    [TestMethod]
    public void RsaSignatures_Verify()
    {
        using var rsa = RSA.Create(2048);
        var p = rsa.ExportParameters(false);
        var cose = new CborWriter(CborConformanceMode.Ctap2Canonical);
        cose.WriteStartMap(4);
        cose.WriteInt32(1); cose.WriteInt32(3);
        cose.WriteInt32(3); cose.WriteInt32(WebAuthn.Rs256);
        cose.WriteInt32(-1); cose.WriteByteString(p.Modulus!);
        cose.WriteInt32(-2); cose.WriteByteString(p.Exponent!);
        cose.WriteEndMap();
        var key = cose.Encode();

        byte[] authData = new byte[37], clientData = Encoding.UTF8.GetBytes("{}");
        var signature = rsa.SignData([.. authData, .. SHA256.HashData(clientData)], HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        Assert.IsTrue(WebAuthn.VerifySignature(key, authData, clientData, signature));
        signature[0] ^= 1;
        Assert.IsFalse(WebAuthn.VerifySignature(key, authData, clientData, signature));
    }

    // ------------------------------------------------------------------ helpers

    private static async Task<SoftAuthenticator> Registered()
    {
        var (authenticator, _) = await RegisteredWithClient();
        return authenticator;
    }

    /// <summary>Sign in with the password, then add a passkey from that session.</summary>
    private static async Task<(SoftAuthenticator, HttpClient)> RegisteredWithClient()
    {
        var client = _factory.CreateClient();
        await SignInWithPassword(client, Password);
        var options = await Post<PasskeyRegisterOptions>(client, "/api/auth/passkey/register/options");
        Assert.AreEqual("localhost", options.RpId);
        CollectionAssert.Contains(options.Algorithms, WebAuthn.Es256);

        var authenticator = new SoftAuthenticator();
        var response = await Post<PasskeyResponse>(client, "/api/auth/passkey/register", authenticator.Create(options));
        Assert.IsTrue(response.Success, response.Error);
        return (authenticator, client);
    }

    /// <summary>A desktop starts a QR sign-in and the phone picks the right number.</summary>
    private static async Task<(HttpClient Desktop, HttpClient Phone, string Id, string PhoneToken)> ConfirmedQrRequest()
    {
        var desktop = _factory.CreateClient();
        var phone = _factory.CreateClient();
        var start = await Post<QrStartResponse>(desktop, "/api/auth/qr/start");
        await Post<QrDescription>(phone, $"/api/auth/qr/{start.Id}/describe");
        var confirm = await Post<QrConfirmResponse>(phone, $"/api/auth/qr/{start.Id}/confirm", new { code = start.Code });
        Assert.IsTrue(confirm.Success, confirm.Error);
        return (desktop, phone, start.Id, confirm.PhoneToken!);
    }

    private static async Task SignInWithPassword(HttpClient client, string password)
    {
        var login = await client.PostAsJsonAsync("/api/auth/login", new { username = User, password });
        StringAssert.Contains(await login.Content.ReadAsStringAsync(), "\"success\":true");
    }

    private static Task<PasskeyAssertionOptions> SignInOptions(HttpClient client, string username) =>
        Post<PasskeyAssertionOptions>(client, "/api/auth/passkey/signin/options", new { username });

    private static async Task<Passkey> RowFor(SoftAuthenticator authenticator)
    {
        await using var db = await Db();
        return await db.Passkeys.AsNoTracking().SingleAsync(p => p.CredentialId == authenticator.Id);
    }

    private static Task<AppDbContext> Db() =>
        _factory.Services.GetRequiredService<IDbContextFactory<AppDbContext>>().CreateDbContextAsync();

    private static async Task<T> Post<T>(HttpClient client, string url, object? body = null)
    {
        var response = await client.PostAsync(url, JsonContent.Create(body ?? new { }));
        var text = await response.Content.ReadAsStringAsync();
        return JsonSerializer.Deserialize<T>(text, Json)
            ?? throw new AssertFailedException($"{url}: {(int)response.StatusCode} {text}");
    }

    /// <summary>A P-256 passkey with PRF, and the browser side of passkey.js.</summary>
    private sealed class SoftAuthenticator : IDisposable
    {
        private readonly ECDsa _key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        private readonly byte[] _credentialId = RandomNumberGenerator.GetBytes(16);
        private readonly byte[] _prfSecret = RandomNumberGenerator.GetBytes(32);
        private uint _counter;

        public string Id => Base64Url.EncodeToString(_credentialId);

        /// <summary>As passkey.js: PRF over SHA-256(label | salt), then HKDF bound to the credential id.</summary>
        public string Kek(string serverSalt)
        {
            var input = SHA256.HashData([.. "nullify-webmail/imap-wrap/v1"u8, .. Base64Url.DecodeFromChars(serverSalt)]);
            var prf = HMACSHA256.HashData(_prfSecret, input);
            return Base64Url.EncodeToString(HKDF.DeriveKey(HashAlgorithmName.SHA256, prf, 32, [], [.. "imap-kek/v1"u8, .. _credentialId]));
        }

        public PasskeyRegisterRequest Create(PasskeyRegisterOptions o)
        {
            var p = _key.ExportParameters(false);
            var cose = new CborWriter(CborConformanceMode.Ctap2Canonical);
            cose.WriteStartMap(5);
            cose.WriteInt32(1); cose.WriteInt32(2);
            cose.WriteInt32(3); cose.WriteInt32(WebAuthn.Es256);
            cose.WriteInt32(-1); cose.WriteInt32(1);
            cose.WriteInt32(-2); cose.WriteByteString(p.Q.X!);
            cose.WriteInt32(-3); cose.WriteByteString(p.Q.Y!);
            cose.WriteEndMap();

            byte[] authData =
            [
                .. SHA256.HashData(Encoding.UTF8.GetBytes(o.RpId)), 0x45, 0, 0, 0, 0,
                .. new byte[16], (byte)(_credentialId.Length >> 8), (byte)_credentialId.Length, .. _credentialId, .. cose.Encode(),
            ];
            var attestation = new CborWriter(CborConformanceMode.Ctap2Canonical);
            attestation.WriteStartMap(3);
            attestation.WriteTextString("fmt"); attestation.WriteTextString("none");
            attestation.WriteTextString("attStmt"); attestation.WriteStartMap(0); attestation.WriteEndMap();
            attestation.WriteTextString("authData"); attestation.WriteByteString(authData);
            attestation.WriteEndMap();

            return new PasskeyRegisterRequest(o.Handle, ClientData("webauthn.create", o.Challenge, Origin),
                Base64Url.EncodeToString(attestation.Encode()), ["internal"], Kek(o.Salt));
        }

        public PasskeyAssertionRequest Assert(PasskeyAssertionOptions o, string origin = Origin, bool tamper = false)
        {
            var salts = o.Salts[Id];
            _counter++;
            byte[] authData = [.. SHA256.HashData(Encoding.UTF8.GetBytes(o.RpId)), 0x05,
                (byte)(_counter >> 24), (byte)(_counter >> 16), (byte)(_counter >> 8), (byte)_counter];
            var clientData = ClientData("webauthn.get", o.Challenge, origin);
            var signed = tamper ? [.. authData, .. new byte[32]] : authData.Concat(SHA256.HashData(Base64Url.DecodeFromChars(clientData))).ToArray();
            var signature = _key.SignData(signed, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
            return new PasskeyAssertionRequest(o.Handle, Id, clientData, Base64Url.EncodeToString(authData),
                Base64Url.EncodeToString(signature), null, Kek(salts.First), salts.Second is { } next ? Kek(next) : null);
        }

        private static string ClientData(string type, string challenge, string origin) =>
            Base64Url.EncodeToString(JsonSerializer.SerializeToUtf8Bytes(new { type, challenge, origin, crossOrigin = false }));

        public void Dispose() => _key.Dispose();
    }
}
