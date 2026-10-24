// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using System.Net;
using System.Net.Http.Json;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Time.Testing;
using Nullify.WebMail.Controllers;
using Nullify.WebMail.Services;

namespace Nullify.WebMail.Tests;

/// <summary>Signing in a "desktop" client from a separate "phone" client, against a fake IMAP server.</summary>
[TestClass]
public class QrLoginTests
{
    private const string User = "qr@example.test";
    private const string Password = "pw-qr-only-on-the-phone";

    private static WebApplicationFactory<Program> _factory = null!;
    private static FakeImapServer _imap = null!;
    private static string _dataDir = null!;
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    [ClassInitialize]
    public static void Setup(TestContext _)
    {
        _imap = new FakeImapServer(User, Password);
        _dataDir = Path.Combine(Path.GetTempPath(), "nullify-webmail-qr-tests-" + Guid.NewGuid().ToString("N"));
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

    [TestMethod]
    public async Task Phone_SignsInDesktop_WithoutThePasswordReachingIt()
    {
        var desktop = _factory.CreateClient();
        var phone = _factory.CreateClient();

        var start = await Post<QrStartResponse>(desktop, "/api/auth/qr/start");
        StringAssert.EndsWith(start.ApproveUrl, "/m/approve#" + start.Id, "The id belongs in the fragment, out of server logs.");

        var described = await Post<QrDescription>(phone, $"/api/auth/qr/{start.Id}/describe");
        CollectionAssert.Contains(described.Codes, start.Code);
        Assert.HasCount(3, described.Codes);

        var confirm = await Post<QrConfirmResponse>(phone, $"/api/auth/qr/{start.Id}/confirm", new { code = start.Code });
        Assert.IsTrue(confirm.Success);

        var wrong = await Post<QrApproveResponse>(phone, $"/api/auth/qr/{start.Id}/approve",
            new { confirm.PhoneToken, username = User, password = "not-it" });
        Assert.IsFalse(wrong.Success, "A wrong password leaves attempts to spare.");

        var approve = await Post<QrApproveResponse>(phone, $"/api/auth/qr/{start.Id}/approve",
            new { confirm.PhoneToken, username = User, password = Password });
        Assert.IsTrue(approve.Success, approve.Error);
        Assert.AreEqual(User, approve.Login);

        // Approving signs nobody in yet: not the phone, and not the desktop until it redeems.
        Assert.AreEqual(HttpStatusCode.Unauthorized, (await phone.GetAsync("/api/auth/session")).StatusCode);
        Assert.AreEqual(HttpStatusCode.Unauthorized, (await desktop.GetAsync("/api/auth/session")).StatusCode);

        // Only the browser holding the binding cookie can collect the session.
        Assert.IsFalse((await Post<Shared.LoginResponse>(phone, $"/api/auth/qr/{start.Id}/redeem")).Success);

        var redeemResponse = await desktop.PostAsync($"/api/auth/qr/{start.Id}/redeem", null);
        var setCookie = string.Join("\n", redeemResponse.Headers.GetValues("Set-Cookie"));
        Assert.IsTrue((await redeemResponse.Content.ReadFromJsonAsync<Shared.LoginResponse>(Json))!.Success);
        Assert.DoesNotContain(Password, setCookie);
        var authCookie = setCookie.Split('\n').Single(c => c.StartsWith("nullify.webmail.auth="));
        Assert.DoesNotContain("expires=", authCookie.ToLowerInvariant(), "A QR session cookie ends with the browser.");

        Assert.AreEqual(HttpStatusCode.OK, (await desktop.GetAsync("/api/auth/session")).StatusCode);

        // Single use.
        Assert.IsFalse((await Post<Shared.LoginResponse>(desktop, $"/api/auth/qr/{start.Id}/redeem")).Success);

        // The phone sees the session and can end it.
        var sessions = await Post<QrSessionResponse[]>(phone, "/api/auth/qr/sessions", new { tokens = new[] { approve.RevokeToken } });
        Assert.HasCount(1, sessions);
        Assert.IsTrue(sessions[0].Active);
        Assert.AreEqual(User, sessions[0].Login);

        Assert.IsTrue((await Post<Shared.LoginResponse>(phone, "/api/auth/qr/sessions/revoke", new { token = approve.RevokeToken })).Success);
        Assert.AreEqual(HttpStatusCode.Unauthorized, (await desktop.GetAsync("/api/auth/session")).StatusCode);
        sessions = await Post<QrSessionResponse[]>(phone, "/api/auth/qr/sessions", new { tokens = new[] { approve.RevokeToken } });
        Assert.IsFalse(sessions[0].Active);
    }

    [TestMethod]
    public async Task WrongMatchCode_CancelsTheRequest()
    {
        var desktop = _factory.CreateClient();
        var phone = _factory.CreateClient();
        var start = await Post<QrStartResponse>(desktop, "/api/auth/qr/start");
        var described = await Post<QrDescription>(phone, $"/api/auth/qr/{start.Id}/describe");

        var wrongCode = described.Codes.First(c => c != start.Code);
        Assert.IsFalse((await Post<QrConfirmResponse>(phone, $"/api/auth/qr/{start.Id}/confirm", new { code = wrongCode })).Success);

        // No second guess, and the request is gone.
        Assert.IsFalse((await Post<QrConfirmResponse>(phone, $"/api/auth/qr/{start.Id}/confirm", new { code = start.Code })).Success);
        Assert.AreEqual(HttpStatusCode.NotFound, (await phone.PostAsync($"/api/auth/qr/{start.Id}/describe", null)).StatusCode);
    }

    [TestMethod]
    public async Task Approve_WithoutAConfirmedRequest_NeverTriesThePassword()
    {
        var desktop = _factory.CreateClient();
        var phone = _factory.CreateClient();
        var start = await Post<QrStartResponse>(desktop, "/api/auth/qr/start");
        var logins = _imap.LoginAttempts;

        var approve = await Post<QrApproveResponse>(phone, $"/api/auth/qr/{start.Id}/approve",
            new { phoneToken = "guess", username = User, password = Password });

        Assert.IsFalse(approve.Success);
        Assert.AreEqual(logins, _imap.LoginAttempts, "The endpoint must not be usable to test passwords.");
    }

    [TestMethod]
    public async Task RepeatedWrongPasswords_EndTheRequest()
    {
        var desktop = _factory.CreateClient();
        var phone = _factory.CreateClient();
        var start = await Post<QrStartResponse>(desktop, "/api/auth/qr/start");
        await Post<QrDescription>(phone, $"/api/auth/qr/{start.Id}/describe");
        var confirm = await Post<QrConfirmResponse>(phone, $"/api/auth/qr/{start.Id}/confirm", new { code = start.Code });

        for (var i = 0; i < QrLoginService.MaxPasswordAttempts; i++)
            await Post<QrApproveResponse>(phone, $"/api/auth/qr/{start.Id}/approve", new { confirm.PhoneToken, username = User, password = "nope" });

        var late = await Post<QrApproveResponse>(phone, $"/api/auth/qr/{start.Id}/approve",
            new { confirm.PhoneToken, username = User, password = Password });
        Assert.IsFalse(late.Success);
    }

    // ------------------------------------------------------------------ service timing

    [TestMethod]
    public void UnscannedRequest_ExpiresAfterTheScanWindow()
    {
        var (qr, time) = NewService();
        var states = new List<QrLoginState>();
        var (id, _, _, _) = qr.Start("ua", "1.2.3.4");
        qr.Changed += (changed, state) => { if (changed == id) states.Add(state); };

        time.Advance(QrLoginService.ScanWindow + TimeSpan.FromSeconds(1));
        qr.Sweep();

        Assert.IsNull(qr.GetState(id));
        Assert.IsNull(qr.Describe(id, null));
        CollectionAssert.Contains(states, QrLoginState.Expired);
    }

    [TestMethod]
    public async Task QrSession_EndsAtItsTimeLimit()
    {
        var store = new MemoryTicketStore();
        var (qr, time) = NewService(store);
        var (id, bind, code, _) = qr.Start("ua", null);
        qr.Describe(id, null);
        var phoneToken = qr.Confirm(id, code)!;

        using var scope = _factory.Services.CreateScope();
        var auth = scope.ServiceProvider.GetRequiredService<AuthService>();
        var cred = new CredentialInfo("h", 1, Shared.MailSecurity.None, false, User, Password, "h", 1, Shared.MailSecurity.None, "h", 1);
        var (principal, properties) = auth.BuildSignIn(cred, qr.SessionLifetime);
        Assert.IsNotNull(qr.Approve(id, phoneToken, principal, properties));
        var (redeemed, _) = qr.Redeem(id, bind)!.Value;
        var sessionId = redeemed.FindFirst(AuthService.SessionIdClaim)!.Value;
        await store.StoreAsync(new Microsoft.AspNetCore.Authentication.AuthenticationTicket(redeemed, properties, "Cookies"));
        Assert.IsTrue(store.HasSession(sessionId));

        string? ended = null;
        store.SessionEnded += s => ended = s;
        time.Advance(qr.SessionLifetime + TimeSpan.FromSeconds(1));
        qr.Sweep();

        Assert.AreEqual(sessionId, ended);
        Assert.IsFalse(store.HasSession(sessionId));
    }

    private static (QrLoginService, FakeTimeProvider) NewService(MemoryTicketStore? store = null)
    {
        var time = new FakeTimeProvider(DateTimeOffset.UtcNow);
        var config = new ConfigurationBuilder().Build();
        return (new QrLoginService(store ?? new MemoryTicketStore(), config, time), time);
    }

    private static async Task<T> Post<T>(HttpClient client, string url, object? body = null)
    {
        var response = await client.PostAsync(url, body == null ? null : JsonContent.Create(body));
        var text = await response.Content.ReadAsStringAsync();
        return JsonSerializer.Deserialize<T>(text, Json)
            ?? throw new AssertFailedException($"{url}: {(int)response.StatusCode} {text}");
    }
}
