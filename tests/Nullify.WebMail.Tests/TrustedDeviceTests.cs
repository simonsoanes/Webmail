// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Nullify.WebMail.Data;
using Nullify.WebMail.Services;

namespace Nullify.WebMail.Tests;

/// <summary>"I trust this computer": the browser keeps the login, sealed by the server, to sign in again later.</summary>
[TestClass]
public class TrustedDeviceTests
{
    private const string User = "trusted@example.test";
    private const string Password = "pw-trusted-sealed-by-the-server";

    private static WebApplicationFactory<Program> _factory = null!;
    private static FakeImapServer _imap = null!;
    private static string _dataDir = null!;

    [ClassInitialize]
    public static void Setup(TestContext _)
    {
        _imap = new FakeImapServer(User, Password);
        _dataDir = Path.Combine(Path.GetTempPath(), "nullify-webmail-trust-tests-" + Guid.NewGuid().ToString("N"));
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
    public async Task TrustedLogin_SetsASealedCookie_UntrustedDoesNot()
    {
        var plain = _factory.CreateClient();
        var plainResponse = await plain.PostAsJsonAsync("/api/auth/login", new { username = User, password = Password });
        Assert.IsFalse(SetCookies(plainResponse).Any(c => c.StartsWith(TrustedDeviceService.CookieName + "=")));

        var trusted = _factory.CreateClient();
        var response = await trusted.PostAsJsonAsync("/api/auth/login", new { username = User, password = Password, trustDevice = true });
        var device = SetCookies(response).Single(c => c.StartsWith(TrustedDeviceService.CookieName + "="));

        Assert.DoesNotContain(Password, device);
        StringAssert.Contains(device.ToLowerInvariant(), "httponly");
        StringAssert.Contains(device.ToLowerInvariant(), "expires=");
        Assert.AreEqual(HttpStatusCode.OK, (await trusted.GetAsync("/api/auth/session")).StatusCode);
    }

    [TestMethod]
    public async Task TrustedComputer_SignsInAgain_AfterTheSessionIsLost()
    {
        var client = await TrustedClient();
        await DropAllSessions(); // what a server restart does
        Assert.AreEqual(HttpStatusCode.Unauthorized, (await client.GetAsync("/api/auth/session")).StatusCode);

        var page = await LoadPage(client);

        Assert.IsTrue(SetCookies(page).Any(c => c.StartsWith("nullify.webmail.auth=")), "Loading a page should sign in again.");
        Assert.AreEqual(HttpStatusCode.OK, (await client.GetAsync("/api/auth/session")).StatusCode);
    }

    [TestMethod]
    public async Task ApiRequests_DoNotRestore()
    {
        var client = await TrustedClient();
        await DropAllSessions();

        // Only page loads sign in again: an API call, even one that asks for HTML, gets a plain 401.
        var request = new HttpRequestMessage(HttpMethod.Get, "/api/auth/session");
        request.Headers.Add("Accept", "text/html");
        var response = await client.SendAsync(request);

        Assert.AreEqual(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.IsFalse(SetCookies(response).Any(c => c.StartsWith("nullify.webmail.auth=")));
    }

    [TestMethod]
    public async Task SignOut_StopsTrustingTheComputer()
    {
        var client = await TrustedClient();
        var devicesBefore = await DeviceCount();

        await client.PostAsync("/api/auth/logout", null);
        await LoadPage(client);

        Assert.AreEqual(HttpStatusCode.Unauthorized, (await client.GetAsync("/api/auth/session")).StatusCode);
        Assert.AreEqual(devicesBefore - 1, await DeviceCount());
    }

    [TestMethod]
    public async Task RevokedComputer_LosesItsSession_AndCannotSignInAgain()
    {
        var client = await TrustedClient();
        string deviceId;
        await using (var db = await DbAsync())
            deviceId = (await db.TrustedDevices.OrderByDescending(d => d.Id).FirstAsync()).DeviceId;

        using (var scope = _factory.Services.CreateScope())
            await scope.ServiceProvider.GetRequiredService<TrustedDeviceService>().RevokeAsync(User, deviceId);

        Assert.AreEqual(HttpStatusCode.Unauthorized, (await client.GetAsync("/api/auth/session")).StatusCode, "The open session ends.");
        var page = await LoadPage(client);
        Assert.IsTrue(SetCookies(page).Any(c => c.StartsWith(TrustedDeviceService.CookieName + "=;")), "The stale cookie is cleared.");
        Assert.AreEqual(HttpStatusCode.Unauthorized, (await client.GetAsync("/api/auth/session")).StatusCode);
    }

    [TestMethod]
    public async Task ChangedPassword_EndsTheTrust()
    {
        var client = await TrustedClient();
        var devicesBefore = await DeviceCount();
        await DropAllSessions();
        _imap.Password = "changed-elsewhere";

        await LoadPage(client);

        Assert.AreEqual(HttpStatusCode.Unauthorized, (await client.GetAsync("/api/auth/session")).StatusCode);
        Assert.AreEqual(devicesBefore - 1, await DeviceCount());
    }

    [TestMethod]
    public async Task TamperedCookie_IsRefused()
    {
        var client = _factory.CreateClient(new WebApplicationFactoryClientOptions { HandleCookies = false });
        var request = new HttpRequestMessage(HttpMethod.Get, "/m/approve");
        request.Headers.Add("Accept", "text/html");
        request.Headers.Add("Cookie", $"{TrustedDeviceService.CookieName}=CfDJ8not-a-real-sealed-value");

        var response = await client.SendAsync(request);

        Assert.IsFalse(SetCookies(response).Any(c => c.StartsWith("nullify.webmail.auth=")));
    }

    // ------------------------------------------------------------------ helpers

    private static async Task<HttpClient> TrustedClient()
    {
        var client = _factory.CreateClient();
        var response = await client.PostAsJsonAsync("/api/auth/login", new { username = User, password = Password, trustDevice = true });
        response.EnsureSuccessStatusCode();
        Assert.AreEqual(HttpStatusCode.OK, (await client.GetAsync("/api/auth/session")).StatusCode);
        return client;
    }

    // A page that renders without contacting the mail server.
    private static Task<HttpResponseMessage> LoadPage(HttpClient client)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, "/m/approve");
        request.Headers.Add("Accept", "text/html");
        return client.SendAsync(request);
    }

    private static Task DropAllSessions() =>
        _factory.Services.GetRequiredService<MemoryTicketStore>().RemoveSessionsAsync(_ => true);

    private static async Task<AppDbContext> DbAsync() =>
        await _factory.Services.GetRequiredService<IDbContextFactory<AppDbContext>>().CreateDbContextAsync();

    private static async Task<int> DeviceCount()
    {
        await using var db = await DbAsync();
        return await db.TrustedDevices.CountAsync();
    }

    private static IEnumerable<string> SetCookies(HttpResponseMessage response) =>
        response.Headers.TryGetValues("Set-Cookie", out var values) ? values : [];
}
