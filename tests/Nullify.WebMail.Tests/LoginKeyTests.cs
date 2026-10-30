// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Nullify.WebMail.Services;
using Nullify.WebMail.Shared;

namespace Nullify.WebMail.Tests;

/// <summary>One-time sign-in keys: typed in place of the password, used once, gone after half an hour at most.</summary>
[TestClass]
public class LoginKeyTests
{
    private const string User = "keyed@example.test";
    private const string Password = "pw-sealed-under-a-one-time-key";

    private static WebApplicationFactory<Program> _factory = null!;
    private static FakeImapServer _imap = null!;
    private static string _dataDir = null!;

    [ClassInitialize]
    public static void Setup(TestContext _)
    {
        _imap = new FakeImapServer(User, Password);
        _dataDir = Path.Combine(Path.GetTempPath(), "nullify-webmail-loginkey-tests-" + Guid.NewGuid().ToString("N"));
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

    private static LoginKeyService NewService() => new(NullLogger<LoginKeyService>.Instance);

    [TestMethod]
    public void Key_IsGroupsOfUnambiguousSymbols()
    {
        var key = NewService().Create(User, Password, TimeSpan.FromMinutes(5)).Key;
        Assert.MatchesRegex(@"^[2-9A-HJ-NP-Z]{4}(-[2-9A-HJ-NP-Z]{4}){3}$", key);
    }

    [TestMethod]
    public void Redeem_UnlocksThePassword_Once_AndForgivesCaseAndSpacing()
    {
        var keys = NewService();
        var key = keys.Create(User, Password, TimeSpan.FromMinutes(5)).Key;
        var typed = " " + key.Replace("-", " ").ToLowerInvariant() + " ";

        Assert.AreEqual(Password, keys.Redeem(User.ToUpperInvariant(), typed));
        Assert.IsNull(keys.Redeem(User, key), "A key works once.");
        Assert.IsEmpty(keys.List(User));
    }

    [TestMethod]
    public void Redeem_RefusesOtherAccounts_AndWrongKeys()
    {
        var keys = NewService();
        var key = keys.Create(User, Password, TimeSpan.FromMinutes(5)).Key;

        Assert.IsNull(keys.Redeem("someone@example.test", key));
        Assert.IsNull(keys.Redeem(User, "2222-2222-2222-2222"));
        Assert.IsNull(keys.Redeem(User, Password));
        Assert.AreEqual(Password, keys.Redeem(User, key), "Failed attempts by others don't use the key up.");
    }

    [TestMethod]
    public void Revoke_OneOrAll()
    {
        var keys = NewService();
        var a = keys.Create(User, Password, TimeSpan.FromMinutes(5));
        var b = keys.Create(User, Password, TimeSpan.FromMinutes(5));
        keys.Create(User, Password, TimeSpan.FromMinutes(5));

        Assert.AreEqual(1, keys.Revoke(User, a.Id));
        Assert.IsNull(keys.Redeem(User, a.Key));
        Assert.HasCount(2, keys.List(User));
        Assert.AreEqual(2, keys.Revoke(User));
        Assert.IsNull(keys.Redeem(User, b.Key));
    }

    [TestMethod]
    public void Lifetime_IsCappedAtThirtyMinutes_AndKeysPerAccountAreLimited()
    {
        var keys = NewService();
        var made = keys.Create(User, Password, TimeSpan.FromHours(5));
        Assert.IsLessThanOrEqualTo(LoginKeyService.MaxLifetime + TimeSpan.FromSeconds(5), made.ExpiresUtc - DateTime.UtcNow);

        for (var i = 1; i < LoginKeyService.MaxPerUser; i++) keys.Create(User, Password, TimeSpan.FromMinutes(5));
        Assert.ThrowsExactly<InvalidOperationException>(() => keys.Create(User, Password, TimeSpan.FromMinutes(5)));
    }

    [TestMethod]
    public async Task Login_WithAKey_SignsIn_InABrowserSessionCookie_AndNeverTrusts()
    {
        var key = _factory.Services.GetRequiredService<LoginKeyService>().Create(User, Password, TimeSpan.FromMinutes(5)).Key;
        var client = _factory.CreateClient();

        var response = await client.PostAsJsonAsync("/api/auth/login", new { username = User, password = key, trustDevice = true });
        var result = await response.Content.ReadFromJsonAsync<LoginResponse>();

        Assert.IsTrue(result!.Success, result.Error);
        var cookies = response.Headers.TryGetValues("Set-Cookie", out var values) ? values.ToList() : [];
        var auth = cookies.Single(c => c.StartsWith("nullify.webmail.auth="));
        Assert.DoesNotContain("expires=", auth.ToLowerInvariant(), "A key sign-in ends when the browser closes.");
        Assert.IsFalse(cookies.Any(c => c.StartsWith(TrustedDeviceService.CookieName + "=")));
        Assert.AreEqual(HttpStatusCode.OK, (await client.GetAsync("/api/auth/session")).StatusCode);

        var again = await _factory.CreateClient().PostAsJsonAsync("/api/auth/login", new { username = User, password = key });
        Assert.IsFalse((await again.Content.ReadFromJsonAsync<LoginResponse>())!.Success, "The key was used up.");
    }

    [TestMethod]
    public async Task Login_WithThePassword_StillWorks()
    {
        var response = await _factory.CreateClient().PostAsJsonAsync("/api/auth/login", new { username = User, password = Password });
        Assert.IsTrue((await response.Content.ReadFromJsonAsync<LoginResponse>())!.Success);
    }
}
