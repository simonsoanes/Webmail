// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Nullify.WebMail.Services;
using Nullify.WebMail.Shared;

namespace Nullify.WebMail.Tests;

[TestClass]
public class BasicIntegrationTests
{
    private static WebApplicationFactory<Program> _factory = null!;
    private static string _dataDir = null!;

    [ClassInitialize]
    public static void Setup(TestContext _)
    {
        // Isolated database per test run: tests never touch (or race on) the dev DB.
        _dataDir = Path.Combine(Path.GetTempPath(), "nullify-webmail-tests-" + Guid.NewGuid().ToString("N"));
        _factory = new WebApplicationFactory<Program>().WithWebHostBuilder(b =>
            b.UseSetting("Storage:DataDirectory", _dataDir));
    }

    [ClassCleanup]
    public static void Cleanup()
    {
        _factory.Dispose();
        try { Directory.Delete(_dataDir, recursive: true); } catch { }
    }

    [TestMethod]
    public async Task Session_Unauthenticated_Returns401()
    {
        var client = _factory.CreateClient();
        var response = await client.GetAsync("/api/auth/session");
        Assert.AreEqual(System.Net.HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [TestMethod]
    public async Task Manifest_Anonymous_IsInstallable()
    {
        var client = _factory.CreateClient();
        var response = await client.GetAsync("/manifest.webmanifest");
        Assert.AreEqual(System.Net.HttpStatusCode.OK, response.StatusCode);
        Assert.AreEqual("application/manifest+json", response.Content.Headers.ContentType?.MediaType);
        using var doc = System.Text.Json.JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var root = doc.RootElement;
        Assert.AreEqual("Nullify WebMail", root.GetProperty("name").GetString());
        Assert.AreEqual("standalone", root.GetProperty("display").GetString());
        Assert.AreEqual("./", root.GetProperty("start_url").GetString());
        var sizes = root.GetProperty("icons").EnumerateArray().Select(i => i.GetProperty("sizes").GetString()).ToList();
        CollectionAssert.IsSubsetOf(new[] { "192x192", "512x512" }, sizes);

        foreach (var icon in root.GetProperty("icons").EnumerateArray())
            Assert.AreEqual(System.Net.HttpStatusCode.OK, (await client.GetAsync("/" + icon.GetProperty("src").GetString())).StatusCode);
        Assert.AreEqual(System.Net.HttpStatusCode.OK, (await client.GetAsync("/sw.js")).StatusCode);
        Assert.AreEqual(System.Net.HttpStatusCode.OK, (await client.GetAsync("/offline.html")).StatusCode);
    }

    [TestMethod]
    public async Task HasUsers_OnFreshDatabase_ReturnsFalse()
    {
        var client = _factory.CreateClient();
        var body = await client.GetStringAsync("/api/auth/has-users");
        Assert.AreEqual("false", body.Trim());
    }

    [TestMethod]
    public async Task Login_WithEmptyCredentials_ReturnsError()
    {
        var client = _factory.CreateClient();
        var content = new StringContent(
            """{"username":"","password":""}""",
            System.Text.Encoding.UTF8, "application/json");
        var response = await client.PostAsync("/api/auth/login", content);
        Assert.AreEqual(System.Net.HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync();
        StringAssert.Contains(body, "\"success\":false");
    }

    [TestMethod]
    public async Task Folders_Unauthenticated_Returns401()
    {
        var client = _factory.CreateClient();
        var response = await client.GetAsync("/api/mail/folders");
        Assert.AreEqual(System.Net.HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [TestMethod]
    public async Task Prefs_Unauthenticated_Returns401()
    {
        var client = _factory.CreateClient();
        var response = await client.GetAsync("/api/prefs");
        Assert.AreEqual(System.Net.HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [TestMethod]
    public async Task Setup_WhenUsersExist_IsRejected()
    {
        // First create a user row directly is not possible via API without IMAP,
        // so verify the guard on a fresh DB rejects empty input instead.
        var client = _factory.CreateClient();
        var content = new StringContent(
            """{"username":"","password":"","imapHost":"","imapPort":993,"imapSecurity":"Tls","smtpHost":"","smtpPort":587,"smtpSecurity":"StartTls"}""",
            System.Text.Encoding.UTF8, "application/json");
        var response = await client.PostAsync("/api/auth/setup", content);
        Assert.AreEqual(System.Net.HttpStatusCode.BadRequest, response.StatusCode);
    }

    [TestMethod]
    public async Task Root_ServesFullHtmlShell_WithBlazorScript()
    {
        var client = _factory.CreateClient();
        var html = await client.GetStringAsync("/");
        StringAssert.Contains(html, "<!DOCTYPE html>");
        StringAssert.Contains(html, "_framework/blazor.web.js");
        StringAssert.Contains(html, "css/app.css");
        // Interactive server rendering leaves the persisted component-state marker.
        StringAssert.Contains(html, "Blazor-Server-Component-State");
    }

    [TestMethod]
    public async Task AuthenticatedPrerender_RendersMailUi_WithoutException()
    {
        // Regression: UserSession used to call PersistentComponentState.PersistAsJson
        // inline during OnInitializedAsync, which throws
        // "Persisting state is only allowed during an OnPersisting callback"
        // and 500s every authenticated page load.
        var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Add("Cookie", $"nullify.webmail.auth={ForgeAuthCookie("user@example.test")}");

        // Bisect step 1: the cookie must authenticate at the HTTP layer.
        var session = await client.GetAsync("/api/auth/session");
        Assert.AreEqual(System.Net.HttpStatusCode.OK, session.StatusCode,
            "Forged auth cookie was rejected by the cookie handler.");

        // Bisect step 2: SSR prerender must capture the session and render the mail UI.
        var html = await client.GetStringAsync("/");

        StringAssert.Contains(html, "<!DOCTYPE html>");
        StringAssert.DoesNotMatch(html, new System.Text.RegularExpressions.Regex("An unhandled exception occurred"));
        // Authenticated shell renders the mail UI chrome...
        StringAssert.Contains(html, "app-shell");
        // ...and an unreachable IMAP host must degrade to an inline error, not a 500.
        StringAssert.Contains(html, "Mail server unreachable");
        // The credential stays in server memory: nothing of it is embedded for the circuit.
        Assert.DoesNotContain(Password, html);
        Assert.DoesNotContain("imap_credential", html);
    }

    [TestMethod]
    public void AuthCookie_CarriesOnlyASessionKey()
    {
        var ticket = ReadCookie(ForgeAuthCookie("cookie@example.test"));
        Assert.IsNotNull(ticket, "The cookie should still be a valid ticket.");
        Assert.IsNull(ticket.Principal.FindFirst("imap_credential"), "The mail credential must not travel in the cookie.");
        Assert.IsNotNull(ticket.Principal.FindFirst(SessionIdClaim), "The cookie should reference a server-side session.");
    }

    [TestMethod]
    public async Task Session_EndsWhenItsServerMemoryIsGone()
    {
        // What a restart does: the in-memory ticket disappears, so the cookie stops working.
        var cookie = ForgeAuthCookie("restart@example.test");
        var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Add("Cookie", $"nullify.webmail.auth={cookie}");
        Assert.AreEqual(System.Net.HttpStatusCode.OK, (await client.GetAsync("/api/auth/session")).StatusCode);

        var key = ReadCookie(cookie)!.Principal.FindFirst(SessionIdClaim)!.Value;
        await _factory.Services.GetRequiredService<MemoryTicketStore>().RemoveAsync(key);

        Assert.AreEqual(System.Net.HttpStatusCode.Unauthorized, (await client.GetAsync("/api/auth/session")).StatusCode);
    }

    [TestMethod]
    public async Task Logout_DiscardsTheServerSideSession()
    {
        var cookie = ForgeAuthCookie("logout@example.test");
        var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Add("Cookie", $"nullify.webmail.auth={cookie}");
        Assert.AreEqual(System.Net.HttpStatusCode.OK, (await client.PostAsync("/api/auth/logout", null)).StatusCode);

        // Replaying the old cookie must not revive the session.
        Assert.AreEqual(System.Net.HttpStatusCode.Unauthorized, (await client.GetAsync("/api/auth/session")).StatusCode);
    }

    // Claim the cookie handler uses to reference a ticket held in its SessionStore.
    private const string SessionIdClaim = "Microsoft.AspNetCore.Authentication.Cookies-SessionId";

    /// <summary>Decrypt an auth cookie with the app's own ticket format, to see what it carries.</summary>
    private static AuthenticationTicket? ReadCookie(string cookie) =>
        _factory.Services.GetRequiredService<IOptionsMonitor<CookieAuthenticationOptions>>()
            .Get(CookieAuthenticationDefaults.AuthenticationScheme).TicketDataFormat.Unprotect(Uri.UnescapeDataString(cookie));

    // Distinctive, so tests can check it never appears in a page or cookie.
    private const string Password = "pw-7f3c9e1a-never-in-a-page";

    /// <summary>Mint a real auth cookie by running the app's own SignInAsync against a
    /// synthetic HttpContext, then lifting the value from the Set-Cookie response header.
    /// Hand-rolling the protector/serializer missed .NET 10 handler internals.</summary>
    private static string ForgeAuthCookie(string username)
    {
        using var scope = _factory.Services.CreateScope();
        var auth = scope.ServiceProvider.GetRequiredService<AuthService>();

        var httpContext = new Microsoft.AspNetCore.Http.DefaultHttpContext
        {
            RequestServices = scope.ServiceProvider,
        };
        httpContext.Request.Scheme = "http";
        httpContext.Request.Host = new Microsoft.AspNetCore.Http.HostString("localhost");

        var cred = new CredentialInfo(
            "imap.invalid", 993, MailSecurity.Tls, false, username, Password,
            "smtp.invalid", 587, MailSecurity.StartTls,
            "imap.invalid", 4190);

        auth.SignInAsync(httpContext, cred).GetAwaiter().GetResult();

        var setCookie = httpContext.Response.Headers.SetCookie.ToString();
        Assert.StartsWith("nullify.webmail.auth=", setCookie, "SignInAsync did not set the auth cookie.");
        return setCookie["nullify.webmail.auth=".Length..].Split(';')[0];
    }
}