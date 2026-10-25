// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using System.Net;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.EntityFrameworkCore;
using Nullify.WebMail.Data;
using Nullify.WebMail.Services;
using Nullify.WebMail.Shared;

namespace Nullify.WebMail.Services;

/// <summary>Servers resolved for a user: either from the Domain table or global config.</summary>
public sealed record ResolvedServers(
    ImapEndpoint Imap,
    string SmtpHost, int SmtpPort, MailSecurity SmtpSecurity,
    string SieveHost, int SievePort);

public sealed class AuthService(
    ImapClient imap,
    SettingsService settings,
    IDataProtectionProvider protection,
    IHttpContextAccessor httpContext,
    IDbContextFactory<AppDbContext> dbFactory)
{
    private readonly IDataProtector _protector = protection.CreateProtector("Nullify.WebMail.Credentials.v2");

    public bool HasHttpContext => httpContext.HttpContext != null;

    // ------------------------------------------------------------------ credential blob

    public string ProtectCredential(CredentialInfo cred) =>
        _protector.Protect(JsonSerializer.Serialize(cred));

    public CredentialInfo? UnprotectCredential(string? blob)
    {
        if (string.IsNullOrEmpty(blob)) return null;
        try
        {
            return JsonSerializer.Deserialize<CredentialInfo>(_protector.Unprotect(blob));
        }
        catch
        {
            return null; // stale cookie from an older format
        }
    }

    /// <summary>Read the credential from an arbitrary principal — works inside circuits.</summary>
    public CredentialInfo? GetCredential(System.Security.Claims.ClaimsPrincipal? user) =>
        UnprotectCredential(user?.FindFirst("imap_credential")?.Value);

    /// <summary>Read the credential from the current HTTP request — controllers and prerender only.</summary>
    public CredentialInfo? GetCredential() =>
        GetCredential(httpContext.HttpContext?.User);

    /// <summary>The current HTTP request's user — controllers and prerender only.</summary>
    public System.Security.Claims.ClaimsPrincipal? CurrentUser => httpContext.HttpContext?.User;

    // ------------------------------------------------------------------ server resolution

    /// <summary>
    /// Resolve IMAP/SMTP/Sieve servers for a login name. Domain table wins; global
    /// config is the fallback. Returns null when the domain is not allowed.
    /// </summary>
    public async Task<ResolvedServers?> ResolveServersAsync(string username, CancellationToken ct = default)
    {
        var domain = ExtractDomain(username);
        var s = settings.Current;

        Domain? mapping = null;
        if (!string.IsNullOrEmpty(domain))
        {
            await using var db = await dbFactory.CreateDbContextAsync(ct);
            mapping = await db.Domains.FirstOrDefaultAsync(d => d.Name == domain, ct);

            var restricted = (await db.AdminSettings
                .FirstOrDefaultAsync(x => x.Key == "restrict_domains", ct))?.Value == "true";
            if (restricted && mapping == null)
                return null; // domain not allowed
        }

        var imapHost = FirstNonEmpty(mapping?.ImapHost, s.ImapHost);
        if (string.IsNullOrEmpty(imapHost))
            return null; // nothing configured anywhere

        return new ResolvedServers(
            new ImapEndpoint(
                imapHost,
                mapping?.ImapPort ?? s.ImapPort,
                mapping?.ImapSecurity ?? s.ImapSecurity,
                mapping?.ImapAllowInvalidCertificates ?? s.ImapAllowInvalidCertificates),
            SmtpHost: FirstNonEmpty(mapping?.SmtpHost, s.SmtpHost) ?? imapHost,
            SmtpPort: mapping?.SmtpPort ?? s.SmtpPort,
            SmtpSecurity: mapping?.SmtpSecurity ?? s.SmtpSecurity,
            SieveHost: FirstNonEmpty(mapping?.SieveHost, s.SieveHost) ?? imapHost,
            SievePort: mapping?.SievePort ?? s.SievePort);
    }

    public async Task<ImapResult> VerifyAsync(ImapEndpoint endpoint, string username, string password, CancellationToken ct = default) =>
        await imap.AuthenticateAsync(endpoint, username, password, ct);

    // ------------------------------------------------------------------ user record

    /// <summary>Ensure a User row exists for a successful login; the very first user becomes admin.</summary>
    public async Task UpsertUserAsync(string username, CancellationToken ct = default)
    {
        await using var db = await dbFactory.CreateDbContextAsync(ct);
        var user = await db.Users.FirstOrDefaultAsync(u => u.Username == username, ct);
        if (user == null)
        {
            user = new User
            {
                Username = username,
                Email = username,
                IsAdmin = !await db.Users.AnyAsync(ct),
            };
            db.Users.Add(user);
        }
        user.LastLoginUtc = DateTime.UtcNow;
        await db.SaveChangesAsync(ct);
    }

    // ------------------------------------------------------------------ sign-in / sign-out (HTTP requests only)

    /// <summary>Random id of one signed-in session, so it can be listed or ended (see <see cref="MemoryTicketStore"/>).</summary>
    public const string SessionIdClaim = "nullify_sid";
    /// <summary>Present on sessions a phone approved by QR code: the desktop is treated as less trusted.</summary>
    public const string QrSessionClaim = "nullify_qr";
    /// <summary>Present on sessions from a trusted computer: the <see cref="TrustedDevice"/> it signed in with.</summary>
    public const string TrustedDeviceClaim = "nullify_device";
    /// <summary>Present on sessions signed in with a passkey: the <see cref="Passkey"/> row id.</summary>
    public const string PasskeyClaim = "nullify_passkey";

    public async Task SignInAsync(HttpContext ctx, CredentialInfo cred, string? trustedDeviceId = null, string? passkeyId = null)
    {
        var (principal, properties) = BuildSignIn(cred, qrLifetime: null, trustedDeviceId, passkeyId);
        await ctx.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal, properties);
        ctx.User = principal; // so the rest of this request (e.g. a page prerender) sees the user
    }

    /// <summary>
    /// The principal and cookie properties for a sign-in. A QR sign-in gets a browser-session
    /// cookie with a fixed lifetime that is never extended, instead of the usual sliding 7 days.
    /// </summary>
    public (System.Security.Claims.ClaimsPrincipal, AuthenticationProperties) BuildSignIn(
        CredentialInfo cred, TimeSpan? qrLifetime, string? trustedDeviceId = null, string? passkeyId = null)
    {
        var identity = new System.Security.Claims.ClaimsIdentity(CookieAuthenticationDefaults.AuthenticationScheme);
        identity.AddClaim(new System.Security.Claims.Claim(System.Security.Claims.ClaimTypes.Name, cred.Login));
        identity.AddClaim(new System.Security.Claims.Claim(System.Security.Claims.ClaimTypes.NameIdentifier, cred.Login));
        identity.AddClaim(new System.Security.Claims.Claim("imap_credential", ProtectCredential(cred)));
        identity.AddClaim(new System.Security.Claims.Claim(SessionIdClaim, Convert.ToHexString(System.Security.Cryptography.RandomNumberGenerator.GetBytes(16))));
        if (trustedDeviceId != null && qrLifetime == null)
            identity.AddClaim(new System.Security.Claims.Claim(TrustedDeviceClaim, trustedDeviceId));
        if (passkeyId != null)
            identity.AddClaim(new System.Security.Claims.Claim(PasskeyClaim, passkeyId));

        if (qrLifetime is { } lifetime)
        {
            var expires = DateTimeOffset.UtcNow + lifetime;
            identity.AddClaim(new System.Security.Claims.Claim(QrSessionClaim, expires.ToUnixTimeSeconds().ToString()));
            return (new System.Security.Claims.ClaimsPrincipal(identity), new AuthenticationProperties
            {
                IsPersistent = false,
                ExpiresUtc = expires,
                AllowRefresh = false,
            });
        }

        return (new System.Security.Claims.ClaimsPrincipal(identity), new AuthenticationProperties
        {
            IsPersistent = true,
            ExpiresUtc = DateTimeOffset.UtcNow.AddDays(7),
            AllowRefresh = true,
        });
    }

    public async Task SignOutAsync(HttpContext ctx) =>
        await ctx.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

    // ------------------------------------------------------------------ legacy JSON API path (controllers)

    public async Task<LoginResult> LoginAsync(string username, string password, CancellationToken ct = default)
    {
        var (result, cred) = await VerifyLoginAsync(username, password, ct);
        var ctx = httpContext.HttpContext;
        if (cred != null && ctx != null)
            await SignInAsync(ctx, cred);
        return result;
    }

    /// <summary>
    /// Check a username and password against the user's IMAP server and record the login.
    /// Returns the credential to sign in with, without signing anyone in: the QR flow
    /// signs in a different browser from the one that sent the password.
    /// </summary>
    public async Task<(LoginResult Result, CredentialInfo? Credential)> VerifyLoginAsync(string username, string password, CancellationToken ct = default)
    {
        username = username.Trim();
        if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(password))
            return (new LoginResult(false, "Username and password are required."), null);

        var servers = await ResolveServersAsync(username, ct);
        if (servers == null)
            return (new LoginResult(false, DomainRestrictedMessage(username)), null);

        var result = await VerifyAsync(servers.Imap, username, password, ct);
        if (result != ImapResult.Success)
            return (new LoginResult(false, "Invalid credentials or IMAP server unavailable."), null);

        await UpsertUserAsync(username, ct);
        return (new LoginResult(true, null), BuildCredential(username, password, servers));
    }

    /// <summary>
    /// First-run setup: authenticate against the servers submitted on the form (not global
    /// config, which is empty on a fresh install), create the domain mapping, and make the
    /// user an admin.
    /// </summary>
    public async Task<LoginResult> SetupAsync(
        string username, string password,
        string imapHost, int imapPort, MailSecurity imapSecurity,
        string? smtpHost, int smtpPort, MailSecurity smtpSecurity,
        CancellationToken ct = default)
    {
        username = username.Trim();
        imapHost = imapHost.Trim();
        if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(password))
            return new LoginResult(false, "Username and password are required.");
        if (string.IsNullOrWhiteSpace(imapHost))
            return new LoginResult(false, "IMAP host is required.");

        await using var db = await dbFactory.CreateDbContextAsync(ct);
        if (await db.Users.AnyAsync(ct))
            return new LoginResult(false, "Setup has already been completed.");

        var endpoint = new ImapEndpoint(imapHost, imapPort > 0 ? imapPort : 993, imapSecurity, false);
        var result = await imap.AuthenticateAsync(endpoint, username, password, ct);
        if (result != ImapResult.Success)
            return new LoginResult(false, "Invalid credentials or IMAP server unreachable.");

        var domain = ExtractDomain(username);
        if (!string.IsNullOrEmpty(domain) && !await db.Domains.AnyAsync(d => d.Name == domain, ct))
        {
            db.Domains.Add(new Domain
            {
                Name = domain,
                ImapHost = imapHost,
                ImapPort = endpoint.Port,
                ImapSecurity = imapSecurity,
                SmtpHost = string.IsNullOrWhiteSpace(smtpHost) ? null : smtpHost.Trim(),
                SmtpPort = smtpPort > 0 ? smtpPort : null,
                SmtpSecurity = smtpSecurity,
            });
        }

        db.Users.Add(new User
        {
            Username = username,
            Email = username,
            IsAdmin = true,
            LastLoginUtc = DateTime.UtcNow,
        });
        await db.SaveChangesAsync(ct);

        var servers = new ResolvedServers(
            endpoint,
            FirstNonEmpty(smtpHost, imapHost)!,
            smtpPort > 0 ? smtpPort : 587,
            smtpSecurity,
            imapHost,
            settings.Current.SievePort);

        var ctx = httpContext.HttpContext;
        if (ctx != null)
            await SignInAsync(ctx, BuildCredential(username, password, servers));

        return new LoginResult(true, null);
    }

    // ------------------------------------------------------------------ helpers

    public static CredentialInfo BuildCredential(string username, string password, ResolvedServers s) => new(
        s.Imap.Host, s.Imap.Port, s.Imap.Security, s.Imap.AllowInvalidCertificates,
        username, password,
        s.SmtpHost, s.SmtpPort, s.SmtpSecurity,
        s.SieveHost, s.SievePort);

    private string DomainRestrictedMessage(string username)
    {
        var domain = ExtractDomain(username);
        return domain != null
            ? $"The domain '@{domain}' is not supported by this server, or no mail server is configured."
            : "No mail server is configured for this account.";
    }

    public static string? ExtractDomain(string username)
    {
        var at = username.IndexOf('@');
        return at > 0 && at < username.Length - 1 ? username[(at + 1)..].ToLowerInvariant() : null;
    }

    private static string? FirstNonEmpty(params string?[] values) =>
        values.FirstOrDefault(v => !string.IsNullOrWhiteSpace(v));
}

public sealed record LoginResult(bool Success, string? Error);

public sealed record CredentialInfo(
    string Host, int Port, MailSecurity Security, bool AllowInvalidCertificates,
    string Login, string Password,
    string SmtpHost, int SmtpPort, MailSecurity SmtpSecurity,
    string SieveHost, int SievePort);