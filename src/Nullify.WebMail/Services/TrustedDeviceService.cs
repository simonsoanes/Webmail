// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Nullify.WebMail.Data;

namespace Nullify.WebMail.Services;

/// <summary>A trusted computer as listed in Settings.</summary>
public sealed record TrustedDeviceInfo(string DeviceId, string Name, DateTime CreatedUtc, DateTime LastUsedUtc, DateTime ExpiresUtc);

/// <summary>
/// "I trust this computer": the opposite of signing in by QR code. The browser keeps the mail
/// login in an HttpOnly cookie, encrypted and authenticated with the server's key ring, so it
/// can sign in again after the server restarts or the session cookie expires. The browser
/// can't read the cookie and the server keeps no copy of the password between sessions.
/// Each cookie names a <see cref="TrustedDevice"/> row, and without that row the cookie is
/// refused, so a computer can be revoked from Settings.
/// </summary>
public sealed class TrustedDeviceService(
    AuthService auth,
    IDataProtectionProvider protection,
    IDbContextFactory<AppDbContext> dbFactory,
    MemoryTicketStore tickets,
    IConfiguration config,
    ILogger<TrustedDeviceService> logger)
{
    public const string CookieName = "nullify.webmail.device";

    private readonly ITimeLimitedDataProtector _protector =
        protection.CreateProtector("Nullify.WebMail.TrustedDevice.v1").ToTimeLimitedDataProtector();

    /// <summary>How long a trusted computer stays signed in without being used. Each sign-in from it starts the period again.</summary>
    public TimeSpan Lifetime => TimeSpan.FromDays(Math.Clamp(config.GetValue("TrustedDevice:Days", 30), 1, 365));

    private sealed record Sealed(string DeviceId, string Login, string Password);

    /// <summary>Register this browser as trusted after a password sign-in. Returns the device id for the session's claim.</summary>
    public async Task<string> TrustAsync(HttpContext ctx, string login, string password, CancellationToken ct = default)
    {
        await using var db = await dbFactory.CreateDbContextAsync(ct);
        var user = await db.Users.FirstAsync(u => u.Username == login, ct);

        // Signing in again on a computer that is already trusted replaces its old entry.
        if (ReadCookie(ctx) is { } old)
            await db.TrustedDevices.Where(d => d.DeviceId == old.DeviceId).ExecuteDeleteAsync(ct);

        var device = new TrustedDevice
        {
            UserId = user.Id,
            DeviceId = Convert.ToHexString(RandomNumberGenerator.GetBytes(16)),
            Name = QrLoginService.DescribeUserAgent(ctx.Request.Headers.UserAgent.ToString()),
            ExpiresUtc = DateTime.UtcNow + Lifetime,
        };
        db.TrustedDevices.Add(device);
        await db.SaveChangesAsync(ct);

        WriteCookie(ctx, new Sealed(device.DeviceId, login, password), device.ExpiresUtc);
        return device.DeviceId;
    }

    /// <summary>
    /// Sign in from this browser's trusted-computer cookie, for a request that has no session.
    /// The password is checked with the mail server again; if it was rejected (changed, say),
    /// the computer stops being trusted. If the server can't be reached, the user is signed in
    /// anyway and the mail view reports it.
    /// </summary>
    public async Task<bool> TryRestoreAsync(HttpContext ctx, CancellationToken ct = default)
    {
        var sealedLogin = ReadCookie(ctx);
        if (sealedLogin == null)
        {
            DeleteCookie(ctx);
            return false;
        }

        await using var db = await dbFactory.CreateDbContextAsync(ct);
        var device = await db.TrustedDevices.Include(d => d.User)
            .FirstOrDefaultAsync(d => d.DeviceId == sealedLogin.DeviceId, ct);
        if (device == null || device.User?.Username != sealedLogin.Login || device.ExpiresUtc < DateTime.UtcNow)
        {
            if (device != null) db.TrustedDevices.Remove(device);
            await db.SaveChangesAsync(ct);
            DeleteCookie(ctx);
            return false;
        }

        // Servers are resolved again, so a changed domain mapping applies.
        var servers = await auth.ResolveServersAsync(sealedLogin.Login, ct);
        var result = servers == null
            ? ImapResult.InvalidCredentials
            : await auth.VerifyAsync(servers.Imap, sealedLogin.Login, sealedLogin.Password, ct);
        if (result == ImapResult.InvalidCredentials)
        {
            logger.LogInformation("Trusted computer {Device} for {Login} no longer signs in; forgetting it", device.DeviceId, sealedLogin.Login);
            db.TrustedDevices.Remove(device);
            await db.SaveChangesAsync(ct);
            DeleteCookie(ctx);
            return false;
        }

        device.LastUsedUtc = DateTime.UtcNow;
        device.ExpiresUtc = DateTime.UtcNow + Lifetime;
        await db.SaveChangesAsync(ct);
        WriteCookie(ctx, sealedLogin, device.ExpiresUtc);

        await auth.UpsertUserAsync(sealedLogin.Login, ct);
        await auth.SignInAsync(ctx, AuthService.BuildCredential(sealedLogin.Login, sealedLogin.Password, servers!), device.DeviceId);
        return true;
    }

    /// <summary>On sign-out: this computer stops being trusted.</summary>
    public async Task ForgetAsync(HttpContext ctx, CancellationToken ct = default)
    {
        var deviceId = ctx.User.FindFirst(AuthService.TrustedDeviceClaim)?.Value ?? ReadCookie(ctx)?.DeviceId;
        if (deviceId != null)
        {
            await using var db = await dbFactory.CreateDbContextAsync(ct);
            await db.TrustedDevices.Where(d => d.DeviceId == deviceId).ExecuteDeleteAsync(ct);
        }
        DeleteCookie(ctx);
    }

    public async Task<List<TrustedDeviceInfo>> ListAsync(string login, CancellationToken ct = default)
    {
        await using var db = await dbFactory.CreateDbContextAsync(ct);
        return await db.TrustedDevices
            .Where(d => d.User!.Username == login && d.ExpiresUtc > DateTime.UtcNow)
            .OrderByDescending(d => d.LastUsedUtc)
            .Select(d => new TrustedDeviceInfo(d.DeviceId, d.Name, d.CreatedUtc, d.LastUsedUtc, d.ExpiresUtc))
            .ToListAsync(ct);
    }

    /// <summary>Stop trusting a computer, and end any session it has open now.</summary>
    public async Task RevokeAsync(string login, string deviceId, CancellationToken ct = default)
    {
        await using (var db = await dbFactory.CreateDbContextAsync(ct))
            await db.TrustedDevices.Where(d => d.DeviceId == deviceId && d.User!.Username == login).ExecuteDeleteAsync(ct);
        await tickets.RemoveSessionsAsync(p => p.FindFirst(AuthService.TrustedDeviceClaim)?.Value == deviceId);
    }

    // ------------------------------------------------------------------ cookie

    private Sealed? ReadCookie(HttpContext ctx)
    {
        var value = ctx.Request.Cookies[CookieName];
        if (string.IsNullOrEmpty(value)) return null;
        try
        {
            return JsonSerializer.Deserialize<Sealed>(_protector.Unprotect(value));
        }
        catch (Exception ex) when (ex is CryptographicException or JsonException)
        {
            return null; // expired, tampered with, or sealed by a key ring we no longer have
        }
    }

    private void WriteCookie(HttpContext ctx, Sealed value, DateTime expiresUtc) =>
        ctx.Response.Cookies.Append(CookieName,
            _protector.Protect(JsonSerializer.Serialize(value), new DateTimeOffset(expiresUtc, TimeSpan.Zero)),
            CookieOptions(ctx, expiresUtc));

    private static void DeleteCookie(HttpContext ctx)
    {
        if (ctx.Request.Cookies.ContainsKey(CookieName))
            ctx.Response.Cookies.Delete(CookieName, CookieOptions(ctx, null));
    }

    private static CookieOptions CookieOptions(HttpContext ctx, DateTime? expiresUtc) => new()
    {
        HttpOnly = true,
        Secure = ctx.Request.IsHttps,
        // Lax, so opening the site from a link or bookmark can sign in.
        SameSite = SameSiteMode.Lax,
        Path = ctx.Request.PathBase.HasValue ? ctx.Request.PathBase.Value : "/",
        Expires = expiresUtc is { } e ? new DateTimeOffset(e, TimeSpan.Zero) : null,
        IsEssential = true,
    };
}
