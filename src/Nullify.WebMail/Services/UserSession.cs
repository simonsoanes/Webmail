// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.EntityFrameworkCore;
using Nullify.WebMail.Data;

namespace Nullify.WebMail.Services;

/// <summary>
/// Scoped snapshot of the authenticated user.
/// The credential lives only in the server's in-memory session store (<see cref="MemoryTicketStore"/>);
/// the cookie carries a session key, and nothing about the credential is written into the page.
/// Prerender and controllers read it from the request's user. An interactive circuit (a fresh DI
/// scope with no HttpContext) reads it from the authentication state, which ASP.NET Core resolves
/// from the same store when the circuit's connection is authenticated.
/// </summary>
public sealed class UserSession(
    AuthService auth,
    AuthenticationStateProvider authState,
    IDbContextFactory<AppDbContext> dbFactory)
{
    public CredentialInfo? Credential { get; private set; }
    public bool IsAdmin { get; private set; }
    public bool IsAuthenticated => Credential != null;

    /// <summary>Id of this signed-in session (<see cref="AuthService.SessionIdClaim"/>).</summary>
    public string? SessionId { get; private set; }

    /// <summary>
    /// When a phone signed this browser in by QR code: the session ends at this time. The user chose
    /// that route because they don't fully trust this device, so secrets typed here deserve a warning.
    /// </summary>
    public DateTimeOffset? QrSessionExpiresUtc { get; private set; }
    public bool IsQrSession => QrSessionExpiresUtc != null;

    /// <summary>When this browser is a trusted computer: its <see cref="Data.TrustedDevice"/> id.</summary>
    public string? TrustedDeviceId { get; private set; }

    public async Task CaptureAsync(CancellationToken ct = default)
    {
        if (Credential != null) return;

        var user = auth.HasHttpContext
            ? auth.CurrentUser
            : (await authState.GetAuthenticationStateAsync()).User;
        var cred = auth.GetCredential(user);
        if (cred == null) return;

        SessionId = user?.FindFirst(AuthService.SessionIdClaim)?.Value;
        TrustedDeviceId = user?.FindFirst(AuthService.TrustedDeviceClaim)?.Value;
        if (long.TryParse(user?.FindFirst(AuthService.QrSessionClaim)?.Value, out var expires))
            QrSessionExpiresUtc = DateTimeOffset.FromUnixTimeSeconds(expires);
        await ApplyAsync(cred, ct);
    }

    /// <summary>The session was ended elsewhere (revoked from the phone, or timed out): stop using the credential.</summary>
    public void End() => Credential = null;

    private async Task ApplyAsync(CredentialInfo cred, CancellationToken ct)
    {
        Credential = cred;
        await using var db = await dbFactory.CreateDbContextAsync(ct);
        IsAdmin = await db.Users
            .Where(u => u.Username == cred.Login)
            .Select(u => u.IsAdmin)
            .FirstOrDefaultAsync(ct);
    }
}
