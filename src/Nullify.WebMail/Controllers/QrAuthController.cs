// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Nullify.WebMail.Services;
using Nullify.WebMail.Shared;

namespace Nullify.WebMail.Controllers;

/// <summary>
/// Sign in a desktop from a phone (see <see cref="QrLoginService"/>). The desktop calls start and
/// redeem; the phone calls describe, confirm and approve, and later lists or revokes the desktop
/// sessions it approved. The password only ever arrives in approve, from the phone.
/// </summary>
[ApiController]
[Route("api/auth/qr")]
[AllowAnonymous]
[EnableRateLimiting(RateLimitPolicy)]
public class QrAuthController(QrLoginService qr, AuthService auth, PasskeyService passkeys, SettingsService settings) : ControllerBase
{
    public const string RateLimitPolicy = "qr";
    public const string StartRateLimitPolicy = "qr-start";
    public const string BindCookie = "nullify.webmail.qr";

    private string? ClientIp => HttpContext.Connection.RemoteIpAddress?.ToString();

    // ------------------------------------------------------------------ desktop

    [HttpPost("start")]
    [EnableRateLimiting(StartRateLimitPolicy)]
    public QrStartResponse Start()
    {
        var (id, bind, code, expires) = qr.Start(Request.Headers.UserAgent.ToString(), ClientIp);

        // Proves on redeem that it's this browser collecting the session, not whoever photographed the code.
        Response.Cookies.Append(BindCookie, bind, new CookieOptions
        {
            HttpOnly = true,
            Secure = Request.IsHttps,
            SameSite = SameSiteMode.Strict,
            Path = Request.PathBase + "/api/auth/qr",
            MaxAge = TimeSpan.FromMinutes(10),
        });

        var baseUrl = settings.Current.PublicUrl ?? $"{Request.Scheme}://{Request.Host}{Request.PathBase}";
        // The id goes in the fragment, so it never appears in access logs or Referer headers.
        return new QrStartResponse(id, code, expires, $"{baseUrl}/m/approve#{id}");
    }

    [HttpPost("{id}/redeem")]
    public async Task<LoginResponse> Redeem(string id)
    {
        var signIn = qr.Redeem(id, Request.Cookies[BindCookie]);
        if (signIn == null)
            return new LoginResponse(false, "This sign-in request has expired. Scan a new code.");

        Response.Cookies.Delete(BindCookie, new CookieOptions { Path = Request.PathBase + "/api/auth/qr" });
        await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, signIn.Value.Principal, signIn.Value.Properties);
        return new LoginResponse(true, null);
    }

    // ------------------------------------------------------------------ phone

    [HttpPost("{id}/describe")]
    public ActionResult<QrDescription> Describe(string id) =>
        qr.Describe(id, ClientIp) is { } d ? d : NotFound(new LoginResponse(false, ExpiredMessage));

    [HttpPost("{id}/confirm")]
    public QrConfirmResponse Confirm(string id, [FromBody] QrConfirmRequest request) =>
        qr.Confirm(id, request.Code) is { } phoneToken
            ? new QrConfirmResponse(true, phoneToken, null)
            : new QrConfirmResponse(false, null,
                "That isn't the number on the computer, so this sign-in has been cancelled. If you're signing in yourself, scan the new code on the computer's screen. If you didn't start this, someone may be trying to get you to sign them in.");

    [HttpPost("{id}/approve")]
    public async Task<QrApproveResponse> Approve(string id, [FromBody] QrApproveRequest request)
    {
        // Check the request before the password, so this endpoint can't be used to test passwords.
        if (!qr.CanApprove(id, request.PhoneToken))
            return new QrApproveResponse(false, ExpiredMessage, null, null, null);

        var (result, cred) = await auth.VerifyLoginAsync(request.Username ?? "", request.Password ?? "", HttpContext.RequestAborted);
        if (cred == null)
        {
            var retry = qr.RecordFailedPassword(id);
            return new QrApproveResponse(false,
                retry ? result.Error : "Too many failed attempts. Scan a new code on the computer to try again.",
                null, null, null);
        }

        var (principal, properties) = auth.BuildSignIn(cred, qr.SessionLifetime);
        var revokeToken = qr.Approve(id, request.PhoneToken!, principal, properties);
        return revokeToken == null
            ? new QrApproveResponse(false, ExpiredMessage, null, null, null)
            : new QrApproveResponse(true, null, revokeToken, cred.Login, properties.ExpiresUtc);
    }

    /// <summary>
    /// Approve with a passkey on the phone instead of the password. The phone runs the ceremony
    /// (options from <see cref="PasskeyController"/>), so the key that unlocks the password only
    /// exists on the phone and the server; the computer still receives just a session cookie.
    /// </summary>
    [HttpPost("{id}/approve-passkey")]
    public async Task<QrApproveResponse> ApprovePasskey(string id, [FromBody] QrPasskeyApproveRequest request)
    {
        if (!qr.CanApprove(id, request.PhoneToken) || request.Assertion == null)
            return new QrApproveResponse(false, ExpiredMessage, null, null, null);

        CredentialInfo cred;
        string passkeyId;
        try
        {
            (cred, passkeyId) = await passkeys.VerifySignInAsync(HttpContext, request.Assertion, HttpContext.RequestAborted);
        }
        catch (WebAuthnException ex)
        {
            // Counts like a wrong password, so a request can't be tried for ever.
            var retry = qr.RecordFailedPassword(id);
            return new QrApproveResponse(false,
                retry ? ex.Message : "Too many failed attempts. Scan a new code on the computer to try again.",
                null, null, null);
        }

        // Removing the passkey in Settings ends this computer's session too.
        var (principal, properties) = auth.BuildSignIn(cred, qr.SessionLifetime, passkeyId: passkeyId);
        var revokeToken = qr.Approve(id, request.PhoneToken!, principal, properties);
        return revokeToken == null
            ? new QrApproveResponse(false, ExpiredMessage, null, null, null)
            : new QrApproveResponse(true, null, revokeToken, cred.Login, properties.ExpiresUtc);
    }

    [HttpPost("sessions")]
    public IEnumerable<QrSessionResponse> Sessions([FromBody] QrSessionsRequest request) =>
        qr.Status(request.Tokens ?? []).Select(s => new QrSessionResponse(
            s.Token, s.Status.Login, s.Status.Desktop, s.Status.DesktopIp, s.Status.SignedInUtc, s.Status.ExpiresUtc, s.Status.Active));

    [HttpPost("sessions/revoke")]
    public async Task<LoginResponse> Revoke([FromBody] QrRevokeRequest request) =>
        await qr.RevokeAsync(request.Token ?? "")
            ? new LoginResponse(true, null)
            : new LoginResponse(false, "That session has already ended.");

    private const string ExpiredMessage = "This sign-in request has expired or was cancelled. Scan the new code on the computer's screen.";
}

public sealed record QrStartResponse(string Id, int Code, DateTimeOffset ExpiresUtc, string ApproveUrl);
public sealed record QrConfirmRequest(int Code);
public sealed record QrConfirmResponse(bool Success, string? PhoneToken, string? Error);
public sealed record QrApproveRequest(string? PhoneToken, string? Username, string? Password);
public sealed record QrPasskeyApproveRequest(string? PhoneToken, PasskeyAssertionRequest? Assertion);
public sealed record QrApproveResponse(bool Success, string? Error, string? RevokeToken, string? Login, DateTimeOffset? ExpiresUtc);
public sealed record QrSessionsRequest(string[]? Tokens);
public sealed record QrRevokeRequest(string? Token);
public sealed record QrSessionResponse(string Token, string Login, string Desktop, string? DesktopIp, DateTimeOffset SignedInUtc, DateTimeOffset ExpiresUtc, bool Active);
