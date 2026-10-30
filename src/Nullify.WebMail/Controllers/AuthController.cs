// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Nullify.WebMail.Data;
using Nullify.WebMail.Services;
using Nullify.WebMail.Shared;

namespace Nullify.WebMail.Controllers;

[ApiController]
[Route("api/auth")]
public class AuthController(
    AuthService auth,
    TrustedDeviceService trustedDevices,
    LoginKeyService loginKeys,
    IDbContextFactory<AppDbContext> dbFactory) : ControllerBase
{
    /// <summary>
    /// JSON login used by the browser via fetch — the Set-Cookie lands in the browser jar.
    /// The password field also takes a one-time sign-in key, which unlocks the real password.
    /// </summary>
    [HttpPost("login")]
    [AllowAnonymous]
    public async Task<LoginResponse> Login([FromBody] LoginRequest request)
    {
        var ct = HttpContext.RequestAborted;
        var password = request.Password ?? "";
        var unlocked = loginKeys.Redeem(request.Username ?? "", password);
        var (result, cred) = await auth.VerifyLoginAsync(request.Username ?? "", unlocked ?? password, ct);
        if (cred != null)
        {
            // A key is for a computer that isn't the user's, so it never makes the computer trusted.
            var deviceId = request.TrustDevice && unlocked == null
                ? await trustedDevices.TrustAsync(HttpContext, cred.Login, cred.Password, ct)
                : null;
            await auth.SignInAsync(HttpContext, cred, deviceId, loginKey: unlocked != null);
        }
        return new LoginResponse(result.Success, result.Error);
    }

    /// <summary>First-run bootstrap: verify against the submitted servers, create admin + domain mapping, sign in.</summary>
    [HttpPost("setup")]
    [AllowAnonymous]
    public async Task<ActionResult<LoginResponse>> Setup([FromBody] SetupRequest request)
    {
        var imapSecurity = Enum.TryParse<MailSecurity>(request.ImapSecurity, true, out var i) ? i : MailSecurity.Tls;
        var smtpSecurity = Enum.TryParse<MailSecurity>(request.SmtpSecurity, true, out var s) ? s : MailSecurity.StartTls;

        var result = await auth.SetupAsync(
            request.Username ?? "", request.Password ?? "",
            request.ImapHost ?? "", request.ImapPort, imapSecurity,
            request.SmtpHost, request.SmtpPort, smtpSecurity,
            HttpContext.RequestAborted);

        if (!result.Success)
            return BadRequest(new LoginResponse(false, result.Error));
        return Ok(new LoginResponse(true, null));
    }

    [HttpGet("has-users")]
    [AllowAnonymous]
    public async Task<bool> HasUsers()
    {
        await using var db = await dbFactory.CreateDbContextAsync(HttpContext.RequestAborted);
        return await db.Users.AnyAsync(HttpContext.RequestAborted);
    }

    [HttpPost("logout")]
    public async Task<IActionResult> Logout()
    {
        // Signing out of a trusted computer stops trusting it; otherwise it would sign straight back in.
        await trustedDevices.ForgetAsync(HttpContext, HttpContext.RequestAborted);
        await auth.SignOutAsync(HttpContext);
        return Ok();
    }

    [HttpGet("session")]
    [Authorize]
    public IActionResult Session()
    {
        var cred = auth.GetCredential();
        if (cred == null) return Unauthorized();
        return Ok(new SessionInfo(cred.Login, cred.Login, cred.Login));
    }
}

public sealed record SetupRequest(
    string Username, string Password,
    string? ImapHost, int ImapPort, string? ImapSecurity,
    string? SmtpHost, int SmtpPort, string? SmtpSecurity);