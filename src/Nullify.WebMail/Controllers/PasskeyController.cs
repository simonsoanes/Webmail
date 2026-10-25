// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Nullify.WebMail.Services;

namespace Nullify.WebMail.Controllers;

/// <summary>
/// WebAuthn ceremonies for passkeys (see <see cref="PasskeyService"/>). The browser calls these with
/// fetch, so the session cookie lands in its jar and the PRF-derived keys never pass through the
/// Blazor circuit. Listing and removing passkeys happens in Settings, through the service directly.
/// </summary>
[ApiController]
[Route("api/auth/passkey")]
[EnableRateLimiting(RateLimitPolicy)]
public class PasskeyController(PasskeyService passkeys, AuthService auth) : ControllerBase
{
    public const string RateLimitPolicy = "passkey";

    private const string QrSessionMessage =
        "This computer was signed in from your phone, so passkeys can't be set up on it. Its browser would hold the key that unlocks your password.";

    [HttpPost("signin/options")]
    [AllowAnonymous]
    public Task<IActionResult> SignInOptions([FromBody] PasskeySignInOptionsRequest request) =>
        Run(() => passkeys.BeginSignInAsync(request.Username, request.CredentialIds, HttpContext, HttpContext.RequestAborted));

    [HttpPost("signin")]
    [AllowAnonymous]
    public Task<IActionResult> SignIn([FromBody] PasskeyAssertionRequest request) =>
        Run(async () =>
        {
            await passkeys.FinishSignInAsync(HttpContext, request, HttpContext.RequestAborted);
            return new PasskeyResponse(true, null, request.CredentialId);
        });

    [HttpPost("register/options")]
    [Authorize]
    public Task<IActionResult> RegisterOptions() =>
        Run(() => passkeys.BeginRegisterAsync(HttpContext, Credential(), HttpContext.RequestAborted));

    [HttpPost("register")]
    [Authorize]
    public Task<IActionResult> Register([FromBody] PasskeyRegisterRequest request) =>
        Run(async () =>
        {
            await passkeys.FinishRegisterAsync(HttpContext, Credential(), request, HttpContext.RequestAborted);
            return new PasskeyResponse(true, null);
        });

    [HttpPost("{id:int}/update/options")]
    [Authorize]
    public Task<IActionResult> UpdateOptions(int id) =>
        Run(() => passkeys.BeginUpdateAsync(HttpContext, Credential(), id, HttpContext.RequestAborted));

    [HttpPost("update")]
    [Authorize]
    public Task<IActionResult> Update([FromBody] PasskeyAssertionRequest request) =>
        Run(async () =>
        {
            await passkeys.FinishUpdateAsync(HttpContext, Credential(), request, HttpContext.RequestAborted);
            return new PasskeyResponse(true, null, request.CredentialId);
        });

    /// <summary>The signed-in credential, for ceremonies that wrap it. Never on a desktop a phone signed in.</summary>
    private CredentialInfo Credential()
    {
        if (User.FindFirst(AuthService.QrSessionClaim) != null)
            throw new WebAuthnException(QrSessionMessage);
        return auth.GetCredential() ?? throw new WebAuthnException("You're not signed in.");
    }

    private async Task<IActionResult> Run<T>(Func<Task<T>> action)
    {
        try
        {
            return Ok(await action());
        }
        catch (WebAuthnException ex)
        {
            return BadRequest(new PasskeyResponse(false, ex.Message));
        }
    }
}
