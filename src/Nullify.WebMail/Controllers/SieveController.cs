// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Nullify.WebMail.Services;
using Nullify.WebMail.Shared;

namespace Nullify.WebMail.Controllers;

[ApiController]
[Route("api/sieve")]
[Authorize]
public class SieveController(AuthService auth, ManageSieveClient sieve) : ControllerBase
{
    private CredentialInfo? Cred => auth.GetCredential();

    private static SieveEndpoint EndpointFor(CredentialInfo cred) =>
        SieveEndpoint.For(cred.SieveHost, cred.SievePort);

    [HttpGet("scripts")]
    public async Task<ActionResult<IReadOnlyList<SieveScriptDto>>> ListScripts()
    {
        if (Cred is not { } cred) return Unauthorized();
        try
        {
            await using var session = await sieve.ConnectAndLoginAsync(EndpointFor(cred), cred.Login, cred.Password, HttpContext.RequestAborted);
            var scripts = await session.ListScriptsAsync();
            await session.LogoutAsync();
            return Ok(scripts.Select(s => new SieveScriptDto(s.Name, s.IsActive, "")).ToList());
        }
        catch (Exception ex) when (ex is SieveException or IOException or System.Net.Sockets.SocketException)
        {
            return StatusCode(StatusCodes.Status502BadGateway, "Sieve server unavailable: " + ex.Message);
        }
    }

    [HttpGet("scripts/{name}")]
    public async Task<ActionResult<SieveScriptDto>> GetScript(string name)
    {
        if (Cred is not { } cred) return Unauthorized();
        try
        {
            await using var session = await sieve.ConnectAndLoginAsync(EndpointFor(cred), cred.Login, cred.Password, HttpContext.RequestAborted);
            var content = await session.GetScriptAsync(name);
            var scripts = await session.ListScriptsAsync();
            await session.LogoutAsync();
            var isActive = scripts.FirstOrDefault(s => s.Name == name)?.IsActive ?? false;
            return Ok(new SieveScriptDto(name, isActive, content));
        }
        catch (SieveException ex)
        {
            return BadRequest(ex.Message);
        }
    }

    [HttpPut("scripts/{name}")]
    public async Task<IActionResult> PutScript(string name, [FromBody] SieveScriptDto dto)
    {
        if (Cred is not { } cred) return Unauthorized();
        try
        {
            await using var session = await sieve.ConnectAndLoginAsync(EndpointFor(cred), cred.Login, cred.Password, HttpContext.RequestAborted);
            await session.PutScriptAsync(name, dto.Content ?? "");
            await session.LogoutAsync();
            return Ok();
        }
        catch (SieveException ex)
        {
            return BadRequest(ex.Message);
        }
    }

    [HttpDelete("scripts/{name}")]
    public async Task<IActionResult> DeleteScript(string name)
    {
        if (Cred is not { } cred) return Unauthorized();
        try
        {
            await using var session = await sieve.ConnectAndLoginAsync(EndpointFor(cred), cred.Login, cred.Password, HttpContext.RequestAborted);
            await session.DeleteScriptAsync(name);
            await session.LogoutAsync();
            return Ok();
        }
        catch (SieveException ex)
        {
            return BadRequest(ex.Message);
        }
    }

    [HttpPut("scripts/{name}/activate")]
    public async Task<IActionResult> Activate(string name)
    {
        if (Cred is not { } cred) return Unauthorized();
        try
        {
            await using var session = await sieve.ConnectAndLoginAsync(EndpointFor(cred), cred.Login, cred.Password, HttpContext.RequestAborted);
            await session.SetActiveAsync(name);
            await session.LogoutAsync();
            return Ok();
        }
        catch (SieveException ex)
        {
            return BadRequest(ex.Message);
        }
    }
}