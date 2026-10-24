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
[Route("api/admin")]
[Authorize]
public class AdminController(
    AuthService auth,
    IDbContextFactory<AppDbContext> dbFactory,
    WriteGate gate,
    BrandingCache brandingCache) : ControllerBase
{
    private async Task<bool> IsAdminAsync()
    {
        var cred = auth.GetCredential();
        if (cred == null) return false;
        await using var db = await dbFactory.CreateDbContextAsync(HttpContext.RequestAborted);
        return await db.Users
            .Where(u => u.Username == cred.Login)
            .Select(u => u.IsAdmin)
            .FirstOrDefaultAsync(HttpContext.RequestAborted);
    }

    // ---- Domains ----

    [HttpGet("domains")]
    public async Task<ActionResult<IReadOnlyList<DomainDto>>> ListDomains()
    {
        if (!await IsAdminAsync()) return StatusCode(StatusCodes.Status403Forbidden);
        await using var db = await dbFactory.CreateDbContextAsync(HttpContext.RequestAborted);
        var domains = await db.Domains.OrderBy(d => d.Name).ToListAsync(HttpContext.RequestAborted);
        return Ok(domains.Select(MapDomain).ToList());
    }

    [HttpPost("domains")]
    public async Task<IActionResult> CreateDomain([FromBody] DomainDto dto)
    {
        if (!await IsAdminAsync()) return StatusCode(StatusCodes.Status403Forbidden);
        if (string.IsNullOrWhiteSpace(dto.Name)) return BadRequest("Domain name is required.");
        var name = dto.Name.Trim().ToLowerInvariant();

        await using var db = await dbFactory.CreateDbContextAsync(HttpContext.RequestAborted);
        using (await gate.EnterAsync(HttpContext.RequestAborted))
        {
            if (await db.Domains.AnyAsync(d => d.Name == name, HttpContext.RequestAborted))
                return Conflict("Domain already exists.");
            db.Domains.Add(new Domain
            {
                Name = name,
                ImapHost = dto.ImapHost, ImapPort = dto.ImapPort, ImapSecurity = dto.ImapSecurity,
                ImapAllowInvalidCertificates = dto.ImapAllowInvalidCertificates,
                SmtpHost = dto.SmtpHost, SmtpPort = dto.SmtpPort, SmtpSecurity = dto.SmtpSecurity,
                SieveHost = dto.SieveHost, SievePort = dto.SievePort,
                CalDavUrl = dto.CalDavUrl, CardDavUrl = dto.CardDavUrl,
            });
            await db.SaveChangesAsync(HttpContext.RequestAborted);
        }
        return Ok();
    }

    [HttpPut("domains/{name}")]
    public async Task<IActionResult> UpdateDomain(string name, [FromBody] DomainDto dto)
    {
        if (!await IsAdminAsync()) return StatusCode(StatusCodes.Status403Forbidden);
        name = name.Trim().ToLowerInvariant();

        await using var db = await dbFactory.CreateDbContextAsync(HttpContext.RequestAborted);
        using (await gate.EnterAsync(HttpContext.RequestAborted))
        {
            var domain = await db.Domains.FirstOrDefaultAsync(d => d.Name == name, HttpContext.RequestAborted);
            if (domain == null) return NotFound();
            domain.ImapHost = dto.ImapHost; domain.ImapPort = dto.ImapPort; domain.ImapSecurity = dto.ImapSecurity;
            domain.ImapAllowInvalidCertificates = dto.ImapAllowInvalidCertificates;
            domain.SmtpHost = dto.SmtpHost; domain.SmtpPort = dto.SmtpPort; domain.SmtpSecurity = dto.SmtpSecurity;
            domain.SieveHost = dto.SieveHost; domain.SievePort = dto.SievePort;
            domain.CalDavUrl = dto.CalDavUrl; domain.CardDavUrl = dto.CardDavUrl;
            await db.SaveChangesAsync(HttpContext.RequestAborted);
        }
        return Ok();
    }

    [HttpDelete("domains/{name}")]
    public async Task<IActionResult> DeleteDomain(string name)
    {
        if (!await IsAdminAsync()) return StatusCode(StatusCodes.Status403Forbidden);
        name = name.Trim().ToLowerInvariant();

        await using var db = await dbFactory.CreateDbContextAsync(HttpContext.RequestAborted);
        using (await gate.EnterAsync(HttpContext.RequestAborted))
        {
            var domain = await db.Domains.FirstOrDefaultAsync(d => d.Name == name, HttpContext.RequestAborted);
            if (domain == null) return NotFound();
            db.Domains.Remove(domain);
            await db.SaveChangesAsync(HttpContext.RequestAborted);
        }
        return Ok();
    }

    // ---- Settings ----

    [HttpGet("settings")]
    public async Task<ActionResult<IReadOnlyList<AdminSettingDto>>> ListSettings()
    {
        if (!await IsAdminAsync()) return StatusCode(StatusCodes.Status403Forbidden);
        await using var db = await dbFactory.CreateDbContextAsync(HttpContext.RequestAborted);
        var settings = await db.AdminSettings.OrderBy(s => s.Key).ToListAsync(HttpContext.RequestAborted);
        return Ok(settings.Select(s => new AdminSettingDto(s.Key, s.Value)).ToList());
    }

    [HttpPut("settings/{key}")]
    public async Task<IActionResult> SetSetting(string key, [FromBody] AdminSettingDto dto)
    {
        if (!await IsAdminAsync()) return StatusCode(StatusCodes.Status403Forbidden);
        await using var db = await dbFactory.CreateDbContextAsync(HttpContext.RequestAborted);
        using (await gate.EnterAsync(HttpContext.RequestAborted))
        {
            var setting = await db.AdminSettings.FirstOrDefaultAsync(s => s.Key == key, HttpContext.RequestAborted);
            if (setting == null)
            {
                db.AdminSettings.Add(new AdminSetting { Key = key, Value = dto.Value });
            }
            else
            {
                setting.Value = dto.Value;
            }
            await db.SaveChangesAsync(HttpContext.RequestAborted);
        }
        brandingCache.Invalidate(key);
        return Ok();
    }

    // ---- Users ----

    [HttpGet("users")]
    public async Task<ActionResult<IReadOnlyList<UserDto>>> ListUsers()
    {
        if (!await IsAdminAsync()) return StatusCode(StatusCodes.Status403Forbidden);
        await using var db = await dbFactory.CreateDbContextAsync(HttpContext.RequestAborted);
        var users = await db.Users.OrderBy(u => u.Username).ToListAsync(HttpContext.RequestAborted);
        return Ok(users.Select(u => new UserDto(u.Username, u.Email, u.IsAdmin, u.CreatedUtc, u.LastLoginUtc)).ToList());
    }

    [HttpPut("users/{username}/admin")]
    public async Task<IActionResult> SetAdmin(string username, [FromBody] AdminToggleDto dto)
    {
        if (!await IsAdminAsync()) return StatusCode(StatusCodes.Status403Forbidden);
        await using var db = await dbFactory.CreateDbContextAsync(HttpContext.RequestAborted);
        using (await gate.EnterAsync(HttpContext.RequestAborted))
        {
            var user = await db.Users.FirstOrDefaultAsync(u => u.Username == username, HttpContext.RequestAborted);
            if (user == null) return NotFound();
            // Never allow removing the last admin.
            if (user.IsAdmin && !dto.IsAdmin)
            {
                var adminCount = await db.Users.CountAsync(u => u.IsAdmin, HttpContext.RequestAborted);
                if (adminCount <= 1) return BadRequest("Cannot remove the last admin.");
            }
            user.IsAdmin = dto.IsAdmin;
            await db.SaveChangesAsync(HttpContext.RequestAborted);
        }
        return Ok();
    }

    [HttpGet("is-admin")]
    public async Task<bool> IsAdmin() => await IsAdminAsync();

    private static DomainDto MapDomain(Domain d) => new(
        d.Name,
        d.ImapHost, d.ImapPort, d.ImapSecurity, d.ImapAllowInvalidCertificates,
        d.SmtpHost, d.SmtpPort, d.SmtpSecurity,
        d.SieveHost, d.SievePort,
        d.CalDavUrl, d.CardDavUrl,
        d.CreatedUtc);
}