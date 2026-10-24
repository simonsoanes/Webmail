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
[Route("api/[controller]")]
[Authorize]
public class PrefsController(AuthService auth, AppDbContext db, WriteGate gate) : ControllerBase
{
    [HttpGet]
    public async Task<IReadOnlyList<PreferenceDto>> GetAll()
    {
        var username = auth.GetCredential()?.Login ?? "";
        var user = await db.Users.FirstOrDefaultAsync(u => u.Username == username);
        if (user == null) return Array.Empty<PreferenceDto>();

        var prefs = await db.UserPreferences.Where(p => p.UserId == user.Id).ToListAsync();
        return prefs.Select(p => new PreferenceDto(p.Key, p.Value)).ToList();
    }

    [HttpPut("{key}")]
    public async Task<IActionResult> Set(string key, [FromBody] PreferenceDto dto)
    {
        var username = auth.GetCredential()?.Login ?? "";
        var user = await db.Users.FirstOrDefaultAsync(u => u.Username == username);
        if (user == null) return Unauthorized();

        using (await gate.EnterAsync())
        {
            var pref = await db.UserPreferences
                .FirstOrDefaultAsync(p => p.UserId == user.Id && p.Key == key);
            if (pref == null)
            {
                pref = new UserPreference { UserId = user.Id, Key = key };
                db.UserPreferences.Add(pref);
            }
            pref.Value = dto.Value;
            await db.SaveChangesAsync();
        }
        return Ok();
    }
}