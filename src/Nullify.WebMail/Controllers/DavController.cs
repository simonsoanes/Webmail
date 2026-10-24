// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Nullify.WebMail.Services;
using Nullify.WebMail.Shared;

namespace Nullify.WebMail.Controllers;

[ApiController]
[Route("api/dav")]
[Authorize]
public class DavController(AuthService auth) : ControllerBase
{
    [HttpGet("calendar/events")]
    public Task<IReadOnlyList<CalendarEvent>> GetCalendarEvents(
        [FromQuery] string? start, [FromQuery] string? end)
    {
        if (auth.GetCredential() == null) return Task.FromResult<IReadOnlyList<CalendarEvent>>(Array.Empty<CalendarEvent>());
        // Placeholder: CalDAV REPORT proxy — see design.md Phase 3.
        return Task.FromResult<IReadOnlyList<CalendarEvent>>(Array.Empty<CalendarEvent>());
    }

    [HttpGet("contacts")]
    public Task<IReadOnlyList<ContactInfo>> GetContacts([FromQuery] string? q)
    {
        if (auth.GetCredential() == null) return Task.FromResult<IReadOnlyList<ContactInfo>>(Array.Empty<ContactInfo>());
        // Placeholder: CardDAV addressbook-query proxy — see design.md Phase 3.
        return Task.FromResult<IReadOnlyList<ContactInfo>>(Array.Empty<ContactInfo>());
    }
}