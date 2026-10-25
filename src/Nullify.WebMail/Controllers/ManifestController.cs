// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Nullify.WebMail.Services;

namespace Nullify.WebMail.Controllers;

/// <summary>
/// The web app manifest that lets browsers install WebMail as an app. Served here rather than as
/// a static file so the installed app carries the instance's title. Browsers fetch it without
/// cookies, so there is never a domain to brand by. URLs are relative to the manifest, which
/// keeps them right under a PathBase.
/// </summary>
[ApiController]
[AllowAnonymous]
public class ManifestController(BrandingService branding) : ControllerBase
{
    [HttpGet("/manifest.webmanifest")]
    public async Task<IActionResult> Get()
    {
        var title = await branding.InstanceTitleAsync() ?? BrandingService.DefaultTitle;
        Response.Headers.CacheControl = "no-cache";
        return new JsonResult(Build(title)) { ContentType = "application/manifest+json" };
    }

    public static object Build(string title) => new
    {
        id = "./",
        name = $"{title} WebMail",
        short_name = title,
        description = "Mail, calendar, contacts and files.",
        start_url = "./",
        scope = "./",
        display = "standalone",
        background_color = "#f4f5f7",
        theme_color = "#f4f5f7",
        icons = new object[]
        {
            new { src = "icons/icon-192.png", sizes = "192x192", type = "image/png", purpose = "any" },
            new { src = "icons/icon-512.png", sizes = "512x512", type = "image/png", purpose = "any" },
            new { src = "icons/icon-maskable-192.png", sizes = "192x192", type = "image/png", purpose = "maskable" },
            new { src = "icons/icon-maskable-512.png", sizes = "512x512", type = "image/png", purpose = "maskable" },
            new { src = "favicon.svg", sizes = "any", type = "image/svg+xml", purpose = "any" },
        },
    };
}
