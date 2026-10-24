// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Net.Http.Headers;
using Nullify.WebMail.Services;

namespace Nullify.WebMail.Controllers;

/// <summary>Streams Documents (WebDAV) files to the browser; the UI does everything else in-circuit.</summary>
[ApiController]
[Route("api/files")]
[Authorize]
public class FilesController(UserSession session, WebDavService dav) : ControllerBase
{
    [HttpGet("download")]
    public async Task Download([FromQuery] string path, CancellationToken ct)
    {
        await session.CaptureAsync(ct);
        if (!session.IsAuthenticated)
        {
            Response.StatusCode = StatusCodes.Status401Unauthorized;
            return;
        }

        HttpResponseMessage upstream;
        try
        {
            upstream = await dav.OpenDownloadAsync(path, ct);
        }
        catch (Exception ex) when (ex is CalDavException or InvalidOperationException)
        {
            Response.StatusCode = StatusCodes.Status404NotFound;
            await Response.WriteAsync(ex.Message, ct);
            return;
        }

        using (upstream)
        {
            var name = WebDavService.NormalizePath(path).TrimEnd('/');
            name = name[(name.LastIndexOf('/') + 1)..];
            // Always a download with a neutral type: serving user files inline (HTML, SVG, PDF)
            // would let them run on this origin.
            Response.ContentType = "application/octet-stream";
            Response.Headers[HeaderNames.ContentDisposition] =
                new ContentDispositionHeaderValue("attachment") { FileNameStar = name, FileName = AsciiName(name) }.ToString();
            if (upstream.Content.Headers.ContentLength is { } length) Response.ContentLength = length;
            await using var body = await upstream.Content.ReadAsStreamAsync(ct);
            await body.CopyToAsync(Response.Body, ct);
        }
    }

    private static string AsciiName(string name)
    {
        var ascii = new string(name.Select(c => c is >= ' ' and < (char)127 && c != '"' ? c : '_').ToArray());
        return string.IsNullOrWhiteSpace(ascii) ? "download" : ascii;
    }
}
