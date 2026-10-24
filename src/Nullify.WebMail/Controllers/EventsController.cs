// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using System.Net.Sockets;
using System.Text.Json;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Nullify.WebMail.Services;

namespace Nullify.WebMail.Controllers;

/// <summary>
/// Server-Sent Events stream of INBOX updates, powered by a dedicated IMAP IDLE
/// connection (deliberately not from the pool — IDLE blocks indefinitely).
/// </summary>
[ApiController]
[Route("api/[controller]")]
[Authorize]
public class EventsController(
    AuthService auth,
    ImapClient imap,
    ILogger<EventsController> logger) : ControllerBase
{
    private static readonly TimeSpan IdleTimeout = TimeSpan.FromMinutes(25); // re-enter before the 29-min server cap
    private static readonly TimeSpan ReconnectDelay = TimeSpan.FromSeconds(30);

    [HttpGet]
    public async Task Stream(CancellationToken ct)
    {
        var cred = auth.GetCredential();
        if (cred == null)
        {
            Response.StatusCode = StatusCodes.Status401Unauthorized;
            return;
        }

        Response.Headers.ContentType = "text/event-stream";
        Response.Headers.CacheControl = "no-cache, no-transform";
        Response.Headers.Connection = "keep-alive";

        var endpoint = new ImapEndpoint(cred.Host, cred.Port, cred.Security, cred.AllowInvalidCertificates);
        ImapSession? session = null;

        try
        {
            await WriteEventAsync("connected", JsonSerializer.Serialize(new { folder = "INBOX" }), ct);

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    session ??= await imap.ConnectAndLoginAsync(endpoint, cred.Login, cred.Password, ct);
                    await session.SelectFolderAsync("INBOX");

                    var update = await session.IdleAsync(IdleTimeout, ct);
                    if (update == null) continue; // idle keepalive timeout — re-enter

                    await WriteEventAsync("update", JsonSerializer.Serialize(new { folder = "INBOX", line = update }), ct);
                    // Loop re-SELECTs to pick up new counts before IDLEing again.
                }
                catch (Exception ex) when (ex is IOException or SocketException or ImapProtocolException or TlsException)
                {
                    logger.LogDebug("IDLE connection lost, reconnecting: {Msg}", ex.Message);
                    if (session != null) await session.DisposeAsync();
                    session = null;
                    await Task.Delay(ReconnectDelay, ct);
                }
            }
        }
        catch (OperationCanceledException)
        {
            // Client disconnected — normal.
        }
        finally
        {
            if (session != null) await session.DisposeAsync();
        }
    }

    private async Task WriteEventAsync(string type, string json, CancellationToken ct)
    {
        await Response.WriteAsync($"event: {type}\ndata: {json}\n\n", ct);
        await Response.Body.FlushAsync(ct);
    }
}