// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using System.Net;
using System.Net.Sockets;

namespace Nullify.WebMail.Services;

/// <summary>The address resolves only to loopback, private or link-local networks.</summary>
public sealed class PrivateAddressException(string host)
    : IOException($"{host} is on a private network, which this server won't fetch from.");

/// <summary>
/// An HTTP client for addresses users type in (internet calendars). It connects only to public
/// internet addresses, checked at connect time so a DNS answer that changes between lookups or a
/// redirect can't reach the server's own network, except for a host the request names in
/// <see cref="AllowedHost"/> (the user's own CalDAV server, which is often on the LAN).
/// </summary>
public static class PublicNetwork
{
    public const string HttpClientName = "public-web";
    public const long MaxResponseBytes = 8 * 1024 * 1024;

    public static readonly HttpRequestOptionsKey<string> AllowedHost = new("nullify.allowed-host");

    public static SocketsHttpHandler CreateHandler() => new()
    {
        AllowAutoRedirect = true,
        MaxAutomaticRedirections = 5,
        UseProxy = false,
        AutomaticDecompression = DecompressionMethods.All,
        ConnectTimeout = TimeSpan.FromSeconds(10),
        ConnectCallback = ConnectAsync,
    };

    private static async ValueTask<Stream> ConnectAsync(SocketsHttpConnectionContext context, CancellationToken ct)
    {
        var host = context.DnsEndPoint.Host;
        var allowPrivate = context.InitialRequestMessage.Options.TryGetValue(AllowedHost, out var allowed)
                           && string.Equals(allowed, host, StringComparison.OrdinalIgnoreCase);
        var addresses = await Dns.GetHostAddressesAsync(host, ct);
        var target = addresses.FirstOrDefault(a => allowPrivate || SenderAuth.IsPublic(a))
                     ?? throw new PrivateAddressException(host);
        var socket = new Socket(target.AddressFamily, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
        try
        {
            await socket.ConnectAsync(new IPEndPoint(target, context.DnsEndPoint.Port), ct);
            return new NetworkStream(socket, ownsSocket: true);
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }

    /// <summary>The <see cref="PrivateAddressException"/> behind a failed request, if that's why it failed.</summary>
    public static PrivateAddressException? Blocked(Exception ex)
    {
        for (Exception? e = ex; e != null; e = e.InnerException)
            if (e is PrivateAddressException p) return p;
        return null;
    }
}
