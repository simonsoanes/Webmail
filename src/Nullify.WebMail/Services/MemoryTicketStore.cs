// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using System.Collections.Concurrent;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.Caching.Memory;

namespace Nullify.WebMail.Services;

/// <summary>
/// Keeps authentication tickets, and with them the user's mail credential, in server memory only.
/// The auth cookie carries just a random session key, so the mail password is never sent to the
/// browser in any form: not in the cookie, not in the page.
/// Consequences: sessions end when the process restarts (users sign in again), and running more
/// than one instance needs sticky sessions.
/// </summary>
public sealed class MemoryTicketStore : ITicketStore, IDisposable
{
    // Matches the cookie lifetime in Program.cs; used when a ticket carries no expiry of its own.
    private static readonly TimeSpan DefaultLifetime = TimeSpan.FromDays(7);

    // A private cache, so nothing else in the app can enumerate or evict sessions.
    private readonly MemoryCache _tickets = new(new MemoryCacheOptions());

    // App session id (AuthService.SessionIdClaim) → cache key, so a session can be ended by id.
    private readonly ConcurrentDictionary<string, string> _keysBySession = new();

    public int Count => _tickets.Count;

    public Task<string> StoreAsync(AuthenticationTicket ticket)
    {
        var key = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        Put(key, ticket);
        return Task.FromResult(key);
    }

    public Task RenewAsync(string key, AuthenticationTicket ticket)
    {
        Put(key, ticket);
        return Task.CompletedTask;
    }

    public Task<AuthenticationTicket?> RetrieveAsync(string key) =>
        Task.FromResult(_tickets.Get<AuthenticationTicket>(key));

    public Task RemoveAsync(string key)
    {
        _tickets.Remove(key);
        return Task.CompletedTask;
    }

    /// <summary>
    /// A session was ended from elsewhere (revoked, or past a time limit) by its app session id.
    /// Open pages for that session listen for this, because a Blazor circuit keeps working
    /// without its cookie.
    /// </summary>
    public event Action<string>? SessionEnded;

    /// <summary>End a session by its app session id, wherever its cookie is.</summary>
    public Task RemoveSessionAsync(string sessionId)
    {
        if (_keysBySession.TryRemove(sessionId, out var key)) _tickets.Remove(key);
        SessionEnded?.Invoke(sessionId);
        return Task.CompletedTask;
    }

    /// <summary>End every session whose user matches, e.g. all sessions from one trusted computer.</summary>
    public async Task RemoveSessionsAsync(Func<System.Security.Claims.ClaimsPrincipal, bool> match)
    {
        foreach (var (sessionId, key) in _keysBySession)
            if (_tickets.Get<AuthenticationTicket>(key) is { } ticket && match(ticket.Principal))
                await RemoveSessionAsync(sessionId);
    }

    public bool HasSession(string sessionId) =>
        _keysBySession.TryGetValue(sessionId, out var key) && _tickets.TryGetValue(key, out _);

    private void Put(string key, AuthenticationTicket ticket)
    {
        var options = new MemoryCacheEntryOptions
        {
            AbsoluteExpiration = ticket.Properties.ExpiresUtc ?? DateTimeOffset.UtcNow + DefaultLifetime,
        };
        var sessionId = ticket.Principal.FindFirst(AuthService.SessionIdClaim)?.Value;
        if (sessionId != null)
        {
            _keysBySession[sessionId] = key;
            options.RegisterPostEvictionCallback((_, _, reason, _) =>
            {
                // A renewal replaces the entry under the same key; only drop the index when it is really gone.
                if (reason != EvictionReason.Replaced) _keysBySession.TryRemove(new KeyValuePair<string, string>(sessionId, key));
            });
        }
        _tickets.Set(key, ticket, options);
    }

    public void Dispose() => _tickets.Dispose();
}
