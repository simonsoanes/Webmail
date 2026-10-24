// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;

namespace Nullify.WebMail.Services;

/// <summary>
/// Per-(server,user) pool of authenticated IMAP connections. Commands are serialised
/// per connection by the semaphore; IDLE runs on dedicated connections outside the pool.
/// </summary>
public sealed class ConnectionPool(SettingsService settings, ImapClient imap, ILogger<ConnectionPool> logger)
{
    private readonly ConcurrentDictionary<string, PoolEntry> _pools = new();

    public static string KeyFor(ImapEndpoint ep, string login)
    {
        var raw = $"{ep.Host}:{ep.Port}:{ep.Security}:{login}";
        return Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(raw)));
    }

    public async Task<ImapSession> GetSessionAsync(
        ImapEndpoint endpoint, string login, string password, CancellationToken ct = default)
    {
        var key = KeyFor(endpoint, login);
        var entry = _pools.GetOrAdd(key, _ => new PoolEntry(
            Math.Max(1, settings.Current.ConnectionPoolSize),
            TimeSpan.FromMinutes(Math.Max(1, settings.Current.ConnectionIdleMinutes))));

        await entry.Semaphore.WaitAsync(ct);
        var acquired = false;
        try
        {
            while (entry.Idle.TryDequeue(out var idle))
            {
                if (DateTime.UtcNow - idle.LastUsed > entry.IdleTimeout)
                {
                    await idle.Session.DisposeAsync();
                    continue;
                }
                try
                {
                    await idle.Session.NoopAsync(); // verify still alive
                    acquired = true;
                    return idle.Session;
                }
                catch
                {
                    await idle.Session.DisposeAsync();
                }
            }

            var session = await imap.ConnectAndLoginAsync(endpoint, login, password, ct);
            acquired = true;
            return session;
        }
        finally
        {
            if (!acquired) entry.Semaphore.Release();
        }
    }

    public void ReturnSession(string key, ImapSession session)
    {
        if (_pools.TryGetValue(key, out var entry))
        {
            entry.Idle.Enqueue(new IdleConnection(session, DateTime.UtcNow));
            entry.Semaphore.Release();
        }
        else
        {
            _ = session.DisposeAsync();
        }
    }

    public void RemoveSession(string key, ImapSession session)
    {
        logger.LogDebug("Discarding IMAP session for pool {Key}", key[..8]);
        _ = session.DisposeAsync();
        if (_pools.TryGetValue(key, out var entry))
            entry.Semaphore.Release();
    }

    private sealed class PoolEntry(int maxConnections, TimeSpan idleTimeout)
    {
        public readonly SemaphoreSlim Semaphore = new(maxConnections, maxConnections);
        public readonly ConcurrentQueue<IdleConnection> Idle = new();
        public readonly TimeSpan IdleTimeout = idleTimeout;
    }

    private sealed record IdleConnection(ImapSession Session, DateTime LastUsed);
}