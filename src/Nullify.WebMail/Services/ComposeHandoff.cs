// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using System.Collections.Concurrent;
using System.Security.Cryptography;
using Nullify.WebMail.Shared;

namespace Nullify.WebMail.Services;

/// <summary>
/// Carries a message being written from one window to another when it's popped out. The new
/// window has its own circuit, so the draft waits here under a random one-time token (the only
/// thing put in the URL), for the same signed-in user, for a short while. Memory only.
/// </summary>
public sealed class ComposeHandoff(TimeProvider clock)
{
    public static readonly TimeSpan Lifetime = TimeSpan.FromMinutes(2);

    /// <param name="BodyHtml">The editor's contents; inline photos are <c>img[data-cid]</c> matching attachments.</param>
    public sealed record Draft(
        ComposeMode Mode, string? SourceFolder, long? SourceUid,
        string From, string To, string Cc, string Bcc, bool ShowCc, bool ShowBcc,
        string Subject, string BodyHtml, bool Important,
        string? InReplyTo, string? References,
        IReadOnlyList<OutgoingAttachment> Attachments,
        bool Sign, bool EncryptTouched, bool EncryptChoice);

    private readonly ConcurrentDictionary<string, (string Owner, DateTimeOffset Expires, Draft Draft)> waiting = new();

    public string Put(string owner, Draft draft)
    {
        Prune();
        var token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(24)).Replace('+', '-').Replace('/', '_');
        waiting[token] = (owner, clock.GetUtcNow() + Lifetime, draft);
        return token;
    }

    /// <summary>The draft, once; null if it's gone, expired, or someone else's.</summary>
    public Draft? Take(string owner, string token)
    {
        Prune();
        if (!waiting.TryGetValue(token, out var item) || !string.Equals(item.Owner, owner, StringComparison.OrdinalIgnoreCase))
            return null;
        return waiting.TryRemove(token, out item) ? item.Draft : null;
    }

    private void Prune()
    {
        var now = clock.GetUtcNow();
        foreach (var (key, item) in waiting)
            if (item.Expires <= now) waiting.TryRemove(key, out _);
    }
}
