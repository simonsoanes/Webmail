// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;

namespace Nullify.WebMail.Services;

/// <summary>An unused sign-in key as listed in Settings (never the key itself).</summary>
public sealed record LoginKeyInfo(string Id, DateTime CreatedUtc, DateTime ExpiresUtc);

/// <summary>A key just made: <see cref="Key"/> is shown once and never again.</summary>
public sealed record NewLoginKey(string Id, string Key, DateTime ExpiresUtc);

/// <summary>
/// One-time sign-in keys: a short random code the user can type in place of their password,
/// say on a computer they don't want to type the real one on. Each key seals the mail password
/// (<see cref="SecretBox"/>, keyed by the code), so the server can't open it again until the
/// code is typed. Only a salted hash of the code is kept, to find the entry. Keys live only in
/// server memory: they last at most <see cref="MaxLifetime"/>, a restart forgets them, and each
/// one works once.
/// </summary>
public sealed class LoginKeyService(ILogger<LoginKeyService> logger)
{
    public static readonly TimeSpan MaxLifetime = TimeSpan.FromMinutes(30);
    public static readonly TimeSpan MinLifetime = TimeSpan.FromMinutes(1);
    /// <summary>Unused keys one account may have at a time.</summary>
    public const int MaxPerUser = 5;

    /// <summary>No 0/O or 1/I, so a key read off one screen types correctly on another. 32 symbols = 5 bits each.</summary>
    public const string Alphabet = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ";
    private const int Groups = 4, GroupLength = 4; // 16 symbols = 80 bits
    private const string SealContext = "Nullify.WebMail.LoginKey.v1:";

    private sealed record Entry(string Id, string Login, string SealedPassword, DateTime CreatedUtc, DateTime ExpiresUtc);

    // Keyed by Hash(code): a memory dump shows neither the codes nor, without one, the passwords.
    private readonly ConcurrentDictionary<string, Entry> _keys = new();
    private readonly byte[] _pepper = RandomNumberGenerator.GetBytes(32);

    /// <summary>Make a key that signs in as <paramref name="login"/> with <paramref name="password"/> until it's used or expires.</summary>
    /// <exception cref="InvalidOperationException">The account already has <see cref="MaxPerUser"/> unused keys.</exception>
    public NewLoginKey Create(string login, string password, TimeSpan lifetime)
    {
        Prune();
        if (List(login).Count >= MaxPerUser)
            throw new InvalidOperationException($"You can have up to {MaxPerUser} unused sign-in keys. Revoke one first.");

        if (lifetime < MinLifetime) lifetime = MinLifetime;
        if (lifetime > MaxLifetime) lifetime = MaxLifetime;
        var code = Generate();
        var now = DateTime.UtcNow;
        var entry = new Entry(
            Convert.ToHexString(RandomNumberGenerator.GetBytes(8)), login,
            SecretBox.Seal(password, code, SealContext + login.ToLowerInvariant()),
            now, now + lifetime);
        if (!_keys.TryAdd(Hash(code), entry))
            throw new InvalidOperationException("Could not make a key. Try again."); // 80 random bits colliding: never in practice

        logger.LogInformation("Sign-in key {Id} made for {Login}, expires {Expires:u}", entry.Id, login, entry.ExpiresUtc);
        return new NewLoginKey(entry.Id, Format(code), entry.ExpiresUtc);
    }

    /// <summary>
    /// The mail password <paramref name="typed"/> unlocks for <paramref name="login"/>, using up the
    /// key; null when it isn't a current key for that account (so it may be the real password).
    /// </summary>
    public string? Redeem(string login, string typed)
    {
        if (Normalize(typed) is not { } code) return null;
        login = login.Trim();
        var hash = Hash(code);
        if (!_keys.TryGetValue(hash, out var entry)
            || !entry.Login.Equals(login, StringComparison.OrdinalIgnoreCase)
            || entry.ExpiresUtc <= DateTime.UtcNow)
            return null;
        // Two sign-ins racing with one key: only one gets it.
        if (!_keys.TryRemove(new KeyValuePair<string, Entry>(hash, entry))) return null;

        if (!SecretBox.TryOpen(entry.SealedPassword, code, SealContext + entry.Login.ToLowerInvariant(), out var password))
            return null;
        logger.LogInformation("Sign-in key {Id} used by {Login}", entry.Id, entry.Login);
        return password;
    }

    public IReadOnlyList<LoginKeyInfo> List(string login)
    {
        var now = DateTime.UtcNow;
        return _keys.Values
            .Where(e => e.Login.Equals(login, StringComparison.OrdinalIgnoreCase) && e.ExpiresUtc > now)
            .OrderBy(e => e.CreatedUtc)
            .Select(e => new LoginKeyInfo(e.Id, e.CreatedUtc, e.ExpiresUtc))
            .ToList();
    }

    /// <summary>Revoke one unused key, or all of them when <paramref name="id"/> is null.</summary>
    public int Revoke(string login, string? id = null)
    {
        var removed = 0;
        foreach (var (hash, e) in _keys)
            if (e.Login.Equals(login, StringComparison.OrdinalIgnoreCase) && (id == null || e.Id == id)
                && _keys.TryRemove(new KeyValuePair<string, Entry>(hash, e)))
                removed++;
        return removed;
    }

    private void Prune()
    {
        var now = DateTime.UtcNow;
        foreach (var (hash, e) in _keys)
            if (e.ExpiresUtc <= now) _keys.TryRemove(new KeyValuePair<string, Entry>(hash, e));
    }

    // ------------------------------------------------------------------ codes

    private static string Generate()
    {
        var chars = new char[Groups * GroupLength];
        for (var i = 0; i < chars.Length; i++)
            chars[i] = Alphabet[RandomNumberGenerator.GetInt32(Alphabet.Length)];
        return new string(chars);
    }

    /// <summary>"K7QM-R3XD-9FHW-2NBT": groups of four, for reading out and typing.</summary>
    public static string Format(string code) =>
        string.Join('-', Enumerable.Range(0, Groups).Select(g => code.Substring(g * GroupLength, GroupLength)));

    /// <summary>
    /// The code as typed, in any case, with or without dashes and spaces; null when it can't be one.
    /// Look-alikes of left-out symbols are not guessed at: a key never has them.
    /// </summary>
    public static string? Normalize(string? typed)
    {
        if (string.IsNullOrEmpty(typed) || typed.Length > 40) return null;
        var sb = new StringBuilder(Groups * GroupLength);
        foreach (var ch in typed)
        {
            if (ch is '-' or ' ') continue;
            var upper = char.ToUpperInvariant(ch);
            if (!Alphabet.Contains(upper)) return null;
            sb.Append(upper);
        }
        return sb.Length == Groups * GroupLength ? sb.ToString() : null;
    }

    private string Hash(string code) => Convert.ToHexString(HMACSHA256.HashData(_pepper, Encoding.ASCII.GetBytes(code)));
}
