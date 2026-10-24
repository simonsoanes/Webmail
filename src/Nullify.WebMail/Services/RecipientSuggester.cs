// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using Nullify.WebMail.Shared;

namespace Nullify.WebMail.Services;

/// <summary>One address a recipient field can suggest (a contact may contribute several).</summary>
public sealed record RecipientCandidate(string Name, string Email, string? Label, string? Photo)
{
    public string Formatted => new MailFormat.Address(Name, Email).ToString();
}

/// <summary>Ranks contacts for the address being typed in To/Cc/Bcc.</summary>
public static class RecipientSuggester
{
    public static List<RecipientCandidate> FromContacts(IEnumerable<ContactInfo> contacts) =>
        contacts
            .SelectMany(c => c.Emails.Select(e => new RecipientCandidate(c.FullName, e.Value, e.Label, c.Photo)))
            .Where(c => c.Email.Contains('@'))
            .DistinctBy(c => c.Email.ToLowerInvariant())
            .ToList();

    /// <summary>The text being typed: everything after the last unquoted comma or semicolon.</summary>
    public static (string Prefix, string Token) CurrentToken(string value)
    {
        var quoted = false;
        var cut = -1;
        for (var i = 0; i < value.Length; i++)
        {
            if (value[i] == '"') quoted = !quoted;
            else if ((value[i] == ',' || value[i] == ';') && !quoted) cut = i;
        }
        return cut < 0 ? ("", value.Trim()) : (value[..(cut + 1)], value[(cut + 1)..].Trim());
    }

    /// <summary>
    /// Best matches for <paramref name="token"/>: a name or name-word prefix beats an address
    /// prefix, which beats a substring match (substrings only from 3 characters). Addresses
    /// already in the field are left out.
    /// </summary>
    public static List<RecipientCandidate> Rank(
        IReadOnlyList<RecipientCandidate> candidates, string token, IEnumerable<string> alreadyAdded, int max = 8)
    {
        token = token.Trim().Trim('"', '<');
        if (token.Length == 0) return [];
        var exclude = alreadyAdded.Select(a => a.ToLowerInvariant()).ToHashSet();

        return candidates
            .Where(c => !exclude.Contains(c.Email.ToLowerInvariant()))
            .Select(c => (Candidate: c, Score: Score(c, token)))
            .Where(x => x.Score > 0)
            .OrderByDescending(x => x.Score)
            .ThenBy(x => x.Candidate.Name, StringComparer.CurrentCultureIgnoreCase)
            // Stable sort: one person's addresses keep the card's order, preferred first.
            .Take(max)
            .Select(x => x.Candidate)
            .ToList();
    }

    private static int Score(RecipientCandidate c, string token)
    {
        const StringComparison ci = StringComparison.CurrentCultureIgnoreCase;
        if (c.Name.StartsWith(token, ci)) return 100;
        if (c.Name.Split([' ', '-', '.', '\''], StringSplitOptions.RemoveEmptyEntries).Any(w => w.StartsWith(token, ci))) return 80;
        if (c.Email.StartsWith(token, StringComparison.OrdinalIgnoreCase)) return 70;
        var domain = c.Email.IndexOf('@');
        if (domain >= 0 && c.Email[(domain + 1)..].StartsWith(token.TrimStart('@'), StringComparison.OrdinalIgnoreCase)) return 40;
        if (token.Length >= 3 && (c.Name.Contains(token, ci) || c.Email.Contains(token, StringComparison.OrdinalIgnoreCase))) return 20;
        return 0;
    }
}
