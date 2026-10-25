// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using System.Text;

namespace Nullify.WebMail.Services;

/// <summary>
/// Tags are IMAP keywords (RFC 3501 flags without a backslash), so other mail clients see
/// the same ones. Names are stored the way Thunderbird stores them — spaces as underscores,
/// non-ASCII in modified UTF-7 — and Thunderbird's built-in $label1..5 get their usual names.
/// Colours are not stored on the server; they come from the name.
/// </summary>
public static class MailTags
{
    /// <summary>Keywords clients use for state rather than as tags; never shown.</summary>
    private static readonly HashSet<string> SystemKeywords = new(StringComparer.OrdinalIgnoreCase)
    {
        "$Forwarded", "$MDNSent", "$Junk", "$NotJunk", "Junk", "NonJunk", "NotJunk", "$Phishing",
        "$SubmitPending", "$Submitted", "$HasAttachment", "$HasNoAttachment", "$IsTrusted",
        "$Important", "$Notify", "$Muted", "$Followed", "$MailFlagBit0", "$MailFlagBit1", "$MailFlagBit2",
        "$autojunk", "$autonotjunk", "$Answered", "$Seen", "Forwarded", "Redirected", "$Redirected",
        "$Unsubscribed", "$Memo", "$HasMemo", "$CanUnsubscribe", "$Label0",
    };

    private static readonly Dictionary<string, (string Label, string Color)> Thunderbird =
        new(StringComparer.OrdinalIgnoreCase)
        {
            ["$label1"] = ("Important", "#ff5f57"),
            ["$label2"] = ("Work", "#ff9f0a"),
            ["$label3"] = ("Personal", "#30d158"),
            ["$label4"] = ("To Do", "#0a84ff"),
            ["$label5"] = ("Later", "#bf5af2"),
        };

    private static readonly (string Word, string Color)[] ColourWords =
    [
        ("red", "#ff5f57"), ("orange", "#ffaa44"), ("yellow", "#ffd23f"), ("green", "#30d158"),
        ("blue", "#3b9bff"), ("purple", "#c77dff"), ("violet", "#c77dff"), ("pink", "#ff7eb6"),
        ("grey", "#98a2b3"), ("gray", "#98a2b3"), ("brown", "#b07d2b"), ("teal", "#2ec4b6"),
        ("black", "#475467"),
    ];

    private static readonly string[] Palette =
    [
        // Mid tones: readable as text on both the light and the dark theme.
        "#c08a2e", "#7c5cff", "#3fa34d", "#f0703a", "#139c8f", "#e0487f", "#9775fa", "#2f9e44",
        "#d6336c", "#3d8bfd", "#e8890c", "#6f6af8",
    ];

    /// <summary>True for a keyword that should be offered as a tag.</summary>
    public static bool IsTag(string keyword) =>
        keyword.Length > 0 && keyword[0] != '\\' && !SystemKeywords.Contains(keyword);

    public static IEnumerable<string> Tags(IEnumerable<string>? keywords) => (keywords ?? []).Where(IsTag);

    /// <summary>The name to show for a keyword.</summary>
    public static string Label(string keyword)
    {
        if (Thunderbird.TryGetValue(keyword, out var known)) return known.Label;
        string text;
        try { text = ImapUtf7.Decode(keyword); }
        catch { text = keyword; }
        return text.Replace('_', ' ');
    }

    /// <summary>A CSS colour for the tag: Thunderbird's for its labels, a colour named in the tag, or a stable pick.</summary>
    public static string Color(string keyword)
    {
        if (Thunderbird.TryGetValue(keyword, out var known)) return known.Color;
        var words = Label(keyword).ToLowerInvariant()
            .Split([' ', '-', '_', '.'], StringSplitOptions.RemoveEmptyEntries);
        foreach (var (word, color) in ColourWords)
            if (words.Contains(word)) return color;
        var hash = 0u;
        foreach (var c in keyword.ToLowerInvariant()) hash = hash * 31 + c;
        return Palette[hash % (uint)Palette.Length];
    }

    /// <summary>
    /// The keyword for a tag name typed by the user: spaces and characters IMAP doesn't allow in
    /// an atom become underscores and non-ASCII is modified UTF-7, as Thunderbird does.
    /// Returns null for a name that can't be a tag.
    /// </summary>
    public static string? ToKeyword(string name)
    {
        name = name.Trim();
        if (name.Length == 0) return null;
        var sb = new StringBuilder();
        foreach (var c in name)
            sb.Append(c < 0x7f && (c <= ' ' || "(){%*\"\\]".Contains(c)) ? '_' : c);
        var keyword = ImapUtf7.Encode(sb.ToString());
        // '&' is fine in an atom, but a leading '\' would make it a system flag.
        keyword = keyword.TrimStart('\\');
        return keyword.Length is > 0 and <= 100 && IsTag(keyword) ? keyword : null;
    }

    /// <summary>True when <paramref name="keyword"/> is safe to send in a STORE command.</summary>
    public static bool IsValidKeyword(string keyword) =>
        keyword.Length is > 0 and <= 100 && keyword[0] != '\\'
        && keyword.All(c => c > ' ' && c < 0x7f && !"(){%*\"\\]".Contains(c));
}
