// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using System.Globalization;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using Nullify.WebMail.Shared;

namespace Nullify.WebMail.Services;

/// <summary>Display helpers shared by the mail components.</summary>
public static partial class MailFormat
{
    public sealed record Address(string Name, string Email)
    {
        public string Display => Name.Length > 0 ? Name : Email;
        public override string ToString() => Name.Length > 0 ? $"{Name} <{Email}>" : Email;
    }

    /// <summary>Split an address-list header on commas that are not inside quotes or angle brackets.</summary>
    public static List<Address> ParseAddressList(string? header)
    {
        var list = new List<Address>();
        if (string.IsNullOrWhiteSpace(header)) return list;
        var sb = new StringBuilder();
        bool quoted = false, angle = false;
        foreach (var c in header)
        {
            if (c == '"') quoted = !quoted;
            else if (c == '<' && !quoted) angle = true;
            else if (c == '>' && !quoted) angle = false;
            if ((c == ',' || c == ';') && !quoted && !angle)
            {
                AddParsed(list, sb.ToString());
                sb.Clear();
                continue;
            }
            sb.Append(c);
        }
        AddParsed(list, sb.ToString());
        return list;
    }

    private static void AddParsed(List<Address> list, string raw)
    {
        var a = ParseAddress(raw);
        if (a.Email.Length > 0 || a.Name.Length > 0) list.Add(a);
    }

    public static Address ParseAddress(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return new Address("", "");
        raw = raw.Trim();
        var lt = raw.LastIndexOf('<');
        var gt = raw.LastIndexOf('>');
        if (lt >= 0 && gt > lt)
        {
            var email = raw[(lt + 1)..gt].Trim();
            var name = raw[..lt].Trim().Trim('"').Replace("\\\"", "\"").Trim();
            return new Address(name == email ? "" : name, email);
        }
        // "addr (Name)" legacy form
        var paren = raw.IndexOf('(');
        if (paren > 0 && raw.EndsWith(')'))
            return new Address(raw[(paren + 1)..^1].Trim(), raw[..paren].Trim());
        return new Address("", raw.Trim('"'));
    }

    public static string Initials(Address a)
    {
        var source = a.Name.Length > 0 ? a.Name : a.Email.Split('@')[0];
        var words = source.Split([' ', '.', '_', '-'], StringSplitOptions.RemoveEmptyEntries)
            .Where(w => char.IsLetterOrDigit(w[0])).ToArray();
        if (words.Length == 0) return "?";
        var first = char.ToUpperInvariant(words[0][0]);
        return words.Length > 1 ? $"{first}{char.ToUpperInvariant(words[^1][0])}" : first.ToString();
    }

    /// <summary>Stable hue (0–359) for an avatar, keyed on the address.</summary>
    public static int AvatarHue(Address a)
    {
        var key = (a.Email.Length > 0 ? a.Email : a.Name).ToLowerInvariant();
        uint h = 2166136261;
        foreach (var c in key) h = (h ^ c) * 16777619;
        return (int)(h % 360);
    }

    // ------------------------------------------------------------------ dates

    public static DateTimeOffset? ParseDate(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return null;
        var s = CommentRx().Replace(raw, "").Trim();
        s = TzNameRx().Replace(s, " +00:00");
        s = NumericTzRx().Replace(s, "$1:$2");
        if (DateTimeOffset.TryParse(s, CultureInfo.InvariantCulture, DateTimeStyles.AllowWhiteSpaces, out var dt)) return dt;
        // Day-of-week mismatches make the strict parser bail; retry without it.
        var comma = s.IndexOf(',');
        if (comma > 0 && DateTimeOffset.TryParse(s[(comma + 1)..], CultureInfo.InvariantCulture,
                DateTimeStyles.AllowWhiteSpaces, out dt)) return dt;
        return null;
    }

    [GeneratedRegex(@"\([^)]*\)")]
    private static partial Regex CommentRx();
    [GeneratedRegex(@"\s+(GMT|UTC|UT|Z)$", RegexOptions.IgnoreCase)]
    private static partial Regex TzNameRx();
    [GeneratedRegex(@"([+-]\d{2})(\d{2})$")]
    private static partial Regex NumericTzRx();

    /// <summary>Compact list date: time today, weekday this week, "12 Mar" this year, else d/m/yyyy.</summary>
    public static string ListDate(string? raw, TimeZoneInfo tz)
    {
        var parsed = ParseDate(raw);
        if (parsed == null) return "";
        var local = TimeZoneInfo.ConvertTime(parsed.Value, tz);
        var now = TimeZoneInfo.ConvertTime(DateTimeOffset.UtcNow, tz);
        if (local.Date == now.Date) return local.ToString("HH:mm", CultureInfo.InvariantCulture);
        if (local.Date == now.Date.AddDays(-1)) return "Yesterday";
        if (local.Date > now.Date.AddDays(-7) && local.Date < now.Date) return local.ToString("ddd", CultureInfo.InvariantCulture);
        if (local.Year == now.Year) return local.ToString("d MMM", CultureInfo.InvariantCulture);
        return local.ToString("d MMM yyyy", CultureInfo.InvariantCulture);
    }

    public static string FullDate(string? raw, TimeZoneInfo tz)
    {
        var parsed = ParseDate(raw);
        if (parsed == null) return raw ?? "";
        var local = TimeZoneInfo.ConvertTime(parsed.Value, tz);
        return local.ToString("ddd d MMM yyyy, HH:mm", CultureInfo.InvariantCulture);
    }

    public static string Size(long bytes) => bytes switch
    {
        < 1024 => $"{bytes} B",
        < 1024 * 1024 => $"{bytes / 1024.0:0.#} KB",
        _ => $"{bytes / (1024.0 * 1024):0.#} MB",
    };

    // ------------------------------------------------------------------ folders

    public static string FolderLeaf(FolderInfo f)
    {
        if (f.SpecialUse == "Inbox") return "Inbox";
        if (string.IsNullOrEmpty(f.Delimiter)) return f.Name;
        var parts = f.Name.Split(f.Delimiter[0]);
        return parts[^1];
    }

    public static int FolderDepth(FolderInfo f)
    {
        if (string.IsNullOrEmpty(f.Delimiter)) return 0;
        var depth = f.Name.Count(c => c == f.Delimiter[0]);
        // Children of INBOX ("INBOX.Lists") sit at top level visually when INBOX is the namespace root.
        if (f.Name.StartsWith("INBOX" + f.Delimiter, StringComparison.OrdinalIgnoreCase)) depth--;
        return Math.Max(0, depth);
    }

    public static string FolderIcon(FolderInfo f) => f.SpecialUse switch
    {
        "Inbox" => "inbox",
        "Sent" => "send",
        "Drafts" => "file",
        "Trash" => "trash",
        "Junk" => "alert",
        "Archive" => "archive",
        _ => "folder",
    };

    /// <summary>
    /// The folders as a tree. Siblings the user has arranged (<paramref name="customOrder"/>, from
    /// dragging) keep that order; the rest follow, special folders first in a conventional order,
    /// then alphabetically.
    /// </summary>
    public static List<FolderInfo> OrderFolders(IEnumerable<FolderInfo> folders, IReadOnlyList<string>? customOrder = null)
    {
        string[] order = ["Inbox", "Drafts", "Sent", "Archive", "Junk", "Trash"];
        var all = folders.ToList();
        var names = all.Select(f => f.Name).ToHashSet(StringComparer.Ordinal);
        var custom = new Dictionary<string, int>(StringComparer.Ordinal);
        for (var i = 0; i < (customOrder?.Count ?? 0); i++) custom.TryAdd(customOrder![i], i);
        var byParent = all.GroupBy(f => ParentOf(f, names)).ToDictionary(g => g.Key, g => g.ToList());

        var result = new List<FolderInfo>(all.Count);
        var seen = new HashSet<string>(StringComparer.Ordinal);
        void Walk(string parent)
        {
            if (!byParent.TryGetValue(parent, out var children)) return;
            foreach (var f in children
                         .OrderBy(f => custom.TryGetValue(f.Name, out var i) ? i : int.MaxValue)
                         .ThenBy(f => f.SpecialUse != null && FolderDepth(f) == 0 && Array.IndexOf(order, f.SpecialUse) is >= 0 and var i ? i : order.Length)
                         .ThenBy(f => f.Name, StringComparer.OrdinalIgnoreCase))
            {
                if (!seen.Add(f.Name)) continue;
                result.Add(f);
                Walk(f.Name);
            }
        }
        Walk("");
        return result;
    }

    /// <summary>
    /// The folder this one is shown under: its nearest listed ancestor, or "" at the top level
    /// (which includes INBOX's children on servers that put every folder under INBOX).
    /// </summary>
    public static string ParentOf(FolderInfo f, IReadOnlySet<string> names)
    {
        if (string.IsNullOrEmpty(f.Delimiter) || FolderDepth(f) == 0) return "";
        var name = f.Name;
        for (var cut = name.LastIndexOf(f.Delimiter[0]); cut > 0; cut = name.LastIndexOf(f.Delimiter[0]))
        {
            name = name[..cut];
            if (name.Equals("INBOX", StringComparison.OrdinalIgnoreCase)) break;
            if (names.Contains(name)) return name;
        }
        return "";
    }

    /// <summary>
    /// The custom order after dropping <paramref name="dragged"/> next to <paramref name="target"/>
    /// (after it when <paramref name="after"/>), or null when they aren't siblings.
    /// </summary>
    public static List<string>? MoveFolder(IReadOnlyList<FolderInfo> folders, IReadOnlyList<string> customOrder,
        string dragged, string target, bool after)
    {
        if (dragged == target) return null;
        var names = folders.Select(f => f.Name).ToHashSet(StringComparer.Ordinal);
        var d = folders.FirstOrDefault(f => f.Name == dragged);
        var t = folders.FirstOrDefault(f => f.Name == target);
        if (d == null || t == null) return null;
        var parent = ParentOf(d, names);
        if (ParentOf(t, names) != parent) return null;

        var siblings = OrderFolders(folders, customOrder)
            .Where(f => ParentOf(f, names) == parent).Select(f => f.Name).ToList();
        siblings.Remove(dragged);
        siblings.Insert(siblings.IndexOf(target) + (after ? 1 : 0), dragged);
        // Only the names of folders that still exist are kept.
        return customOrder.Where(n => names.Contains(n) && !siblings.Contains(n)).Concat(siblings).ToList();
    }

    // ------------------------------------------------------------------ bodies

    /// <summary>Plain text → safe HTML with clickable links and styled quote blocks.</summary>
    public static string TextToHtml(string text)
    {
        var sb = new StringBuilder();
        var inQuote = false;
        foreach (var rawLine in text.Replace("\r\n", "\n").Split('\n'))
        {
            var isQuote = rawLine.StartsWith('>');
            if (isQuote != inQuote)
            {
                sb.Append(isQuote ? "<blockquote>" : "</blockquote>");
                inQuote = isQuote;
            }
            var line = isQuote ? rawLine.TrimStart('>', ' ') : rawLine;
            var encoded = WebUtility.HtmlEncode(line);
            encoded = UrlRx().Replace(encoded, m =>
            {
                var url = m.Value;
                var trail = "";
                while (url.Length > 0 && ".,;:!?)".Contains(url[^1])) { trail = url[^1] + trail; url = url[..^1]; }
                return $"<a href=\"{url}\" target=\"_blank\" rel=\"noopener noreferrer\">{url}</a>{trail}";
            });
            sb.Append(encoded).Append('\n');
        }
        if (inQuote) sb.Append("</blockquote>");
        return sb.ToString();
    }

    [GeneratedRegex(@"https?://[^\s<>""']+", RegexOptions.IgnoreCase)]
    private static partial Regex UrlRx();

    /// <summary>Rough HTML → text for quoting a reply when only an HTML body exists.</summary>
    public static string HtmlToText(string html)
    {
        var s = Regex.Replace(html, @"<(script|style|head)[^>]*>.*?</\1>", "", RegexOptions.Singleline | RegexOptions.IgnoreCase);
        s = Regex.Replace(s, @"<br\s*/?>|</p>|</div>|</tr>|</h\d>|</li>", "\n", RegexOptions.IgnoreCase);
        s = Regex.Replace(s, "<[^>]+>", "");
        s = WebUtility.HtmlDecode(s);
        s = Regex.Replace(s, @"[ \t]+\n", "\n");
        s = Regex.Replace(s, @"\n{3,}", "\n\n");
        return s.Trim();
    }

    /// <summary>
    /// High priority by any of the headers mail apps use: Importance: high (RFC 2156),
    /// X-Priority 1 or 2 (Outlook and most others), or Priority: urgent (RFC 2156).
    /// </summary>
    public static bool IsImportant(string? importance, string? xPriority, string? priority) =>
        importance?.Trim().StartsWith("high", StringComparison.OrdinalIgnoreCase) == true
        || xPriority?.TrimStart() is ['1' or '2', ..]
        || priority?.Trim().StartsWith("urgent", StringComparison.OrdinalIgnoreCase) == true;

    /// <summary>True when the HTML would fetch anything from the network.</summary>
    public static bool HasRemoteContent(string html) => RemoteRx().IsMatch(html);

    [GeneratedRegex(@"(src|background|poster|srcset)\s*=\s*[""']?\s*(https?:)?//|url\(\s*[""']?\s*(https?:)?//|<link\b", RegexOptions.IgnoreCase)]
    private static partial Regex RemoteRx();
}
