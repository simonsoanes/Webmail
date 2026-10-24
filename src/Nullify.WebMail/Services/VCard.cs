// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using System.Text;
using Nullify.WebMail.Shared;

namespace Nullify.WebMail.Services;

/// <summary>Minimal vCard 3.0/4.0 reader (RFC 2426 / RFC 6350) for the contacts list.</summary>
public static class VCard
{
    private const int MaxPhotoBytes = 256 * 1024;
    private const string CRLF = "\r\n";

    public static List<ContactInfo> Parse(string text, string? addressBookId = null)
    {
        var contacts = new List<ContactInfo>();
        List<(string Name, Dictionary<string, string> Params, string Value)>? props = null;
        var raw = new StringBuilder();

        foreach (var line in Unfold(text))
        {
            if (line.Equals("BEGIN:VCARD", StringComparison.OrdinalIgnoreCase)) { props = new(); raw.Clear().Append(line).Append(CRLF); continue; }
            if (props == null) continue;
            raw.Append(line).Append(CRLF);
            if (line.Equals("END:VCARD", StringComparison.OrdinalIgnoreCase))
            {
                if (Build(props, addressBookId) is { } c) contacts.Add(c with { RawCard = raw.ToString() });
                props = null;
                continue;
            }
            props.Add(SplitProperty(line));
        }
        return contacts;
    }

    // ------------------------------------------------------------------ writing

    /// <summary>Properties the editor owns; everything else in an existing card is kept verbatim.</summary>
    private static readonly HashSet<string> Managed =
        new(StringComparer.OrdinalIgnoreCase) { "FN", "N", "EMAIL", "TEL", "ORG", "TITLE", "NOTE", "BDAY", "REV" };

    /// <summary>
    /// Produce the card to store: <paramref name="existing"/> (if any) with the managed fields
    /// replaced from <paramref name="edit"/>. Labels attached to removed emails/phones through
    /// a group prefix ("item1.X-ABLabel") are removed with them.
    /// </summary>
    public static string Write(string? existing, ContactEdit edit, string uid)
    {
        var lines = existing != null ? Unfold(existing).ToList() : [];
        var begin = lines.FindIndex(l => l.Equals("BEGIN:VCARD", StringComparison.OrdinalIgnoreCase));
        var end = begin < 0 ? -1 : lines.FindIndex(begin, l => l.Equals("END:VCARD", StringComparison.OrdinalIgnoreCase));
        var body = begin >= 0 && end > begin ? lines[(begin + 1)..end] : [];

        var version = body.Select(SplitProperty).FirstOrDefault(p => p.Name == "VERSION").Value?.Trim() ?? "3.0";
        var v4 = version.StartsWith('4');

        // Groups whose main property we are replacing, e.g. "item1" of "item1.EMAIL".
        var droppedGroups = body.Where(l => Managed.Contains(SplitProperty(l).Name))
            .Select(GroupOf).Where(g => g != null).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var kept = body.Where(l =>
        {
            var prop = SplitProperty(l);
            if (prop.Name is "VERSION" or "UID" || Managed.Contains(prop.Name)) return false;
            // An OpenPGP KEY is replaced only when the edit says so; other KEYs (X.509...) always stay.
            if (edit.PublicKey != null && prop.Name == "KEY" && IsPgpKey(prop.Params, prop.Value)) return false;
            return GroupOf(l) is not { } g || !droppedGroups.Contains(g);
        }).ToList();

        var given = edit.GivenName?.Trim() ?? "";
        var family = edit.FamilyName?.Trim() ?? "";
        var fn = string.Join(" ", new[] { given, family }.Where(x => x.Length > 0));
        if (fn.Length == 0) fn = edit.Organization?.Trim() ?? edit.Emails.FirstOrDefault()?.Value ?? "Unnamed";

        var output = new List<string> { "BEGIN:VCARD", "VERSION:" + version };
        if (existing == null) output.Add("PRODID:-//Nullify//WebMail//EN");
        output.Add("UID:" + uid);
        output.Add("FN:" + Escape(fn));
        output.Add($"N:{Escape(family)};{Escape(given)};;;");
        if (!string.IsNullOrWhiteSpace(edit.Organization)) output.Add("ORG:" + Escape(edit.Organization.Trim()));
        if (!string.IsNullOrWhiteSpace(edit.Title)) output.Add("TITLE:" + Escape(edit.Title.Trim()));

        var first = true;
        foreach (var e in edit.Emails.Where(e => !string.IsNullOrWhiteSpace(e.Value)))
        {
            var types = new List<string>();
            if (!v4) types.Add("INTERNET");
            if (LabelType(e.Label, phone: false) is { } t) types.Add(t);
            if (first && !v4) types.Add("pref");
            var param = (types.Count > 0 ? ";TYPE=" + string.Join(",", types) : "") + (first && v4 ? ";PREF=1" : "");
            output.Add($"EMAIL{param}:{Escape(e.Value.Trim())}");
            first = false;
        }
        foreach (var p in edit.Phones.Where(p => !string.IsNullOrWhiteSpace(p.Value)))
        {
            var type = LabelType(p.Label, phone: true);
            output.Add($"TEL{(type != null ? ";TYPE=" + type : "")}:{Escape(p.Value.Trim())}");
        }
        if (!string.IsNullOrWhiteSpace(edit.Birthday)) output.Add("BDAY:" + Escape(edit.Birthday.Trim()));
        if (!string.IsNullOrWhiteSpace(edit.Note)) output.Add("NOTE:" + Escape(edit.Note.Trim()));
        if (!string.IsNullOrWhiteSpace(edit.PublicKey) && OpenPgpArmor.Dearmor(edit.PublicKey) is { } keyBytes)
        {
            var b64 = Convert.ToBase64String(keyBytes);
            output.Add(v4 ? "KEY:data:application/pgp-keys;base64," + b64 : "KEY;TYPE=PGP;ENCODING=b:" + b64);
        }

        output.AddRange(kept);
        output.Add("REV:" + DateTime.UtcNow.ToString("yyyyMMdd'T'HHmmss'Z'"));
        output.Add("END:VCARD");
        return string.Concat(output.Select(l => Fold(l) + "\r\n"));
    }

    private static string? GroupOf(string line)
    {
        var colon = line.IndexOf(':');
        var semi = line.IndexOf(';');
        var nameEnd = semi >= 0 && (colon < 0 || semi < colon) ? semi : colon;
        if (nameEnd < 0) return null;
        var dot = line.IndexOf('.', 0, nameEnd);
        return dot > 0 ? line[..dot] : null;
    }

    /// <summary>Editor label → TYPE value (null for "Other"/custom labels, which vCard has no type for).</summary>
    private static string? LabelType(string? label, bool phone) => label?.Trim().ToLowerInvariant() switch
    {
        "work" => "WORK",
        "home" => "HOME",
        "mobile" or "cell" when phone => "CELL",
        "fax" when phone => "FAX",
        "main" when phone => "MAIN",
        _ => null,
    };

    private static string Escape(string s) =>
        s.Replace("\\", "\\\\").Replace(";", "\\;").Replace(",", "\\,").Replace("\r\n", "\n").Replace("\r", "\n").Replace("\n", "\\n");

    /// <summary>RFC 6350 3.2: lines over 75 octets are folded, never splitting a UTF-8 sequence.</summary>
    public static string Fold(string line)
    {
        if (Encoding.UTF8.GetByteCount(line) <= 75) return line;
        var sb = new StringBuilder();
        var count = 0;
        foreach (var rune in line.EnumerateRunes())
        {
            var size = rune.Utf8SequenceLength;
            if (count + size > 75)
            {
                sb.Append("\r\n ");
                count = 1;
            }
            sb.Append(rune.ToString());
            count += size;
        }
        return sb.ToString();
    }

    private static ContactInfo? Build(List<(string Name, Dictionary<string, string> Params, string Value)> props, string? book)
    {
        string? One(string name) => props.FirstOrDefault(p => p.Name == name).Value is { } v ? Unescape(v).Trim() : null;
        IEnumerable<(Dictionary<string, string> Params, string Value)> All(string name) =>
            props.Where(p => p.Name == name).Select(p => (p.Params, p.Value));

        // Contact groups (KIND:group / X-ADDRESSBOOKSERVER-KIND) aren't people.
        var kind = (One("KIND") ?? One("X-ADDRESSBOOKSERVER-KIND"))?.ToLowerInvariant();
        if (kind is "group" or "org" && !All("EMAIL").Any()) return null;

        var emails = All("EMAIL").Select(e => new ContactValue(Unescape(e.Value).Trim(), TypeLabel(e.Params)))
            .Where(e => e.Value.Length > 0).ToList();
        var phones = All("TEL").Select(t => new ContactValue(Unescape(StripTelUri(t.Value)).Trim(), TypeLabel(t.Params)))
            .Where(t => t.Value.Length > 0).ToList();

        var name = One("FN");
        // N = family;given;additional;prefix;suffix
        var nParts = props.Any(p => p.Name == "N") ? SplitStructured(props.First(p => p.Name == "N").Value) : null;
        if (string.IsNullOrWhiteSpace(name) && nParts != null)
        {
            name = string.Join(" ", new[] { Get(nParts, 3), Get(nParts, 1), Get(nParts, 2), Get(nParts, 0), Get(nParts, 4) }
                .Where(s => !string.IsNullOrWhiteSpace(s)));
        }
        string? given = nParts != null ? NullIfEmpty(string.Join(" ", new[] { Get(nParts, 1), Get(nParts, 2) }.Where(x => x.Length > 0))) : null;
        string? family = nParts != null ? NullIfEmpty(Get(nParts, 0)) : null;
        if (given == null && family == null && !string.IsNullOrWhiteSpace(One("FN")))
        {
            // No N: split the display name for the editor ("Ada Lovelace" → Ada / Lovelace).
            var words = One("FN")!.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            given = words.Length > 1 ? string.Join(" ", words[..^1]) : words[0];
            family = words.Length > 1 ? words[^1] : null;
        }
        var org = props.FirstOrDefault(p => p.Name == "ORG").Value is { } o
            ? string.Join(", ", SplitStructured(o).Where(s => s.Length > 0)) : null;
        if (string.IsNullOrWhiteSpace(name)) name = org ?? emails.FirstOrDefault()?.Value ?? phones.FirstOrDefault()?.Value;
        if (string.IsNullOrWhiteSpace(name)) return null;

        return new ContactInfo(
            One("UID") ?? Guid.NewGuid().ToString(), name.Trim(),
            emails.FirstOrDefault()?.Value, phones.FirstOrDefault()?.Value, NullIfEmpty(org))
        {
            Emails = emails,
            Phones = phones,
            Title = NullIfEmpty(One("TITLE")),
            Note = NullIfEmpty(One("NOTE")),
            Birthday = NullIfEmpty(One("BDAY")),
            Photo = Photo(props.FirstOrDefault(p => p.Name == "PHOTO")),
            PublicKey = props.Where(p => p.Name == "KEY").Select(p => PgpKeyOf(p.Params, p.Value)).FirstOrDefault(k => k != null),
            AddressBookId = book,
            GivenName = given,
            FamilyName = family,
        };
    }

    /// <summary>Is this KEY property an OpenPGP key (by type, media type or data: URI)?</summary>
    private static bool IsPgpKey(Dictionary<string, string> parameters, string value)
    {
        var type = (parameters.GetValueOrDefault("TYPE") + "," + parameters.GetValueOrDefault("MEDIATYPE")).ToLowerInvariant();
        return type.Contains("pgp") || value.TrimStart().StartsWith("data:application/pgp-keys", StringComparison.OrdinalIgnoreCase)
               || value.Contains("BEGIN PGP PUBLIC KEY BLOCK");
    }

    /// <summary>
    /// The OpenPGP key in a KEY property, armored. Accepts vCard 3 (TYPE=PGP;ENCODING=b) and
    /// vCard 4 (data:application/pgp-keys[;base64],...) forms; key URLs are not fetched.
    /// </summary>
    private static string? PgpKeyOf(Dictionary<string, string> parameters, string value)
    {
        if (!IsPgpKey(parameters, value)) return null;
        var v = value.Trim();
        try
        {
            if (v.StartsWith("data:", StringComparison.OrdinalIgnoreCase))
            {
                var comma = v.IndexOf(',');
                if (comma < 0) return null;
                var meta = v[..comma];
                var payload = v[(comma + 1)..];
                if (meta.EndsWith(";base64", StringComparison.OrdinalIgnoreCase))
                {
                    var bytes = Convert.FromBase64String(payload);
                    return bytes.Length > 0 && bytes[0] == '-' ? Encoding.UTF8.GetString(bytes) : OpenPgpArmor.Armor("PGP PUBLIC KEY BLOCK", bytes);
                }
                var text = Uri.UnescapeDataString(payload);
                return text.Contains("BEGIN PGP") ? Unescape(text) : null;
            }
            if (v.Contains("BEGIN PGP PUBLIC KEY BLOCK")) return Unescape(v);
            var enc = parameters.GetValueOrDefault("ENCODING")?.ToLowerInvariant();
            if (enc is "b" or "base64") return OpenPgpArmor.Armor("PGP PUBLIC KEY BLOCK", Convert.FromBase64String(v));
        }
        catch (FormatException) { }
        return null;
    }

    /// <summary>Inline photos only, as a data: URI. Remote photo URLs are ignored (they would leak who you look at).</summary>
    private static string? Photo((string Name, Dictionary<string, string> Params, string Value) p)
    {
        if (p.Name == null || string.IsNullOrWhiteSpace(p.Value)) return null;
        var value = p.Value.Trim();
        if (value.StartsWith("data:image/", StringComparison.OrdinalIgnoreCase))
            return value.Length <= MaxPhotoBytes * 4 / 3 + 64 && value.Contains(";base64,") ? value : null;

        // vCard 3.0: PHOTO;ENCODING=b;TYPE=JPEG:<base64>
        var encoding = p.Params.GetValueOrDefault("ENCODING")?.ToLowerInvariant();
        if (encoding is not ("b" or "base64")) return null;
        var type = (p.Params.GetValueOrDefault("TYPE") ?? "jpeg").ToLowerInvariant();
        type = type switch { "jpg" or "jpeg" => "jpeg", "png" => "png", "gif" => "gif", "webp" => "webp", _ => "" };
        if (type.Length == 0) return null;
        try
        {
            var bytes = Convert.FromBase64String(value);
            return bytes.Length <= MaxPhotoBytes ? $"data:image/{type};base64,{Convert.ToBase64String(bytes)}" : null;
        }
        catch (FormatException) { return null; }
    }

    private static string? TypeLabel(Dictionary<string, string> parameters)
    {
        if (!parameters.TryGetValue("TYPE", out var t)) return null;
        var types = t.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(x => x.ToLowerInvariant())
            .Where(x => x is not ("internet" or "pref" or "voice" or "x400"))
            .ToList();
        if (types.Count == 0) return null;
        var label = types[0] switch { "cell" => "mobile", "x-mobile" => "mobile", var x => x.StartsWith("x-") ? x[2..] : x };
        return char.ToUpperInvariant(label[0]) + label[1..];
    }

    private static string StripTelUri(string v) => v.StartsWith("tel:", StringComparison.OrdinalIgnoreCase) ? v[4..] : v;

    private static string Get(List<string> parts, int i) => i < parts.Count ? parts[i] : "";

    /// <summary>Split a structured value on unescaped ';' and unescape each part.</summary>
    private static List<string> SplitStructured(string value)
    {
        var parts = new List<string>();
        var sb = new StringBuilder();
        for (var i = 0; i < value.Length; i++)
        {
            if (value[i] == '\\' && i + 1 < value.Length) { sb.Append(value[i]).Append(value[++i]); continue; }
            if (value[i] == ';') { parts.Add(Unescape(sb.ToString()).Trim()); sb.Clear(); continue; }
            sb.Append(value[i]);
        }
        parts.Add(Unescape(sb.ToString()).Trim());
        return parts;
    }

    private static IEnumerable<string> Unfold(string text)
    {
        var current = new StringBuilder();
        foreach (var raw in text.Replace("\r\n", "\n").Split('\n'))
        {
            if (raw.Length > 0 && (raw[0] == ' ' || raw[0] == '\t'))
            {
                current.Append(raw, 1, raw.Length - 1);
                continue;
            }
            if (current.Length > 0) yield return current.ToString();
            current.Clear().Append(raw.TrimEnd('\r'));
        }
        if (current.Length > 0) yield return current.ToString();
    }

    /// <summary>"item1.EMAIL;TYPE=work:x" → ("EMAIL", {TYPE: work}, "x"). Group prefixes are dropped.</summary>
    private static (string Name, Dictionary<string, string> Params, string Value) SplitProperty(string line)
    {
        var quoted = false;
        var colon = -1;
        for (var i = 0; i < line.Length; i++)
        {
            if (line[i] == '"') quoted = !quoted;
            else if (line[i] == ':' && !quoted) { colon = i; break; }
        }
        if (colon < 0) return (line.ToUpperInvariant(), new(), "");
        var head = line[..colon].Split(';');
        var name = head[0];
        var dot = name.IndexOf('.');
        if (dot >= 0) name = name[(dot + 1)..];
        var parameters = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var p in head.Skip(1))
        {
            var eq = p.IndexOf('=');
            // vCard 2.1/3.0 allow bare types: "TEL;CELL:..." means TYPE=CELL.
            var (key, val) = eq > 0 ? (p[..eq], p[(eq + 1)..].Trim('"')) : ("TYPE", p);
            parameters[key] = parameters.TryGetValue(key, out var existing) ? existing + "," + val : val;
        }
        return (name.ToUpperInvariant(), parameters, line[(colon + 1)..]);
    }

    private static string Unescape(string s) =>
        s.Replace("\\n", "\n").Replace("\\N", "\n").Replace("\\,", ",").Replace("\\;", ";").Replace("\\\\", "\\");

    private static string? NullIfEmpty(string? s) => string.IsNullOrWhiteSpace(s) ? null : s.Trim();
}
