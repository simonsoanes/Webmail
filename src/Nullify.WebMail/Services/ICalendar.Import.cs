// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using System.Text;

namespace Nullify.WebMail.Services;

/// <summary>Turning an .ics file (one opened with the installed app, say) into CalDAV resources.</summary>
public static partial class ICalendar
{
    /// <summary>
    /// Split a calendar file into one VCALENDAR per event UID, as CalDAV stores them (RFC 4791 §4.1):
    /// a series and its overrides stay together, each copy carries only the VTIMEZONEs it uses,
    /// and METHOD (an invitation's iTIP wrapper) is dropped. Lines are kept as written, folding
    /// included, so nothing the reader doesn't understand is lost. Other components are skipped.
    /// </summary>
    public static List<(string Uid, string Ics)> SplitForImport(string ics)
    {
        var header = new List<string>();
        var zones = new List<(string Tzid, List<string> Lines)>();
        var events = new List<(string Uid, List<string> Lines)>();

        List<string>? block = null;
        string kind = "";
        var depth = 0;
        var skipping = false; // inside a dropped top-level property and its continuation lines

        foreach (var line in ics.Replace("\r\n", "\n").Split('\n'))
        {
            if (line.Length == 0) continue;
            var continuation = line[0] is ' ' or '\t';
            if (block != null)
            {
                block.Add(line);
                if (continuation) continue;
                if (line.StartsWith("BEGIN:", StringComparison.OrdinalIgnoreCase)) depth++;
                else if (line.StartsWith("END:", StringComparison.OrdinalIgnoreCase) && depth-- == 0)
                {
                    if (kind == "VTIMEZONE") zones.Add((TopLevelValue(block, "TZID") ?? "", block));
                    else if (kind == "VEVENT") events.Add((TopLevelValue(block, "UID") ?? "", block));
                    block = null;
                }
                continue;
            }
            if (continuation) { if (!skipping) header.Add(line); continue; }
            if (line.StartsWith("BEGIN:", StringComparison.OrdinalIgnoreCase))
            {
                kind = line[6..].Trim().ToUpperInvariant();
                if (kind == "VCALENDAR") continue;
                block = [line];
                depth = 0;
                continue;
            }
            if (line.StartsWith("END:", StringComparison.OrdinalIgnoreCase)) continue;
            skipping = line.StartsWith("METHOD", StringComparison.OrdinalIgnoreCase) && line.Length > 6 && line[6] is ':' or ';';
            if (!skipping) header.Add(line);
        }

        if (!header.Any(l => l.StartsWith("VERSION", StringComparison.OrdinalIgnoreCase))) header.Insert(0, "VERSION:2.0");
        if (!header.Any(l => l.StartsWith("PRODID", StringComparison.OrdinalIgnoreCase))) header.Insert(1, "PRODID:-//Nullify//WebMail//EN");

        var result = new List<(string Uid, string Ics)>();
        foreach (var group in GroupByUid(events))
        {
            var body = group.Lines.SelectMany(l => l).ToList();
            var text = string.Join("\n", Unfold(string.Join("\r\n", body)));
            var sb = new StringBuilder("BEGIN:VCALENDAR\r\n");
            foreach (var l in header) sb.Append(l).Append("\r\n");
            foreach (var (tzid, lines) in zones)
                if (tzid.Length > 0 && (text.Contains("TZID=" + tzid, StringComparison.Ordinal) || text.Contains("TZID=\"" + tzid + "\"", StringComparison.Ordinal)))
                    foreach (var l in lines) sb.Append(l).Append("\r\n");
            foreach (var l in body) sb.Append(l).Append("\r\n");
            sb.Append("END:VCALENDAR\r\n");
            result.Add((group.Uid, sb.ToString()));
        }
        return result;
    }

    /// <summary>Events sharing a UID (a series and its overrides) go together; one without a UID is given its own.</summary>
    private static IEnumerable<(string Uid, List<List<string>> Lines)> GroupByUid(List<(string Uid, List<string> Lines)> events)
    {
        var groups = new List<(string Uid, List<List<string>> Lines)>();
        foreach (var (uid, lines) in events)
        {
            if (uid.Length == 0)
            {
                var fresh = Guid.NewGuid().ToString();
                lines.Insert(1, "UID:" + fresh);
                groups.Add((fresh, [lines]));
                continue;
            }
            var existing = groups.FindIndex(g => g.Uid == uid);
            if (existing >= 0) groups[existing].Lines.Add(lines);
            else groups.Add((uid, [lines]));
        }
        return groups;
    }

    /// <summary>A property's value on the component itself, not inside a nested one (a VALARM, a STANDARD...).</summary>
    private static string? TopLevelValue(List<string> block, string name)
    {
        var depth = 0;
        foreach (var line in Unfold(string.Join("\r\n", block)).Skip(1))
        {
            if (line.StartsWith("BEGIN:", StringComparison.OrdinalIgnoreCase)) { depth++; continue; }
            if (line.StartsWith("END:", StringComparison.OrdinalIgnoreCase)) { depth--; continue; }
            if (depth != 0) continue;
            var (n, _, value) = SplitProperty(line);
            if (n.Equals(name, StringComparison.OrdinalIgnoreCase)) return value.Trim();
        }
        return null;
    }
}
