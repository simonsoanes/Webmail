// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using System.Globalization;
using System.Text;
using Nullify.WebMail.Shared;

namespace Nullify.WebMail.Services;

/// <summary>
/// A VEVENT as written. Times are kept as wall-clock values in <see cref="Zone"/> so that
/// recurrences keep their local time across DST changes. All-day events have no zone.
/// </summary>
public sealed class ICalEvent
{
    public string Uid { get; init; } = "";
    public string Summary { get; init; } = "";
    public string? Location { get; init; }
    public string? Description { get; init; }
    public string? Status { get; init; }
    public bool AllDay { get; init; }
    public DateTime StartWall { get; init; }
    public DateTime EndWall { get; init; }
    public TimeZoneInfo Zone { get; init; } = TimeZoneInfo.Utc;
    public string? RRule { get; init; }
    public List<DateTime> ExDatesWall { get; } = new();
    public DateTime? RecurrenceIdWall { get; init; }
    /// <summary>Set on instances produced by <see cref="ICalendar.Expand"/> from an RRULE.</summary>
    public bool FromSeries { get; init; }
    public EventAttendee? Organizer { get; init; }
    public List<EventAttendee> Attendees { get; init; } = new();
    public int Sequence { get; init; }

    public bool IsRecurring => RRule != null || RecurrenceIdWall != null || FromSeries;

    /// <summary>The occurrence's identity in the series: its RECURRENCE-ID, or its start if expanded locally.</summary>
    public DateTimeOffset? OccurrenceId =>
        RecurrenceIdWall is { } r ? ToOffset(r) : FromSeries ? Start : null;

    public DateTimeOffset Start => ToOffset(StartWall);
    public DateTimeOffset End => ToOffset(EndWall);

    /// <summary>All-day values are dates, pinned to UTC so they never shift across zones.</summary>
    public DateTimeOffset ToOffset(DateTime wall) =>
        AllDay ? new DateTimeOffset(wall.Date, TimeSpan.Zero) : new DateTimeOffset(wall, Zone.GetUtcOffset(wall));
}

/// <summary>Minimal RFC 5545 reader: VEVENTs, TZID times, and RRULE expansion for the common cases.</summary>
public static partial class ICalendar
{
    /// <param name="floatingZone">Zone for times with no TZID or Z suffix (the viewer's zone).</param>
    public static List<ICalEvent> ParseEvents(string ics, TimeZoneInfo floatingZone)
    {
        var events = new List<ICalEvent>();
        Dictionary<string, (string Value, Dictionary<string, string> Params)>? props = null;
        List<(string Value, Dictionary<string, string> Params)>? exdates = null;
        List<EventAttendee>? attendees = null;
        var depth = 0; // nesting inside VEVENT (VALARM etc.)

        foreach (var line in Unfold(ics))
        {
            if (line.Equals("BEGIN:VEVENT", StringComparison.OrdinalIgnoreCase))
            {
                props = new(StringComparer.OrdinalIgnoreCase);
                exdates = new();
                attendees = new();
                depth = 0;
                continue;
            }
            if (props == null) continue;
            if (line.StartsWith("BEGIN:", StringComparison.OrdinalIgnoreCase)) { depth++; continue; }
            if (line.StartsWith("END:", StringComparison.OrdinalIgnoreCase))
            {
                if (depth > 0) { depth--; continue; }
                if (line.Equals("END:VEVENT", StringComparison.OrdinalIgnoreCase))
                {
                    var ev = Build(props, exdates!, attendees!, floatingZone);
                    if (ev != null) events.Add(ev);
                    props = null;
                }
                continue;
            }
            if (depth > 0) continue;

            var (name, parameters, value) = SplitProperty(line);
            if (name.Equals("EXDATE", StringComparison.OrdinalIgnoreCase)) exdates!.Add((value, parameters));
            else if (name.Equals("ATTENDEE", StringComparison.OrdinalIgnoreCase)) { if (ParsePerson(value, parameters) is { } a) attendees!.Add(a); }
            else props.TryAdd(name, (value, parameters));
        }
        return events;
    }

    private static ICalEvent? Build(
        Dictionary<string, (string Value, Dictionary<string, string> Params)> p,
        List<(string Value, Dictionary<string, string> Params)> exdates, List<EventAttendee> attendees, TimeZoneInfo floating)
    {
        if (!p.TryGetValue("DTSTART", out var dtStart)) return null;
        if (!TryParseTime(dtStart.Value, dtStart.Params, floating, out var start, out var zone, out var allDay)) return null;

        DateTime end;
        if (p.TryGetValue("DTEND", out var dtEnd) && TryParseTime(dtEnd.Value, dtEnd.Params, floating, out var e, out var endZone, out _))
            end = allDay ? e : TimeZoneInfo.ConvertTime(new DateTimeOffset(e, endZone.GetUtcOffset(e)), zone).DateTime;
        else if (p.TryGetValue("DURATION", out var dur) && TryParseDuration(dur.Value, out var span))
            end = start + span;
        else
            end = allDay ? start.AddDays(1) : start; // RFC 5545 3.6.1 defaults
        if (end < start) end = start;

        DateTime? recurrenceId = null;
        if (p.TryGetValue("RECURRENCE-ID", out var rid) && TryParseTime(rid.Value, rid.Params, floating, out var r, out var rZone, out _))
            recurrenceId = TimeZoneInfo.ConvertTime(new DateTimeOffset(r, rZone.GetUtcOffset(r)), zone).DateTime;

        var ev = new ICalEvent
        {
            Uid = p.GetValueOrDefault("UID").Value ?? Guid.NewGuid().ToString(),
            Summary = Unescape(p.GetValueOrDefault("SUMMARY").Value ?? ""),
            Location = NullIfEmpty(Unescape(p.GetValueOrDefault("LOCATION").Value ?? "")),
            Description = NullIfEmpty(Unescape(p.GetValueOrDefault("DESCRIPTION").Value ?? "")),
            Status = p.GetValueOrDefault("STATUS").Value?.ToUpperInvariant(),
            AllDay = allDay,
            StartWall = start,
            EndWall = end,
            Zone = zone,
            RRule = p.GetValueOrDefault("RRULE").Value,
            RecurrenceIdWall = recurrenceId,
            Organizer = p.TryGetValue("ORGANIZER", out var org) ? ParsePerson(org.Value, org.Params) : null,
            Attendees = attendees,
            Sequence = int.TryParse(p.GetValueOrDefault("SEQUENCE").Value, out var seq) ? seq : 0,
        };
        foreach (var (value, parameters) in exdates)
            foreach (var part in value.Split(','))
                if (TryParseTime(part, parameters, floating, out var x, out var xZone, out _))
                    ev.ExDatesWall.Add(allDay ? x.Date : TimeZoneInfo.ConvertTime(new DateTimeOffset(x, xZone.GetUtcOffset(x)), zone).DateTime);
        return ev;
    }

    // ------------------------------------------------------------------ recurrence

    /// <summary>
    /// Instances overlapping [from, to). Overrides (RECURRENCE-ID) replace the instances they
    /// modify; EXDATEs and cancelled events are dropped. Supports FREQ=DAILY/WEEKLY/MONTHLY/YEARLY
    /// with INTERVAL, COUNT, UNTIL and BYDAY (weekly) — servers usually expand for us anyway.
    /// </summary>
    public static List<ICalEvent> Expand(IEnumerable<ICalEvent> events, DateTimeOffset from, DateTimeOffset to)
    {
        var all = events.ToList();
        var overrides = all.Where(e => e.RecurrenceIdWall != null)
            .Select(e => (e.Uid, Wall: e.RecurrenceIdWall!.Value)).ToHashSet();
        var result = new List<ICalEvent>();

        foreach (var ev in all)
        {
            if (ev.Status == "CANCELLED") continue;
            if (ev.RRule == null || ev.RecurrenceIdWall != null)
            {
                if (Overlaps(ev.Start, ev.End, from, to)) result.Add(ev);
                continue;
            }
            foreach (var wall in Occurrences(ev, to))
            {
                if (ev.ExDatesWall.Contains(wall) || overrides.Contains((ev.Uid, wall))) continue;
                var instance = new ICalEvent
                {
                    Uid = ev.Uid, Summary = ev.Summary, Location = ev.Location, Description = ev.Description,
                    Status = ev.Status, AllDay = ev.AllDay, Zone = ev.Zone,
                    Organizer = ev.Organizer, Attendees = ev.Attendees, Sequence = ev.Sequence,
                    StartWall = wall, EndWall = wall + (ev.EndWall - ev.StartWall), FromSeries = true,
                };
                if (Overlaps(instance.Start, instance.End, from, to)) result.Add(instance);
            }
        }
        return result;
    }

    private static bool Overlaps(DateTimeOffset start, DateTimeOffset end, DateTimeOffset from, DateTimeOffset to) =>
        start < to && (end > from || (end == start && start >= from));

    private static IEnumerable<DateTime> Occurrences(ICalEvent ev, DateTimeOffset to)
    {
        var rule = ev.RRule!.Split(';', StringSplitOptions.RemoveEmptyEntries)
            .Select(kv => kv.Split('=', 2)).Where(kv => kv.Length == 2)
            .ToDictionary(kv => kv[0].ToUpperInvariant(), kv => kv[1].ToUpperInvariant());
        var freq = rule.GetValueOrDefault("FREQ");
        var interval = int.TryParse(rule.GetValueOrDefault("INTERVAL"), out var i) && i > 0 ? i : 1;
        int? count = int.TryParse(rule.GetValueOrDefault("COUNT"), out var c) ? c : null;
        DateTimeOffset? until = null;
        if (rule.TryGetValue("UNTIL", out var u) &&
            TryParseTime(u, new(), ev.Zone, out var uw, out var uz, out var uAllDay))
            until = uAllDay ? new DateTimeOffset(uw.Date.AddDays(1).AddTicks(-1), ev.Zone.GetUtcOffset(uw)) : new DateTimeOffset(uw, uz.GetUtcOffset(uw));

        var byDay = rule.TryGetValue("BYDAY", out var bd)
            ? bd.Split(',').Select(d => d[^2..]).Select(ParseDay).Where(d => d != null).Select(d => d!.Value).ToHashSet()
            : null;

        var emitted = 0;
        for (var n = 0; n < 5000; n++)
        {
            IEnumerable<DateTime> candidates = freq switch
            {
                "DAILY" => [ev.StartWall.AddDays((double)n * interval)],
                "WEEKLY" => WeekCandidates(ev.StartWall, n * interval, byDay),
                "MONTHLY" => SafeMonth(ev.StartWall, n * interval),
                "YEARLY" => SafeMonth(ev.StartWall, n * interval * 12),
                _ => n == 0 ? [ev.StartWall] : [],
            };
            var any = false;
            foreach (var wall in candidates)
            {
                any = true;
                if (wall < ev.StartWall) continue;
                if (until != null && ev.ToOffset(wall) > until) yield break;
                if (count != null && emitted >= count) yield break;
                if (ev.ToOffset(wall) >= to) yield break;
                emitted++;
                yield return wall;
            }
            if (!any && freq is not ("MONTHLY" or "YEARLY")) yield break;
        }
    }

    private static IEnumerable<DateTime> WeekCandidates(DateTime start, int weekOffset, HashSet<DayOfWeek>? byDay)
    {
        if (byDay == null || byDay.Count == 0)
        {
            yield return start.AddDays(7.0 * weekOffset);
            yield break;
        }
        // Weeks start Monday (RFC 5545 default WKST=MO).
        var weekStart = start.Date.AddDays(-(((int)start.DayOfWeek + 6) % 7) + 7.0 * weekOffset);
        for (var d = 0; d < 7; d++)
        {
            var day = weekStart.AddDays(d);
            if (byDay.Contains(day.DayOfWeek)) yield return day + start.TimeOfDay;
        }
    }

    /// <summary>Same day-of-month N months on; months without that day are skipped (RFC behaviour).</summary>
    private static IEnumerable<DateTime> SafeMonth(DateTime start, int months)
    {
        var target = start.AddMonths(months);
        if (target.Day == start.Day) yield return target;
    }

    private static DayOfWeek? ParseDay(string d) => d switch
    {
        "MO" => DayOfWeek.Monday, "TU" => DayOfWeek.Tuesday, "WE" => DayOfWeek.Wednesday, "TH" => DayOfWeek.Thursday,
        "FR" => DayOfWeek.Friday, "SA" => DayOfWeek.Saturday, "SU" => DayOfWeek.Sunday, _ => null,
    };

    // ------------------------------------------------------------------ people

    /// <summary>An ORGANIZER or ATTENDEE ("mailto:a@b" with CN, PARTSTAT and ROLE); null without an address.</summary>
    internal static EventAttendee? ParsePerson(string value, Dictionary<string, string> parameters)
    {
        var email = AddressOf(value);
        if (email.Length == 0) return null;
        var status = parameters.GetValueOrDefault("PARTSTAT")?.ToUpperInvariant() switch
        {
            "ACCEPTED" => AttendeeStatus.Accepted,
            "TENTATIVE" => AttendeeStatus.Tentative,
            "DECLINED" => AttendeeStatus.Declined,
            "DELEGATED" => AttendeeStatus.Delegated,
            _ => AttendeeStatus.NeedsAction,
        };
        var name = parameters.GetValueOrDefault("CN");
        return new EventAttendee(email, string.IsNullOrWhiteSpace(name) ? null : name.Trim(), status,
            string.Equals(parameters.GetValueOrDefault("ROLE"), "OPT-PARTICIPANT", StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>"mailto:a@b" → "a@b" (other URI schemes are kept as they are).</summary>
    internal static string AddressOf(string value)
    {
        value = value.Trim();
        return value.StartsWith("mailto:", StringComparison.OrdinalIgnoreCase) ? value[7..].Trim() : value;
    }

    // ------------------------------------------------------------------ values

    public static bool TryParseTime(string value, Dictionary<string, string> parameters, TimeZoneInfo floating,
        out DateTime wall, out TimeZoneInfo zone, out bool allDay)
    {
        value = value.Trim();
        zone = floating;
        allDay = parameters.TryGetValue("VALUE", out var v) && v.Equals("DATE", StringComparison.OrdinalIgnoreCase)
                 || value.Length == 8;
        if (allDay)
        {
            var ok = DateTime.TryParseExact(value[..Math.Min(8, value.Length)], "yyyyMMdd", CultureInfo.InvariantCulture,
                DateTimeStyles.None, out wall);
            zone = TimeZoneInfo.Utc;
            return ok;
        }

        var utc = value.EndsWith('Z');
        if (!DateTime.TryParseExact(utc ? value[..^1] : value, "yyyyMMdd'T'HHmmss", CultureInfo.InvariantCulture,
                DateTimeStyles.None, out wall))
            return false;
        wall = DateTime.SpecifyKind(wall, DateTimeKind.Unspecified);

        if (utc) zone = TimeZoneInfo.Utc;
        else if (parameters.TryGetValue("TZID", out var tzid))
            zone = FindZone(tzid) ?? floating;
        return true;
    }

    private static TimeZoneInfo? FindZone(string tzid)
    {
        tzid = tzid.Trim('"');
        if (TimeZoneInfo.TryFindSystemTimeZoneById(tzid, out var tz)) return tz;
        // Some clients prefix IANA names, e.g. "/mozilla.org/20050126_1/Europe/London".
        for (var parts = tzid.Split('/', StringSplitOptions.RemoveEmptyEntries); parts.Length >= 2; parts = parts[1..])
            if (TimeZoneInfo.TryFindSystemTimeZoneById(string.Join('/', parts[^2..]), out tz)) return tz;
        return null;
    }

    public static bool TryParseDuration(string value, out TimeSpan span)
    {
        span = TimeSpan.Zero;
        var s = value.Trim();
        var negative = s.StartsWith('-');
        s = s.TrimStart('+', '-');
        if (!s.StartsWith('P')) return false;
        var inTime = false;
        var number = new StringBuilder();
        foreach (var ch in s[1..])
        {
            if (char.IsDigit(ch)) { number.Append(ch); continue; }
            if (ch == 'T') { inTime = true; continue; }
            if (!int.TryParse(number.ToString(), out var n)) return false;
            number.Clear();
            span += ch switch
            {
                'W' => TimeSpan.FromDays(7 * n),
                'D' => TimeSpan.FromDays(n),
                'H' when inTime => TimeSpan.FromHours(n),
                'M' when inTime => TimeSpan.FromMinutes(n),
                'S' when inTime => TimeSpan.FromSeconds(n),
                _ => TimeSpan.Zero,
            };
        }
        if (negative) span = -span;
        return true;
    }

    /// <summary>Content lines with RFC 5545 folding undone.</summary>
    public static IEnumerable<string> UnfoldLines(string ics) => Unfold(ics);

    private static IEnumerable<string> Unfold(string ics)
    {
        var current = new StringBuilder();
        foreach (var raw in ics.Replace("\r\n", "\n").Split('\n'))
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

    /// <summary>"NAME;P1=a;P2="b:c":value" → name, params, value (colons inside quotes don't split).</summary>
    internal static (string Name, Dictionary<string, string> Params, string Value) SplitProperty(string line)
    {
        var quoted = false;
        var colon = -1;
        for (var i = 0; i < line.Length; i++)
        {
            if (line[i] == '"') quoted = !quoted;
            else if (line[i] == ':' && !quoted) { colon = i; break; }
        }
        if (colon < 0) return (line, new(), "");
        var head = line[..colon].Split(';');
        var parameters = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var p in head.Skip(1))
        {
            var eq = p.IndexOf('=');
            if (eq > 0) parameters[p[..eq]] = p[(eq + 1)..].Trim('"');
        }
        return (head[0], parameters, line[(colon + 1)..]);
    }

    private static string Unescape(string s) =>
        s.Replace("\\n", "\n").Replace("\\N", "\n").Replace("\\,", ",").Replace("\\;", ";").Replace("\\\\", "\\");

    private static string? NullIfEmpty(string s) => string.IsNullOrWhiteSpace(s) ? null : s.Trim();
}
