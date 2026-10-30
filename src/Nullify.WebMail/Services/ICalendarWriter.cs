// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using System.Globalization;
using Nullify.WebMail.Shared;

namespace Nullify.WebMail.Services;

/// <summary>
/// Writes VEVENTs (RFC 5545). Updates rewrite only the properties the editor owns and keep
/// everything else (alarms, categories, X- properties) as the server stored it. The guest
/// list is rewritten only when the edit carries one.
/// </summary>
public static partial class ICalendarWriter
{
    private static readonly HashSet<string> Managed = new(StringComparer.OrdinalIgnoreCase)
        { "SUMMARY", "LOCATION", "DESCRIPTION", "DTSTART", "DTEND", "DURATION", "RRULE", "DTSTAMP", "LAST-MODIFIED", "SEQUENCE" };

    /// <summary>Times to write: wall-clock values in <c>Zone</c> (or dates when all-day, End inclusive).</summary>
    public sealed record EventTimes(DateTime StartLocal, DateTime EndLocal, bool AllDay, TimeZoneInfo Zone);

    public static string NewEvent(string uid, EventEdit edit, EventTimes times, string? rrule)
    {
        var lines = new List<string>
        {
            "BEGIN:VCALENDAR", "VERSION:2.0", "PRODID:-//Nullify//WebMail//EN", "CALSCALE:GREGORIAN",
        };
        if (!times.AllDay && TzidOf(times.Zone) is { } tzid) lines.AddRange(VTimezone(times.Zone, tzid, times.StartLocal.Year));
        lines.Add("BEGIN:VEVENT");
        lines.Add("UID:" + uid);
        lines.Add("CREATED:" + UtcStamp());
        lines.AddRange(EventProperties(edit, times, rrule, sequence: 0));
        if (edit.Attendees != null) lines.AddRange(People(edit, [], reset: false));
        if (edit.Reminders != null) lines.AddRange(Alarms(edit));
        lines.Add("END:VEVENT");
        lines.Add("END:VCALENDAR");
        return Serialize(lines);
    }

    /// <summary>
    /// Rewrite the series master (the VEVENT without RECURRENCE-ID). With
    /// <paramref name="dropExceptions"/>, EXDATEs and per-occurrence overrides are removed too —
    /// needed when the series' times or pattern change, since they'd no longer line up.
    /// When the edit has a guest list it replaces the one in every remaining component; guests
    /// who were already invited keep their answer unless the times or pattern changed.
    /// </summary>
    public static string UpdateMaster(string existing, EventEdit edit, EventTimes times, string? rrule, bool dropExceptions)
    {
        var lines = ICalendar.UnfoldLines(existing).ToList();
        var events = FindEvents(lines);
        var master = events.FirstOrDefault(e => !e.IsOverride);
        if (master == null) throw new InvalidOperationException("The event has no editable component.");

        var sequence = 0;
        var people = new Dictionary<EventBlock, List<string>>(); // each component's ORGANIZER/ATTENDEE lines
        var output = new List<string>();
        for (var i = 0; i < lines.Count; i++)
        {
            var ev = events.FirstOrDefault(e => i >= e.Begin && i <= e.End);
            if (ev != null && ev.IsOverride && dropExceptions) { i = ev.End; continue; }
            // New reminders replace the series' alarms (the only components a VEVENT holds).
            if (ev == master && edit.Reminders != null && i > ev.Begin && i < ev.End && ev.Depth(i) > 0) continue;
            if (ev != null && i > ev.Begin && i < ev.End && ev.Depth(i) == 0)
            {
                var name = PropertyName(lines[i]);
                if (edit.Attendees != null && name is "ATTENDEE" or "ORGANIZER")
                {
                    (people.TryGetValue(ev, out var list) ? list : people[ev] = []).Add(lines[i]);
                    continue;
                }
                if (ev == master)
                {
                    if (name == "SEQUENCE" && int.TryParse(lines[i][(lines[i].IndexOf(':') + 1)..], out var seq)) sequence = seq + 1;
                    if (Managed.Contains(name) || (dropExceptions && name is "EXDATE" or "RDATE")) continue;
                }
            }
            output.Add(lines[i]);
            if (ev != null && i == ev.Begin) output.Add(Placeholder(ev)); // filled below
        }

        var props = EventProperties(edit, times, rrule, Math.Max(sequence, 1)).ToList();
        // Moving the meeting or changing how it repeats asks everyone to answer again (RFC 5546 2.1.4).
        var rescheduled = Timing(existing) != Timing(Serialize(["BEGIN:VCALENDAR", "BEGIN:VEVENT", .. props, "END:VEVENT", "END:VCALENDAR"]));
        foreach (var ev in events)
        {
            var at = output.IndexOf(Placeholder(ev));
            if (at < 0) continue;
            output.RemoveAt(at);
            List<string> insert = edit.Attendees == null ? [] : People(edit, people.GetValueOrDefault(ev) ?? [], rescheduled).ToList();
            if (ev == master)
            {
                insert.InsertRange(0, props);
                if (edit.Reminders != null) insert.AddRange(Alarms(edit));
            }
            output.InsertRange(at, insert);
        }

        if (!times.AllDay) EnsureVTimezone(output, times.Zone, times.StartLocal.Year);
        return Serialize(output);
    }

    /// <summary>Add a VTIMEZONE for the zone after the calendar's own properties, unless one is there already.</summary>
    private static void EnsureVTimezone(List<string> output, TimeZoneInfo zone, int year)
    {
        if (TzidOf(zone) is not { } tzid || output.Any(l => l.Equals("TZID:" + tzid, StringComparison.OrdinalIgnoreCase))) return;
        var cal = output.FindIndex(l => l.Equals("BEGIN:VCALENDAR", StringComparison.OrdinalIgnoreCase));
        output.InsertRange(cal + 1 + output.Skip(cal + 1).TakeWhile(l => !l.StartsWith("BEGIN:", StringComparison.OrdinalIgnoreCase)).Count(),
            VTimezone(zone, tzid, year));
    }

    /// <summary>Skip one occurrence of a series: add an EXDATE and drop any override for it.</summary>
    public static string ExcludeOccurrence(string existing, DateTimeOffset occurrence, bool allDay)
    {
        var lines = ICalendar.UnfoldLines(existing).ToList();
        var events = FindEvents(lines);
        var master = events.FirstOrDefault(e => !e.IsOverride)
            ?? throw new InvalidOperationException("The event has no repeating component.");

        // Overrides for this occurrence go too, or the "deleted" occurrence would still show.
        var drop = events.Where(e => e.IsOverride && OverrideStart(lines, e) is { } s &&
                                     (allDay ? s.UtcDateTime.Date == occurrence.UtcDateTime.Date : s == occurrence)).ToList();
        var output = new List<string>();
        for (var i = 0; i < lines.Count; i++)
        {
            var ev = drop.FirstOrDefault(e => i >= e.Begin && i <= e.End);
            if (ev != null) { i = ev.End; continue; }
            output.Add(lines[i]);
            if (i == master.Begin)
                output.Add(allDay
                    ? $"EXDATE;VALUE=DATE:{occurrence.UtcDateTime:yyyyMMdd}"
                    : $"EXDATE:{occurrence.UtcDateTime:yyyyMMdd'T'HHmmss'Z'}");
        }
        return Serialize(output);
    }

    /// <summary>When the main component happens: what guests answered to.</summary>
    private static (DateTimeOffset, DateTimeOffset, string?)? Timing(string ics) =>
        ICalendar.ParseEvents(ics, TimeZoneInfo.Utc).FirstOrDefault(e => e.RecurrenceIdWall == null) is { } m
            ? (m.Start, m.End, m.RRule?.ToUpperInvariant()) : null;

    private static string Placeholder(EventBlock ev) => "\u0000" + ev.Begin.ToString(CultureInfo.InvariantCulture);

    // ------------------------------------------------------------------ people

    /// <summary>
    /// ORGANIZER and ATTENDEE lines for the edit's guest list (none when it's empty). Guests
    /// already in <paramref name="existing"/> keep their parameters (answer, delegation...);
    /// <paramref name="reset"/> asks every guest to answer again. SCHEDULE-AGENT=CLIENT tells a
    /// scheduling CalDAV server (RFC 6638) that we send the invitations, so guests don't get two.
    /// </summary>
    private static IEnumerable<string> People(EventEdit edit, List<string> existing, bool reset)
    {
        if (edit.Attendees is not { Count: > 0 } guests) yield break;
        var known = new Dictionary<string, Dictionary<string, string>>(StringComparer.OrdinalIgnoreCase);
        string? organizer = null;
        foreach (var line in existing)
        {
            var (name, parameters, value) = ICalendar.SplitProperty(line);
            if (name.Equals("ORGANIZER", StringComparison.OrdinalIgnoreCase)) organizer ??= line;
            else known.TryAdd(ICalendar.AddressOf(value), parameters);
        }
        if (organizer != null) yield return organizer;
        else if (edit.Organizer is { } me)
            yield return "ORGANIZER" + Param("CN", me.Name) + ":mailto:" + me.Email.Trim();

        foreach (var g in guests.DistinctBy(g => g.Email.Trim(), StringComparer.OrdinalIgnoreCase))
        {
            var old = known.GetValueOrDefault(g.Email.Trim());
            var p = old == null ? new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase) : new(old, StringComparer.OrdinalIgnoreCase);
            var cn = string.IsNullOrWhiteSpace(g.Name) ? p.GetValueOrDefault("CN") : g.Name;
            p.Remove("CN");
            p["ROLE"] = g.Optional ? "OPT-PARTICIPANT" : "REQ-PARTICIPANT";
            if (old == null || reset)
            {
                p["PARTSTAT"] = "NEEDS-ACTION";
                p["RSVP"] = "TRUE";
            }
            p["SCHEDULE-AGENT"] = "CLIENT";
            p.Remove("SCHEDULE-STATUS"); // the server's report on its own delivery
            yield return "ATTENDEE" + Param("CN", cn) + string.Concat(p.Select(kv => Param(kv.Key.ToUpperInvariant(), kv.Value)))
                         + ":mailto:" + g.Email.Trim();
        }
    }

    /// <summary>";NAME=value", quoted when the value has ':', ';' or ','; nothing for an empty value.</summary>
    internal static string Param(string name, string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return "";
        // A quoted list ("a","b") reads back without its outer quotes only.
        if (value.Contains("\",\"")) return $";{name}=\"{value}\"";
        value = value.Replace("\"", "").Replace("\r", "").Replace("\n", " ").Trim();
        return value.IndexOfAny([':', ';', ',']) >= 0 ? $";{name}=\"{value}\"" : $";{name}={value}";
    }

    // ------------------------------------------------------------------ pieces

    private static IEnumerable<string> EventProperties(EventEdit edit, EventTimes times, string? rrule, int sequence)
    {
        yield return "DTSTAMP:" + UtcStamp();
        yield return "LAST-MODIFIED:" + UtcStamp();
        yield return "SEQUENCE:" + sequence;
        yield return "SUMMARY:" + Escape(string.IsNullOrWhiteSpace(edit.Summary) ? "(no title)" : edit.Summary.Trim());
        if (times.AllDay)
        {
            yield return $"DTSTART;VALUE=DATE:{times.StartLocal:yyyyMMdd}";
            // DTEND is exclusive for all-day events.
            var end = times.EndLocal.Date < times.StartLocal.Date ? times.StartLocal.Date : times.EndLocal.Date;
            yield return $"DTEND;VALUE=DATE:{end.AddDays(1):yyyyMMdd}";
        }
        else
        {
            var end = times.EndLocal < times.StartLocal ? times.StartLocal : times.EndLocal;
            yield return "DTSTART" + TimeValue(times.StartLocal, times.Zone);
            yield return "DTEND" + TimeValue(end, times.Zone);
        }
        if (!string.IsNullOrWhiteSpace(edit.Location)) yield return "LOCATION:" + Escape(edit.Location.Trim());
        if (!string.IsNullOrWhiteSpace(edit.Description)) yield return "DESCRIPTION:" + Escape(edit.Description.Trim());
        if (rrule != null) yield return "RRULE:" + rrule;
    }

    /// <summary>A display VALARM per reminder, each going off that many minutes before the start.</summary>
    private static IEnumerable<string> Alarms(EventEdit edit)
    {
        var text = Escape(string.IsNullOrWhiteSpace(edit.Summary) ? "Reminder" : edit.Summary.Trim());
        foreach (var minutes in edit.Reminders!.Distinct().OrderDescending())
        {
            yield return "BEGIN:VALARM";
            yield return "ACTION:DISPLAY";
            yield return "DESCRIPTION:" + text;
            yield return "TRIGGER:" + Before(minutes);
            yield return "END:VALARM";
        }
    }

    /// <summary>A TRIGGER duration for <paramref name="minutes"/> before the start, in the largest whole unit.</summary>
    public static string Before(int minutes)
    {
        if (minutes == 0) return "PT0M";
        var sign = minutes > 0 ? "-" : "";
        var m = Math.Abs(minutes);
        return m % 10080 == 0 ? $"{sign}P{m / 10080}W"
            : m % 1440 == 0 ? $"{sign}P{m / 1440}D"
            : m % 60 == 0 ? $"{sign}PT{m / 60}H"
            : $"{sign}PT{m}M";
    }

    public static string? RuleFor(EventRepeat repeat) => repeat switch
    {
        EventRepeat.Daily => "FREQ=DAILY",
        EventRepeat.Weekly => "FREQ=WEEKLY",
        EventRepeat.Monthly => "FREQ=MONTHLY",
        EventRepeat.Yearly => "FREQ=YEARLY",
        _ => null,
    };

    public static EventRepeat RepeatOf(string? rrule)
    {
        var freq = rrule?.Split(';').Select(p => p.Split('=', 2)).FirstOrDefault(p => p[0].Equals("FREQ", StringComparison.OrdinalIgnoreCase))?.ElementAtOrDefault(1);
        return freq?.ToUpperInvariant() switch
        {
            "DAILY" => EventRepeat.Daily, "WEEKLY" => EventRepeat.Weekly,
            "MONTHLY" => EventRepeat.Monthly, "YEARLY" => EventRepeat.Yearly,
            _ => EventRepeat.None,
        };
    }

    private static string TimeValue(DateTime local, TimeZoneInfo zone)
    {
        var tzid = TzidOf(zone);
        if (tzid == null)
            return ":" + TimeZoneInfo.ConvertTimeToUtc(DateTime.SpecifyKind(local, DateTimeKind.Unspecified), zone).ToString("yyyyMMdd'T'HHmmss'Z'");
        return $";TZID={tzid}:{local:yyyyMMdd'T'HHmmss}";
    }

    /// <summary>IANA name for the zone, or null for UTC (written with a Z suffix instead).</summary>
    public static string? TzidOf(TimeZoneInfo zone)
    {
        if (zone == TimeZoneInfo.Utc || zone.Id is "UTC" or "Etc/UTC" or "Coordinated Universal Time") return null;
        if (zone.Id.Contains('/')) return zone.Id;
        return TimeZoneInfo.TryConvertWindowsIdToIanaId(zone.Id, out var iana) ? iana : zone.Id;
    }

    /// <summary>A VTIMEZONE describing the zone's rule in effect for <paramref name="year"/>.</summary>
    public static List<string> VTimezone(TimeZoneInfo zone, string tzid, int year)
    {
        // Derived from the zone's actual offset changes rather than GetAdjustmentRules(): on Linux the
        // rules come from tzdata as per-year fixed-date (or zero-delta) entries, unlike Windows' floating ones.
        var transitions = Transitions(zone, year);
        var toDst = transitions.FirstOrDefault(t => t.Dst);
        var toStd = transitions.FirstOrDefault(t => !t.Dst);
        var lines = new List<string> { "BEGIN:VTIMEZONE", "TZID:" + tzid };
        if (toDst == default || toStd == default)
        {
            var std = zone.GetUtcOffset(new DateTimeOffset(year, 12, 31, 12, 0, 0, TimeSpan.Zero));
            lines.AddRange(["BEGIN:STANDARD", "DTSTART:19700101T000000", "TZOFFSETFROM:" + Offset(std), "TZOFFSETTO:" + Offset(std), "END:STANDARD"]);
        }
        else
        {
            lines.AddRange(Observance("DAYLIGHT", FloatingRule(toDst.LocalBefore), toDst.From, toDst.To));
            lines.AddRange(Observance("STANDARD", FloatingRule(toStd.LocalBefore), toStd.From, toStd.To));
        }
        lines.Add("END:VTIMEZONE");
        return lines;
    }

    private readonly record struct OffsetChange(DateTime LocalBefore, TimeSpan From, TimeSpan To, bool Dst);

    /// <summary>Each UTC offset change in <paramref name="year"/>, located to the minute.</summary>
    private static List<OffsetChange> Transitions(TimeZoneInfo zone, int year)
    {
        var result = new List<OffsetChange>();
        var day = new DateTimeOffset(year, 1, 1, 0, 0, 0, TimeSpan.Zero);
        for (; day.Year == year; day = day.AddDays(1))
        {
            var from = zone.GetUtcOffset(day);
            if (zone.GetUtcOffset(day.AddDays(1)) == from) continue;
            DateTimeOffset lo = day, hi = day.AddDays(1); // offset(lo) == from, offset(hi) != from
            while (hi - lo > TimeSpan.FromMinutes(1))
            {
                var mid = lo + (hi - lo) / 2;
                if (zone.GetUtcOffset(mid) == from) lo = mid; else hi = mid;
            }
            var at = new DateTimeOffset(hi.UtcTicks - hi.UtcTicks % TimeSpan.TicksPerMinute, TimeSpan.Zero);
            result.Add(new OffsetChange(at.UtcDateTime + from, from, zone.GetUtcOffset(at), zone.IsDaylightSavingTime(at)));
        }
        return result;
    }

    /// <summary>The "nth/last weekday of the month" rule matching a transition's local date.</summary>
    private static TimeZoneInfo.TransitionTime FloatingRule(DateTime local)
    {
        var week = local.Day + 7 > DateTime.DaysInMonth(local.Year, local.Month) ? 5 : (local.Day - 1) / 7 + 1;
        return TimeZoneInfo.TransitionTime.CreateFloatingDateRule(new DateTime(1, 1, 1, local.Hour, local.Minute, 0), local.Month, week, local.DayOfWeek);
    }

    private static IEnumerable<string> Observance(string kind, TimeZoneInfo.TransitionTime t, TimeSpan from, TimeSpan to)
    {
        var date = TransitionDate(t, 1970);
        var rule = t.IsFixedDateRule
            ? $"FREQ=YEARLY;BYMONTH={t.Month};BYMONTHDAY={t.Day}"
            : $"FREQ=YEARLY;BYMONTH={t.Month};BYDAY={(t.Week == 5 ? "-1" : t.Week.ToString(CultureInfo.InvariantCulture))}{t.DayOfWeek.ToString()[..2].ToUpperInvariant()}";
        yield return "BEGIN:" + kind;
        yield return $"DTSTART:{date:yyyyMMdd}T{t.TimeOfDay:HHmmss}";
        yield return "RRULE:" + rule;
        yield return "TZOFFSETFROM:" + Offset(from);
        yield return "TZOFFSETTO:" + Offset(to);
        yield return "END:" + kind;
    }

    private static DateTime TransitionDate(TimeZoneInfo.TransitionTime t, int year)
    {
        if (t.IsFixedDateRule) return new DateTime(year, t.Month, Math.Min(t.Day, DateTime.DaysInMonth(year, t.Month)));
        var first = new DateTime(year, t.Month, 1);
        var day = first.AddDays(((int)t.DayOfWeek - (int)first.DayOfWeek + 7) % 7 + 7 * (t.Week - 1));
        while (day.Month != t.Month) day = day.AddDays(-7); // week 5 = "last"
        return day;
    }

    private static string Offset(TimeSpan o) => (o < TimeSpan.Zero ? "-" : "+") + o.Duration().ToString("hhmm", CultureInfo.InvariantCulture);

    internal static string UtcStamp() => DateTime.UtcNow.ToString("yyyyMMdd'T'HHmmss'Z'", CultureInfo.InvariantCulture);

    internal static string Escape(string s) =>
        s.Replace("\\", "\\\\").Replace(";", "\\;").Replace(",", "\\,").Replace("\r\n", "\n").Replace("\r", "\n").Replace("\n", "\\n");

    internal static string Serialize(IEnumerable<string> lines) => string.Concat(lines.Select(l => VCard.Fold(l) + "\r\n"));

    // ------------------------------------------------------------------ structure

    internal sealed record EventBlock(int Begin, int End, bool IsOverride, int[] NestedDepth)
    {
        /// <summary>Nesting depth inside this VEVENT (VALARM etc.) at line <paramref name="i"/>.</summary>
        public int Depth(int i) => NestedDepth[i - Begin];
    }

    internal static List<EventBlock> FindEvents(List<string> lines)
    {
        var result = new List<EventBlock>();
        for (var i = 0; i < lines.Count; i++)
        {
            if (!lines[i].Equals("BEGIN:VEVENT", StringComparison.OrdinalIgnoreCase)) continue;
            var depth = 0;
            var depths = new List<int> { 0 };
            var isOverride = false;
            var j = i + 1;
            for (; j < lines.Count; j++)
            {
                var l = lines[j];
                if (depth == 0 && l.Equals("END:VEVENT", StringComparison.OrdinalIgnoreCase)) { depths.Add(0); break; }
                if (l.StartsWith("BEGIN:", StringComparison.OrdinalIgnoreCase)) { depths.Add(depth + 1); depth++; continue; }
                if (l.StartsWith("END:", StringComparison.OrdinalIgnoreCase)) { depths.Add(depth); depth--; continue; }
                depths.Add(depth);
                if (depth == 0 && PropertyName(l) == "RECURRENCE-ID") isOverride = true;
            }
            result.Add(new EventBlock(i, j, isOverride, depths.ToArray()));
            i = j;
        }
        return result;
    }

    private static DateTimeOffset? OverrideStart(List<string> lines, EventBlock block)
    {
        var text = "BEGIN:VCALENDAR\r\n" + string.Join("\r\n", lines.Skip(block.Begin).Take(block.End - block.Begin + 1)) + "\r\nEND:VCALENDAR\r\n";
        var ev = ICalendar.ParseEvents(text, TimeZoneInfo.Utc).FirstOrDefault();
        return ev?.RecurrenceIdWall is { } r ? ev.ToOffset(r) : null;
    }

    internal static string PropertyName(string line)
    {
        var end = line.IndexOfAny([':', ';']);
        return (end < 0 ? line : line[..end]).ToUpperInvariant();
    }
}
