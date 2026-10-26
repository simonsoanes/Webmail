// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using System.Globalization;
using System.Text;
using Nullify.WebMail.Shared;

namespace Nullify.WebMail.Services;

public enum SchedulingKind { Invitation, Update, Cancellation, Reply }

/// <summary>
/// An iTIP message (RFC 5546) to email from <see cref="Sender"/> to <see cref="Recipients"/>
/// as iMIP (RFC 6047). <see cref="Ics"/> carries the METHOD.
/// </summary>
public sealed record SchedulingMessage(
    SchedulingKind Kind, string Method, string Ics, EventAttendee Sender, IReadOnlyList<EventAttendee> Recipients);

/// <summary>
/// Works out which invitations, updates and cancellations a change to a meeting calls for,
/// and builds them. Only meetings the user organises send anything; guests answer with
/// <see cref="Reply"/>. Alarms never leave the user's own copy.
/// </summary>
public static partial class Scheduling
{
    private static readonly CultureInfo Inv = CultureInfo.InvariantCulture;

    /// <summary>
    /// Messages for saving <paramref name="after"/> over <paramref name="before"/> (null when new).
    /// New guests are invited; removed guests get a cancellation; everyone else gets an update when
    /// what, when or where changed. <paramref name="mine"/> are the user's own addresses.
    /// </summary>
    public static List<SchedulingMessage> ForSave(string? before, string after, IReadOnlyCollection<string> mine)
    {
        var now = Master(after);
        var old = before == null ? null : Master(before);
        var organised = old?.Organizer is { } o && IsMine(o.Email, mine);
        var oldGuests = organised ? Others(old!.Attendees, mine) : [];

        if (now?.Organizer is not { } organizer || !IsMine(organizer.Email, mine))
            // No longer a meeting (the guest list was emptied): tell the guests it's off.
            return organised && now?.Organizer == null && oldGuests.Count > 0 ? [Cancel(before!, oldGuests, null)] : [];

        var guests = Others(now.Attendees, mine);
        var messages = new List<SchedulingMessage>();
        var removed = oldGuests.Where(g => !guests.Any(n => Same(n.Email, g.Email))).ToList();
        if (removed.Count > 0) messages.Add(Cancel(before!, removed, null));

        if (guests.Count == 0) return messages;
        if (!organised || oldGuests.Count == 0)
            messages.Add(Request(SchedulingKind.Invitation, after, organizer, guests));
        else if (Significant(old!) != Significant(now))
            messages.Add(Request(SchedulingKind.Update, after, organizer, guests));
        else if (guests.Where(g => !oldGuests.Any(x => Same(x.Email, g.Email))).ToList() is { Count: > 0 } added)
            messages.Add(Request(SchedulingKind.Invitation, after, organizer, added));
        return messages;
    }

    /// <summary>
    /// The cancellation for deleting a meeting the user organises: the whole series, or one
    /// occurrence of it. Empty for anything else.
    /// </summary>
    public static List<SchedulingMessage> ForDelete(string before, DateTimeOffset? occurrence, bool allDay, IReadOnlyCollection<string> mine)
    {
        if (Master(before) is not { Organizer: { } organizer } master || !IsMine(organizer.Email, mine)) return [];
        var guests = Others(master.Attendees, mine);
        return guests.Count == 0 ? [] : [Cancel(before, guests, occurrence is { } at ? (at, allDay) : null)];
    }

    /// <summary>
    /// The user's answer to an invitation in their calendar: <paramref name="existing"/> with
    /// their PARTSTAT set, and the REPLY for the organiser.
    /// </summary>
    /// <exception cref="InvalidOperationException">The user isn't a guest of this meeting.</exception>
    public static (string Updated, SchedulingMessage Reply) Answer(string existing, IReadOnlyCollection<string> mine, AttendeeStatus answer)
    {
        var master = Master(existing);
        if (master?.Organizer is not { } organizer || IsMine(organizer.Email, mine))
            throw new InvalidOperationException("Only guests can answer an invitation.");
        var me = master.Attendees.FirstOrDefault(a => IsMine(a.Email, mine))
            ?? throw new InvalidOperationException("You aren't on this meeting's guest list.");

        var output = new List<string>();
        var lines = ICalendar.UnfoldLines(existing).ToList();
        var events = ICalendarWriter.FindEvents(lines);
        for (var i = 0; i < lines.Count; i++)
        {
            var line = lines[i];
            if (events.FirstOrDefault(e => i > e.Begin && i < e.End) is { } ev && ev.Depth(i) == 0)
            {
                var name = ICalendarWriter.PropertyName(line);
                if (name == "ATTENDEE" && Same(ICalendar.AddressOf(ICalendar.SplitProperty(line).Value), me.Email))
                    line = WithParams(line, p =>
                    {
                        p["PARTSTAT"] = PartStat(answer);
                        p.Remove("RSVP");
                        p.Remove("SCHEDULE-STATUS");
                    });
                // We email the reply ourselves, so a scheduling server mustn't send one too (RFC 6638 7.1).
                else if (name == "ORGANIZER")
                    line = WithParams(line, p => p["SCHEDULE-AGENT"] = "CLIENT");
            }
            output.Add(line);
        }
        var updated = ICalendarWriter.Serialize(output);

        var reply = Single(updated, "REPLY", attendee => Same(attendee, me.Email), extra: [], drop: []);
        return (updated, new SchedulingMessage(SchedulingKind.Reply, "REPLY", reply,
            me with { Status = answer }, [organizer]));
    }

    // ------------------------------------------------------------------ building

    private static SchedulingMessage Request(SchedulingKind kind, string ics, EventAttendee organizer, List<EventAttendee> to) =>
        new(kind, "REQUEST", ForSending(ics, "REQUEST"), organizer, to);

    /// <param name="occurrence">One occurrence to cancel, or null for the whole event.</param>
    private static SchedulingMessage Cancel(string ics, List<EventAttendee> to, (DateTimeOffset At, bool AllDay)? occurrence)
    {
        var master = Master(ics)!;
        var extra = new List<string> { "STATUS:CANCELLED", "SEQUENCE:" + (master.Sequence + 1) };
        var drop = new HashSet<string> { "STATUS", "SEQUENCE" };
        if (occurrence is { } o)
        {
            drop.UnionWith(["RRULE", "RDATE", "EXDATE", "DTSTART", "DTEND", "DURATION", "RECURRENCE-ID"]);
            var length = master.End - master.Start;
            if (o.AllDay)
            {
                var day = o.At.UtcDateTime.Date;
                extra.Add($"RECURRENCE-ID;VALUE=DATE:{day:yyyyMMdd}");
                extra.Add($"DTSTART;VALUE=DATE:{day:yyyyMMdd}");
                extra.Add($"DTEND;VALUE=DATE:{day.AddDays(Math.Max(1, (int)Math.Round(length.TotalDays))):yyyyMMdd}");
            }
            else
            {
                extra.Add($"RECURRENCE-ID:{o.At.UtcDateTime:yyyyMMdd'T'HHmmss'Z'}");
                extra.Add($"DTSTART:{o.At.UtcDateTime:yyyyMMdd'T'HHmmss'Z'}");
                extra.Add($"DTEND:{(o.At + length).UtcDateTime:yyyyMMdd'T'HHmmss'Z'}");
            }
        }
        var body = Single(ics, "CANCEL", attendee => to.Any(t => Same(t.Email, attendee)), extra, drop);
        return new SchedulingMessage(SchedulingKind.Cancellation, "CANCEL", body, master.Organizer!, to);
    }

    /// <summary>
    /// The stored calendar as sent with <paramref name="method"/>: alarms and the CalDAV
    /// scheduling parameters left out.
    /// </summary>
    private static string ForSending(string ics, string method)
    {
        var lines = ICalendar.UnfoldLines(ics).ToList();
        var output = new List<string>();
        var alarmDepth = 0;
        foreach (var line in lines)
        {
            if (line.Equals("BEGIN:VALARM", StringComparison.OrdinalIgnoreCase)) { alarmDepth++; continue; }
            if (alarmDepth > 0)
            {
                if (line.Equals("END:VALARM", StringComparison.OrdinalIgnoreCase)) alarmDepth--;
                continue;
            }
            var name = ICalendarWriter.PropertyName(line);
            if (name == "METHOD") continue;
            output.Add(name is "ATTENDEE" or "ORGANIZER" ? Clean(line) : line);
            if (line.Equals("BEGIN:VCALENDAR", StringComparison.OrdinalIgnoreCase)) output.Add("METHOD:" + method);
        }
        return ICalendarWriter.Serialize(output);
    }

    /// <summary>
    /// A calendar with one VEVENT made from the main component: the attendees <paramref name="keep"/>
    /// accepts, a fresh DTSTAMP, without <paramref name="drop"/> and alarms, plus <paramref name="extra"/>.
    /// Time zones are kept for the times it still uses.
    /// </summary>
    private static string Single(string ics, string method, Func<string, bool> keep, List<string> extra, HashSet<string> drop)
    {
        var lines = ICalendar.UnfoldLines(ics).ToList();
        var events = ICalendarWriter.FindEvents(lines);
        var master = events.First(e => !e.IsOverride);
        var output = new List<string>();
        for (var i = 0; i < lines.Count; i++)
        {
            var line = lines[i];
            if (events.FirstOrDefault(e => i >= e.Begin && i <= e.End) is { } ev)
            {
                if (ev != master) { i = ev.End; continue; }
                if (i == ev.Begin || i == ev.End) { output.Add(line); continue; }
                if (ev.Depth(i) != 0) continue;
                var name = ICalendarWriter.PropertyName(line);
                if (name is "DTSTAMP" or "METHOD" || drop.Contains(name)) continue;
                if (name == "ATTENDEE" && !keep(ICalendar.AddressOf(ICalendar.SplitProperty(line).Value))) continue;
                output.Add(name is "ATTENDEE" or "ORGANIZER" ? Clean(line) : line);
                if (name == "UID")
                {
                    output.Add("DTSTAMP:" + ICalendarWriter.UtcStamp());
                    output.AddRange(extra);
                }
                continue;
            }
            if (ICalendarWriter.PropertyName(line) == "METHOD") continue;
            output.Add(line);
            if (line.Equals("BEGIN:VCALENDAR", StringComparison.OrdinalIgnoreCase)) output.Add("METHOD:" + method);
        }
        return ICalendarWriter.Serialize(output);
    }

    /// <summary>The line without the parameters only the user's CalDAV server cares about.</summary>
    private static string Clean(string line) => WithParams(line, p =>
    {
        p.Remove("SCHEDULE-AGENT");
        p.Remove("SCHEDULE-STATUS");
        p.Remove("SCHEDULE-FORCE-SEND");
    });

    private static string WithParams(string line, Action<Dictionary<string, string>> change)
    {
        var (name, parameters, value) = ICalendar.SplitProperty(line);
        change(parameters);
        return name + string.Concat(parameters.Select(kv => ICalendarWriter.Param(kv.Key.ToUpperInvariant(), kv.Value))) + ":" + value;
    }

    private static string PartStat(AttendeeStatus s) => s switch
    {
        AttendeeStatus.Accepted => "ACCEPTED",
        AttendeeStatus.Tentative => "TENTATIVE",
        AttendeeStatus.Declined => "DECLINED",
        AttendeeStatus.Delegated => "DELEGATED",
        _ => "NEEDS-ACTION",
    };

    // ------------------------------------------------------------------ reading

    private static ICalEvent? Master(string ics)
    {
        var events = ICalendar.ParseEvents(ics, TimeZoneInfo.Utc);
        return events.FirstOrDefault(e => e.RecurrenceIdWall == null) ?? events.FirstOrDefault();
    }

    /// <summary>What guests are told about when it changes.</summary>
    private static (string, string?, string?, DateTimeOffset, DateTimeOffset, bool, string?) Significant(ICalEvent e) =>
        (e.Summary, e.Location, e.Description, e.Start, e.End, e.AllDay, e.RRule?.ToUpperInvariant());

    private static List<EventAttendee> Others(IEnumerable<EventAttendee> people, IReadOnlyCollection<string> mine) =>
        people.Where(p => !IsMine(p.Email, mine)).DistinctBy(p => p.Email, StringComparer.OrdinalIgnoreCase).ToList();

    public static bool IsMine(string email, IReadOnlyCollection<string> mine) => mine.Any(m => Same(m, email));

    private static bool Same(string a, string b) => string.Equals(a.Trim(), b.Trim(), StringComparison.OrdinalIgnoreCase);

    // ------------------------------------------------------------------ the email

    /// <summary>Subject and plain-text body for the email carrying <paramref name="m"/>, with times in <paramref name="zone"/>.</summary>
    public static (string Subject, string Text) Describe(SchedulingMessage m, TimeZoneInfo zone)
    {
        var ev = Master(m.Ics);
        var summary = string.IsNullOrWhiteSpace(ev?.Summary) ? "(no title)" : ev.Summary;
        var when = ev == null ? "" : When(ev, zone);
        var occurrence = ev?.RecurrenceIdWall != null;
        var who = m.Sender.Display;
        var subject = m.Kind switch
        {
            SchedulingKind.Invitation => $"Invitation: {summary} @ {when}",
            SchedulingKind.Update => $"Updated invitation: {summary} @ {when}",
            SchedulingKind.Cancellation => $"Cancelled: {summary} @ {when}",
            _ => $"{AnswerWord(m.Sender.Status)}: {summary} @ {when}",
        };
        var sb = new StringBuilder();
        sb.AppendLine(m.Kind switch
        {
            SchedulingKind.Invitation => $"{who} has invited you to this event.",
            SchedulingKind.Update => $"{who} has changed this event.",
            SchedulingKind.Cancellation => occurrence ? $"{who} has cancelled this occurrence of the event." : $"{who} has cancelled this event.",
            _ => m.Sender.Status switch
            {
                AttendeeStatus.Accepted => $"{who} has accepted your invitation.",
                AttendeeStatus.Tentative => $"{who} might attend (tentatively accepted).",
                AttendeeStatus.Declined => $"{who} has declined your invitation.",
                _ => $"{who} has replied to your invitation.",
            },
        });
        sb.AppendLine();
        sb.AppendLine(summary);
        if (ev != null)
        {
            sb.Append("When: ").AppendLine(when);
            if (!occurrence && ICalendarWriter.RepeatOf(ev.RRule) is var repeat && ev.RRule != null)
                sb.Append("Repeats: ").AppendLine(repeat switch
                {
                    EventRepeat.Daily => "every day",
                    EventRepeat.Weekly => "every week",
                    EventRepeat.Monthly => "every month",
                    EventRepeat.Yearly => "every year",
                    _ => "on a custom schedule",
                });
            if (ev.Location != null) sb.Append("Where: ").AppendLine(ev.Location);
            if (m.Kind is not SchedulingKind.Reply)
            {
                if (ev.Organizer != null) sb.Append("Organiser: ").AppendLine(Person(ev.Organizer));
                if (ev.Attendees.Count > 0)
                {
                    sb.AppendLine("Guests:");
                    foreach (var a in ev.Attendees)
                        sb.Append("  - ").Append(Person(a)).AppendLine(a.Optional ? " (optional)" : "");
                }
                if (ev.Description != null) sb.AppendLine().AppendLine(ev.Description);
            }
        }
        if (m.Kind is SchedulingKind.Invitation or SchedulingKind.Update)
            sb.AppendLine().AppendLine("Open the attached invitation to add it to your calendar and reply.");
        return (subject, sb.ToString());
    }

    private static string AnswerWord(AttendeeStatus s) => s switch
    {
        AttendeeStatus.Accepted => "Accepted",
        AttendeeStatus.Tentative => "Tentative",
        AttendeeStatus.Declined => "Declined",
        _ => "Reply",
    };

    private static string Person(EventAttendee a) => string.IsNullOrWhiteSpace(a.Name) ? a.Email : $"{a.Name} <{a.Email}>";

    /// <summary>"Tue 3 Nov 2026, 09:00 – 10:00 (Europe/London)", or the dates of an all-day event.</summary>
    public static string When(ICalEvent ev, TimeZoneInfo zone)
    {
        if (ev.AllDay)
        {
            var first = ev.StartWall.Date;
            var last = ev.EndWall.Date.AddDays(-1);
            return last > first
                ? $"{first.ToString("ddd d MMM yyyy", Inv)} – {last.ToString("ddd d MMM yyyy", Inv)}"
                : first.ToString("ddd d MMM yyyy", Inv);
        }
        var s = TimeZoneInfo.ConvertTime(ev.Start, zone).DateTime;
        var e = TimeZoneInfo.ConvertTime(ev.End, zone).DateTime;
        var range = s.Date == e.Date
            ? $"{s.ToString("ddd d MMM yyyy, HH:mm", Inv)} – {e.ToString("HH:mm", Inv)}"
            : $"{s.ToString("ddd d MMM yyyy, HH:mm", Inv)} – {e.ToString("ddd d MMM yyyy, HH:mm", Inv)}";
        return $"{range} ({ICalendarWriter.TzidOf(zone) ?? "UTC"})";
    }
}
