// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using Nullify.WebMail.Shared;

namespace Nullify.WebMail.Services;

/// <summary>
/// A scheduling message that arrived by email. <see cref="Event"/> is null when it has no
/// DTSTART (replies may leave it out); the people and UID are read either way.
/// </summary>
public sealed record IncomingScheduling(
    string Method, string Uid, string Summary, int Sequence, ICalEvent? Event,
    EventAttendee? Organizer, IReadOnlyList<EventAttendee> Attendees, DateTimeOffset? RecurrenceId, string Ics)
{
    public bool ForOccurrence => RecurrenceId != null;
}

/// <summary>Reading invitations, cancellations and replies, and applying them to the user's copy.</summary>
public static partial class Scheduling
{
    /// <summary>The scheduling message in <paramref name="ics"/>, or null for a plain calendar file or an unsupported method.</summary>
    public static IncomingScheduling? Read(string ics, TimeZoneInfo zone)
    {
        var lines = ICalendar.UnfoldLines(ics).ToList();
        var method = lines.TakeWhile(l => !l.StartsWith("BEGIN:", StringComparison.OrdinalIgnoreCase) || l.Equals("BEGIN:VCALENDAR", StringComparison.OrdinalIgnoreCase))
            .Where(l => ICalendarWriter.PropertyName(l) == "METHOD")
            .Select(l => ICalendar.SplitProperty(l).Value.Trim().ToUpperInvariant()).FirstOrDefault();
        if (method is not ("REQUEST" or "CANCEL" or "REPLY")) return null;

        var block = ICalendarWriter.FindEvents(lines).FirstOrDefault(b => !b.IsOverride) ?? ICalendarWriter.FindEvents(lines).FirstOrDefault();
        if (block == null) return null;
        string? uid = null, summary = null;
        var sequence = 0;
        EventAttendee? organizer = null;
        var attendees = new List<EventAttendee>();
        DateTimeOffset? recurrenceId = null;
        for (var i = block.Begin + 1; i < block.End; i++)
        {
            if (block.Depth(i) != 0) continue;
            var (name, parameters, value) = ICalendar.SplitProperty(lines[i]);
            switch (name.ToUpperInvariant())
            {
                case "UID": uid = value.Trim(); break;
                case "SUMMARY": summary = value.Replace("\\n", " ").Replace("\\,", ",").Replace("\\;", ";").Replace("\\\\", "\\"); break;
                case "SEQUENCE": int.TryParse(value, out sequence); break;
                case "ORGANIZER": organizer = ICalendar.ParsePerson(value, parameters); break;
                case "ATTENDEE": if (ICalendar.ParsePerson(value, parameters) is { } a) attendees.Add(a); break;
                case "RECURRENCE-ID":
                    if (ICalendar.TryParseTime(value, parameters, zone, out var wall, out var z, out var allDay))
                        recurrenceId = allDay ? new DateTimeOffset(wall.Date, TimeSpan.Zero) : new DateTimeOffset(wall, z.GetUtcOffset(wall));
                    break;
            }
        }
        if (string.IsNullOrEmpty(uid)) return null;
        var events = ICalendar.ParseEvents(ics, zone);
        var ev = events.FirstOrDefault(e => e.Uid == uid && e.RecurrenceIdWall == null) ?? events.FirstOrDefault(e => e.Uid == uid);
        return new IncomingScheduling(method, uid, string.IsNullOrWhiteSpace(summary) ? "(no title)" : summary.Trim(),
            sequence, ev, organizer, attendees, recurrenceId, ics);
    }

    /// <summary>
    /// Null when an invitation update or cancellation may change <paramref name="stored"/>
    /// (null when not in the calendar), otherwise why not: it must come from the organiser
    /// of the stored event. <paramref name="from"/> are the email's From and Sender addresses.
    /// </summary>
    public static string? WhyNotFromOrganizer(IncomingScheduling m, string? stored, IReadOnlyCollection<string> from)
    {
        if (m.Organizer is not { } organizer) return "It doesn't say who organised the event.";
        if (!from.Any(f => Same(f, organizer.Email))) return $"This email wasn't sent by the organiser, {organizer.Email}.";
        if (stored != null && Master(stored)?.Organizer is { } o && !Same(o.Email, organizer.Email))
            return $"The event in your calendar is organised by {o.Display}, not {organizer.Display}.";
        return null;
    }

    /// <summary>The user's answer recorded in a stored event, or null when they aren't a guest.</summary>
    public static AttendeeStatus? AnswerIn(string stored, IReadOnlyCollection<string> mine) =>
        Master(stored)?.Attendees.FirstOrDefault(a => IsMine(a.Email, mine))?.Status;

    /// <summary>The SEQUENCE of a stored event's main component.</summary>
    public static int SequenceOf(string stored) => Master(stored)?.Sequence ?? 0;

    /// <summary>
    /// Record a guest's REPLY in the user's copy of a meeting they organise: that guest's
    /// PARTSTAT in the main component, or in the occurrence the reply is about.
    /// </summary>
    /// <returns>The updated .ics and the guest as they answered.</returns>
    /// <exception cref="InvalidOperationException">The reply can't be applied; the message says why.</exception>
    public static (string Updated, EventAttendee Guest) ApplyReply(string stored, IncomingScheduling reply,
        IReadOnlyCollection<string> from, IReadOnlyCollection<string> mine)
    {
        if (Master(stored)?.Organizer is not { } organizer || !IsMine(organizer.Email, mine))
            throw new InvalidOperationException("This reply is about a meeting you don't organise.");
        var guest = reply.Attendees.FirstOrDefault() ?? throw new InvalidOperationException("The reply doesn't say who answered.");
        if (!from.Any(f => Same(f, guest.Email)))
            throw new InvalidOperationException($"This email wasn't sent by {guest.Email}, who it answers for.");

        var lines = ICalendar.UnfoldLines(stored).ToList();
        var blocks = ICalendarWriter.FindEvents(lines);
        var target = reply.RecurrenceId is { } rid
            ? blocks.FirstOrDefault(b => b.IsOverride && BlockEvent(lines, b)?.OccurrenceId == rid)
            : blocks.FirstOrDefault(b => !b.IsOverride);
        if (target == null)
            throw new InvalidOperationException(reply.ForOccurrence
                ? $"{guest.Display} answered for a single occurrence, which your calendar doesn't keep separately."
                : "Your copy of the meeting has no main component.");

        // An answer to times the meeting no longer has is out of date (RFC 5546 2.1.5).
        if (reply.Event is { } answered && BlockEvent(lines, target) is { } current && !reply.ForOccurrence && answered.Start != current.Start)
            throw new InvalidOperationException($"{guest.Display} answered an earlier version of this meeting; it has moved since.");

        var found = false;
        for (var i = target.Begin + 1; i < target.End; i++)
        {
            if (target.Depth(i) != 0 || ICalendarWriter.PropertyName(lines[i]) != "ATTENDEE") continue;
            if (!Same(ICalendar.AddressOf(ICalendar.SplitProperty(lines[i]).Value), guest.Email)) continue;
            lines[i] = WithParams(lines[i], p =>
            {
                p["PARTSTAT"] = PartStat(guest.Status);
                p.Remove("RSVP");
            });
            found = true;
        }
        if (!found) throw new InvalidOperationException($"{guest.Display} isn't on this meeting's guest list.");
        return (ICalendarWriter.Serialize(lines), guest);
    }

    /// <summary>The stored copy an accepted invitation becomes: its single event without METHOD.</summary>
    public static string ForCalendar(IncomingScheduling m) =>
        ICalendar.SplitForImport(m.Ics).Where(e => e.Uid == m.Uid).Select(e => e.Ics).FirstOrDefault()
        ?? throw new InvalidOperationException("The invitation has no event in it.");

    private static ICalEvent? BlockEvent(List<string> lines, ICalendarWriter.EventBlock block) =>
        ICalendar.ParseEvents(ICalendarWriter.Serialize(["BEGIN:VCALENDAR", .. lines.Skip(block.Begin).Take(block.End - block.Begin + 1), "END:VCALENDAR"]),
            TimeZoneInfo.Utc).FirstOrDefault();
}
