// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using Nullify.WebMail.Services;
using Nullify.WebMail.Shared;

namespace Nullify.WebMail.Tests;

[TestClass]
public class WriterTests
{
    private static readonly TimeZoneInfo London = TimeZoneInfo.FindSystemTimeZoneById("Europe/London");

    // ------------------------------------------------------------------ vCard

    [TestMethod]
    public void VCardWrite_ReplacesEditedFields_KeepsEverythingElse()
    {
        var original = """
            BEGIN:VCARD
            VERSION:3.0
            UID:alice
            FN:Alice Chen
            N:Chen;Alice;;;
            item1.EMAIL;type=INTERNET;type=WORK:alice@old.example
            item1.X-ABLabel:_$!<Work>!$_
            ADR;TYPE=HOME:;;1 High St;Leeds;;LS1;UK
            X-CUSTOM:keep me
            PHOTO;ENCODING=b;TYPE=JPEG:/9j/4AAQ
            END:VCARD
            """.Replace("\n", "\r\n");

        var edit = new ContactEdit("Alice", "Chen-Smith", "Example; Org", "CFO",
            [new ContactValue("alice@new.example", "Work")], [new ContactValue("+44 7700 900123", "Mobile")],
            "1990-05-17", "Line one\nLine two, with comma");
        var written = VCard.Write(original, edit, "alice");

        StringAssert.Contains(written, "ADR;TYPE=HOME:;;1 High St;Leeds;;LS1;UK");
        StringAssert.Contains(written, "X-CUSTOM:keep me");
        StringAssert.Contains(written, "PHOTO;ENCODING=b;TYPE=JPEG:/9j/4AAQ");
        Assert.DoesNotContain("alice@old.example", written);
        Assert.DoesNotContain("X-ABLabel", written); // label belonged to the replaced email

        var parsed = VCard.Parse(written).Single();
        Assert.AreEqual("Alice Chen-Smith", parsed.FullName);
        Assert.AreEqual("Example; Org", parsed.Organization);
        Assert.AreEqual("alice@new.example", parsed.Email);
        Assert.AreEqual("Mobile", parsed.Phones.Single().Label);
        Assert.AreEqual("Line one\nLine two, with comma", parsed.Note);
        Assert.AreEqual("alice", parsed.Uid);
    }

    [TestMethod]
    public void VCardFold_NeverSplitsUtf8Sequences()
    {
        var line = "NOTE:" + string.Concat(Enumerable.Repeat("é✓", 60));
        var folded = VCard.Fold(line);
        foreach (var part in folded.Split("\r\n"))
            Assert.IsLessThanOrEqualTo(75, System.Text.Encoding.UTF8.GetByteCount(part));
        Assert.AreEqual(line, folded.Replace("\r\n ", ""));
    }

    // ------------------------------------------------------------------ iCalendar

    private static ICalendarWriter.EventTimes Timed(int month, int day, int h, int durHours = 1) =>
        new(new DateTime(2026, month, day, h, 0, 0), new DateTime(2026, month, day, h + durHours, 0, 0), false, London);

    [TestMethod]
    public void NewEvent_RoundTrips_WithVTimezone()
    {
        var edit = new EventEdit("Planning, Q4", "Room 1", "Agenda:\nItem", false, default, default, EventRepeat.Weekly);
        var ics = ICalendarWriter.NewEvent("u1", edit, Timed(11, 3, 9), ICalendarWriter.RuleFor(edit.Repeat));

        StringAssert.Contains(ics, "BEGIN:VTIMEZONE");
        StringAssert.Contains(ics, "TZID:Europe/London");
        StringAssert.Contains(ics, "DTSTART;TZID=Europe/London:20261103T090000");
        var ev = ICalendar.ParseEvents(ics, TimeZoneInfo.Utc).Single();
        Assert.AreEqual("Planning, Q4", ev.Summary);
        Assert.AreEqual("Agenda:\nItem", ev.Description);
        Assert.AreEqual(new DateTimeOffset(2026, 11, 3, 9, 0, 0, TimeSpan.Zero), ev.Start); // GMT in November
        Assert.AreEqual("FREQ=WEEKLY", ev.RRule);
    }

    [TestMethod]
    public void AllDayEvent_WritesExclusiveEndDate()
    {
        var edit = new EventEdit("Trip", null, null, true, default, default, EventRepeat.None);
        var ics = ICalendarWriter.NewEvent("u2", edit,
            new(new DateTime(2026, 10, 29), new DateTime(2026, 10, 31), true, London), null);
        StringAssert.Contains(ics, "DTSTART;VALUE=DATE:20261029");
        StringAssert.Contains(ics, "DTEND;VALUE=DATE:20261101");
        Assert.DoesNotContain("VTIMEZONE", ics);
    }

    private const string Series = """
        BEGIN:VCALENDAR
        VERSION:2.0
        PRODID:-//Other//EN
        BEGIN:VEVENT
        UID:standup
        DTSTART:20261019T080000Z
        DTEND:20261019T081500Z
        RRULE:FREQ=WEEKLY;BYDAY=MO,WE
        EXDATE:20261021T080000Z
        SUMMARY:Standup
        SEQUENCE:3
        ATTENDEE;CN=Bob:mailto:bob@example.org
        BEGIN:VALARM
        ACTION:DISPLAY
        DESCRIPTION:Reminder
        TRIGGER:-PT10M
        END:VALARM
        END:VEVENT
        BEGIN:VEVENT
        UID:standup
        RECURRENCE-ID:20261026T090000Z
        DTSTART:20261026T100000Z
        DTEND:20261026T101500Z
        SUMMARY:Standup (moved)
        END:VEVENT
        END:VCALENDAR
        """;

    [TestMethod]
    public void UpdateMaster_KeepsAlarmsAndAttendees_BumpsSequence()
    {
        var edit = new EventEdit("Daily standup", null, null, false, default, default, EventRepeat.Weekly);
        var updated = ICalendarWriter.UpdateMaster(Series.Replace("\n", "\r\n"), edit, Timed(10, 19, 9), "FREQ=WEEKLY;BYDAY=MO,WE", dropExceptions: false);

        StringAssert.Contains(updated, "ATTENDEE;CN=Bob:mailto:bob@example.org");
        StringAssert.Contains(updated, "TRIGGER:-PT10M");
        StringAssert.Contains(updated, "DESCRIPTION:Reminder"); // the alarm's DESCRIPTION is not the event's
        StringAssert.Contains(updated, "SEQUENCE:4");
        StringAssert.Contains(updated, "EXDATE:20261021T080000Z");
        StringAssert.Contains(updated, "Standup (moved)");
        var master = ICalendar.ParseEvents(updated, TimeZoneInfo.Utc).Single(e => e.RecurrenceIdWall == null);
        Assert.AreEqual("Daily standup", master.Summary);
        Assert.AreEqual("FREQ=WEEKLY;BYDAY=MO,WE", master.RRule);
    }

    [TestMethod]
    public void UpdateMaster_DroppingExceptions_RemovesOverridesAndExdates()
    {
        var edit = new EventEdit("Standup", null, null, false, default, default, EventRepeat.Daily);
        var updated = ICalendarWriter.UpdateMaster(Series, edit, Timed(10, 19, 10), "FREQ=DAILY", dropExceptions: true);
        Assert.DoesNotContain("RECURRENCE-ID", updated);
        Assert.DoesNotContain("EXDATE", updated);
        Assert.HasCount(1, ICalendar.ParseEvents(updated, TimeZoneInfo.Utc));
    }

    [TestMethod]
    public void ExcludeOccurrence_AddsExdate_AndRemovesItsOverride()
    {
        var moved = new DateTimeOffset(2026, 10, 26, 9, 0, 0, TimeSpan.Zero);
        var updated = ICalendarWriter.ExcludeOccurrence(Series, moved, allDay: false);
        StringAssert.Contains(updated, "EXDATE:20261026T090000Z");
        Assert.DoesNotContain("Standup (moved)", updated);

        var instances = ICalendar.Expand(ICalendar.ParseEvents(updated, TimeZoneInfo.Utc),
            new DateTimeOffset(2026, 10, 19, 0, 0, 0, TimeSpan.Zero), new DateTimeOffset(2026, 11, 1, 0, 0, 0, TimeSpan.Zero));
        // The override for the skipped occurrence is gone with it.
        CollectionAssert.DoesNotContain(instances.Select(i => i.Summary).ToList(), "Standup (moved)");
    }

    [TestMethod]
    public void VTimezone_DescribesLondonDst()
    {
        var lines = ICalendarWriter.VTimezone(London, "Europe/London", 2026);
        CollectionAssert.Contains(lines, "RRULE:FREQ=YEARLY;BYMONTH=3;BYDAY=-1SU");
        CollectionAssert.Contains(lines, "RRULE:FREQ=YEARLY;BYMONTH=10;BYDAY=-1SU");
        CollectionAssert.Contains(lines, "TZOFFSETTO:+0100");
        CollectionAssert.Contains(lines, "TZOFFSETTO:+0000");
    }
}
