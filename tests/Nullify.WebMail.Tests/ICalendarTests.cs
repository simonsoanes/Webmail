// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using Nullify.WebMail.Services;

namespace Nullify.WebMail.Tests;

[TestClass]
public class ICalendarTests
{
    private static readonly TimeZoneInfo London = TimeZoneInfo.FindSystemTimeZoneById("Europe/London");

    private static DateTimeOffset Utc(int y, int m, int d, int h = 0, int min = 0) => new(y, m, d, h, min, 0, TimeSpan.Zero);

    private static string Cal(string body) => "BEGIN:VCALENDAR\r\nVERSION:2.0\r\n" + body.Replace("\n", "\r\n") + "\r\nEND:VCALENDAR\r\n";

    [TestMethod]
    public void Parses_TzidTimes_FoldedLines_AndEscapes()
    {
        var events = ICalendar.ParseEvents(Cal("""
            BEGIN:VEVENT
            UID:a1
            DTSTART;TZID=Europe/London:20260701T093000
            DTEND;TZID=Europe/London:20260701T103000
            SUMMARY:Planning\, with a very long title that is
              folded
            LOCATION:Room 1\; floor 2
            DESCRIPTION:Line one\nLine two
            BEGIN:VALARM
            TRIGGER:-PT15M
            SUMMARY:Alarm summary must not leak
            END:VALARM
            END:VEVENT
            """), TimeZoneInfo.Utc);

        var ev = events.Single();
        Assert.AreEqual("Planning, with a very long title that is folded", ev.Summary);
        Assert.AreEqual("Room 1; floor 2", ev.Location);
        Assert.AreEqual("Line one\nLine two", ev.Description);
        Assert.AreEqual(Utc(2026, 7, 1, 8, 30), ev.Start); // BST is UTC+1
        Assert.AreEqual(TimeSpan.FromHours(1), ev.End - ev.Start);
    }

    [TestMethod]
    public void Alarms_RelativeToStartOrEnd_OrAtAFixedTime_EmailOnesLeftOut()
    {
        var ev = ICalendar.ParseEvents(Cal("""
            BEGIN:VEVENT
            UID:al
            DTSTART:20261102T100000Z
            DTEND:20261102T110000Z
            SUMMARY:Review
            BEGIN:VALARM
            ACTION:DISPLAY
            TRIGGER:-PT15M
            END:VALARM
            BEGIN:VALARM
            ACTION:AUDIO
            TRIGGER;RELATED=END:-PT90M
            END:VALARM
            BEGIN:VALARM
            ACTION:DISPLAY
            TRIGGER;VALUE=DATE-TIME:20261101T100000Z
            END:VALARM
            BEGIN:VALARM
            ACTION:EMAIL
            TRIGGER:-P2D
            END:VALARM
            END:VEVENT
            """), TimeZoneInfo.Utc).Single();

        CollectionAssert.AreEqual(new[] { TimeSpan.FromDays(1), TimeSpan.FromMinutes(30), TimeSpan.FromMinutes(15) }, ev.Alarms);
    }

    [TestMethod]
    public void Alarms_CarryOverToExpandedOccurrences()
    {
        var events = ICalendar.ParseEvents(Cal("""
            BEGIN:VEVENT
            UID:weekly
            DTSTART:20261102T100000Z
            DTEND:20261102T110000Z
            RRULE:FREQ=WEEKLY;COUNT=3
            BEGIN:VALARM
            TRIGGER:-PT10M
            END:VALARM
            END:VEVENT
            """), TimeZoneInfo.Utc);
        var instances = ICalendar.Expand(events, Utc(2026, 11, 1), Utc(2026, 12, 1));
        Assert.HasCount(3, instances);
        Assert.IsTrue(instances.All(i => i.Alarms.SequenceEqual([TimeSpan.FromMinutes(10)])));
    }

    [TestMethod]
    public void AllDay_And_Duration_Defaults()
    {
        var events = ICalendar.ParseEvents(Cal("""
            BEGIN:VEVENT
            UID:holiday
            DTSTART;VALUE=DATE:20261026
            DTEND;VALUE=DATE:20261029
            SUMMARY:Trip
            END:VEVENT
            BEGIN:VEVENT
            UID:call
            DTSTART:20261024T140000Z
            DURATION:PT45M
            SUMMARY:Call
            END:VEVENT
            """), TimeZoneInfo.Utc);

        var trip = events.Single(e => e.Uid == "holiday");
        Assert.IsTrue(trip.AllDay);
        Assert.AreEqual(3, (trip.End - trip.Start).Days);
        var call = events.Single(e => e.Uid == "call");
        Assert.AreEqual(Utc(2026, 10, 24, 14, 45), call.End);
    }

    [TestMethod]
    public void Weekly_Rrule_KeepsLocalTimeAcrossDst_AndHonoursExdateAndOverride()
    {
        var events = ICalendar.ParseEvents(Cal("""
            BEGIN:VEVENT
            UID:standup
            DTSTART;TZID=Europe/London:20261019T090000
            DTEND;TZID=Europe/London:20261019T091500
            RRULE:FREQ=WEEKLY;BYDAY=MO,WE;COUNT=6
            EXDATE;TZID=Europe/London:20261021T090000
            SUMMARY:Standup
            END:VEVENT
            BEGIN:VEVENT
            UID:standup
            RECURRENCE-ID;TZID=Europe/London:20261026T090000
            DTSTART;TZID=Europe/London:20261026T100000
            DTEND;TZID=Europe/London:20261026T101500
            SUMMARY:Standup (moved)
            END:VEVENT
            """), TimeZoneInfo.Utc);

        var instances = ICalendar.Expand(events, Utc(2026, 10, 1), Utc(2026, 12, 1))
            .OrderBy(e => e.Start).ToList();

        // Mo19 We21(excluded) Mo26(overridden) We28 Mo2 We4 → 5 shown, incl. the moved one.
        Assert.HasCount(5, instances);
        Assert.AreEqual(Utc(2026, 10, 19, 8), instances[0].Start);          // 09:00 BST
        Assert.AreEqual("Standup (moved)", instances[1].Summary);
        Assert.AreEqual(Utc(2026, 10, 26, 10), instances[1].Start);         // 10:00 GMT
        Assert.AreEqual(Utc(2026, 10, 28, 9), instances[2].Start);          // 09:00 GMT after DST ends
        Assert.IsTrue(instances.All(i => TimeZoneInfo.ConvertTime(i.Start, London).Minute == 0));
    }

    [TestMethod]
    public void Expand_ClipsToRange_AndHonoursUntil()
    {
        var events = ICalendar.ParseEvents(Cal("""
            BEGIN:VEVENT
            UID:daily
            DTSTART:20261001T120000Z
            DTEND:20261001T130000Z
            RRULE:FREQ=DAILY;INTERVAL=2;UNTIL=20261031T235959Z
            SUMMARY:Every other day
            END:VEVENT
            """), TimeZoneInfo.Utc);

        var october = ICalendar.Expand(events, Utc(2026, 10, 1), Utc(2026, 11, 30));
        Assert.HasCount(16, october); // Oct 1,3,...,31
        var lastWeek = ICalendar.Expand(events, Utc(2026, 10, 25), Utc(2026, 11, 1));
        Assert.HasCount(4, lastWeek); // 25, 27, 29, 31
    }

    [TestMethod]
    public void Cancelled_AndFloatingTimes()
    {
        var events = ICalendar.ParseEvents(Cal("""
            BEGIN:VEVENT
            UID:gone
            DTSTART:20261024T100000Z
            STATUS:CANCELLED
            SUMMARY:Cancelled
            END:VEVENT
            BEGIN:VEVENT
            UID:floating
            DTSTART:20260701T090000
            DTEND:20260701T100000
            SUMMARY:Floating
            END:VEVENT
            """), London);

        var shown = ICalendar.Expand(events, Utc(2026, 1, 1), Utc(2027, 1, 1));
        Assert.AreEqual("Floating", shown.Single().Summary);
        Assert.AreEqual(Utc(2026, 7, 1, 8), shown.Single().Start); // floating → viewer's zone
    }

    [TestMethod]
    public void SplitForImport_OneResourcePerUid_WithItsZones_AndNoMethod()
    {
        var ics = """
            BEGIN:VCALENDAR
            VERSION:2.0
            PRODID:-//Example//EN
            METHOD:REQUEST
            BEGIN:VTIMEZONE
            TZID:Europe/London
            BEGIN:STANDARD
            DTSTART:19701025T020000
            TZOFFSETFROM:+0100
            TZOFFSETTO:+0000
            END:STANDARD
            END:VTIMEZONE
            BEGIN:VTIMEZONE
            TZID:America/New_York
            BEGIN:STANDARD
            DTSTART:19701101T020000
            TZOFFSETFROM:-0400
            TZOFFSETTO:-0500
            END:STANDARD
            END:VTIMEZONE
            BEGIN:VEVENT
            UID:series
            DTSTART;TZID=Europe/Lon
             don:20260701T093000
            RRULE:FREQ=WEEKLY
            SUMMARY:Weekly
            BEGIN:VALARM
            UID:alarm-not-event
            TRIGGER:-PT15M
            END:VALARM
            END:VEVENT
            BEGIN:VEVENT
            UID:series
            RECURRENCE-ID;TZID=Europe/London:20260708T093000
            DTSTART;TZID=Europe/London:20260708T100000
            SUMMARY:Weekly (moved)
            END:VEVENT
            BEGIN:VEVENT
            DTSTART;VALUE=DATE:20260710
            SUMMARY:No UID
            END:VEVENT
            BEGIN:VTODO
            UID:todo
            END:VTODO
            END:VCALENDAR
            """.ReplaceLineEndings("\r\n");

        var parts = ICalendar.SplitForImport(ics);

        Assert.AreEqual(2, parts.Count);
        var (uid, series) = parts[0];
        Assert.AreEqual("series", uid);
        Assert.IsFalse(series.Contains("METHOD"));
        Assert.IsTrue(series.Contains("PRODID:-//Example//EN"));
        Assert.IsTrue(series.Contains("TZID:Europe/London"));
        Assert.IsFalse(series.Contains("America/New_York"));
        Assert.IsFalse(series.Contains("VTODO"));
        Assert.IsTrue(series.Contains("DTSTART;TZID=Europe/Lon\r\n don:20260701T093000"), "folding is kept");
        var events = ICalendar.ParseEvents(series, London);
        Assert.AreEqual(2, events.Count);
        Assert.AreEqual(1, events.Count(e => e.RecurrenceIdWall != null));
        Assert.IsTrue(series.StartsWith("BEGIN:VCALENDAR\r\n") && series.EndsWith("END:VCALENDAR\r\n"));

        var (freshUid, single) = parts[1];
        Assert.IsTrue(Guid.TryParse(freshUid, out _));
        Assert.AreEqual(freshUid, ICalendar.ParseEvents(single, London).Single().Uid);
        Assert.IsFalse(single.Contains("VTIMEZONE"));
    }

    [TestMethod]
    public void SplitForImport_AddsVersionAndProdId_WhenMissing()
    {
        var (_, ics) = ICalendar.SplitForImport("BEGIN:VCALENDAR\nBEGIN:VEVENT\nUID:x\nDTSTART:20260701T090000Z\nEND:VEVENT\nEND:VCALENDAR\n").Single();
        StringAssert.Contains(ics, "VERSION:2.0\r\n");
        StringAssert.Contains(ics, "PRODID:");
    }
}
