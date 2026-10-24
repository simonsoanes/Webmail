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
}
