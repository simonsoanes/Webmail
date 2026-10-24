// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using Nullify.WebMail.Services;
using Nullify.WebMail.Shared;

namespace Nullify.WebMail.Tests;

[TestClass]
public class NotesAndTasksTests
{
    private static readonly TimeZoneInfo London = TimeZoneInfo.FindSystemTimeZoneById("Europe/London");

    private static string Ics(string body) => ("BEGIN:VCALENDAR\nVERSION:2.0\nPRODID:-//Test//EN\n" + body + "\nEND:VCALENDAR\n").Replace("\n", "\r\n");

    // ------------------------------------------------------------------ notes

    [TestMethod]
    public void ParseJournals_JoinsDescriptions_AndReadsCategories()
    {
        var ics = Ics("""
            BEGIN:VJOURNAL
            UID:n1
            SUMMARY:Shopping\, weekly
            DESCRIPTION:Milk\nEggs
            DESCRIPTION:Bread
            CATEGORIES:Home,Errands\,misc
            LAST-MODIFIED:20260301T101500Z
            END:VJOURNAL
            """);

        var note = ICalendar.ParseJournals(ics, London).Single();
        Assert.AreEqual("n1", note.Uid);
        Assert.AreEqual("Shopping, weekly", note.Summary);
        Assert.AreEqual("Milk\nEggs\n\nBread", note.Description);
        CollectionAssert.AreEqual(new[] { "Home", "Errands,misc" }, note.Categories.ToArray());
        Assert.AreEqual(new DateTimeOffset(2026, 3, 1, 10, 15, 0, TimeSpan.Zero), note.Modified);
    }

    [TestMethod]
    public void NewJournal_RoundTrips()
    {
        var ics = ICalendarWriter.NewJournal("abc", new NoteEdit("Ideas; v2", "Line one\nLine two, with comma"));
        StringAssert.Contains(ics, "BEGIN:VJOURNAL");
        var note = ICalendar.ParseJournals(ics, London).Single();
        Assert.AreEqual("abc", note.Uid);
        Assert.AreEqual("Ideas; v2", note.Summary);
        Assert.AreEqual("Line one\nLine two, with comma", note.Description);
        Assert.IsNotNull(note.Modified);
    }

    [TestMethod]
    public void UpdateJournal_ReplacesText_KeepsEverythingElse()
    {
        var original = Ics("""
            BEGIN:VJOURNAL
            UID:n1
            SEQUENCE:3
            SUMMARY:Old
            DESCRIPTION:First part
            DESCRIPTION:Second part
            X-CUSTOM:keep me
            CATEGORIES:Work
            BEGIN:VALARM
            ACTION:DISPLAY
            DESCRIPTION:Alarm text stays
            TRIGGER:-PT5M
            END:VALARM
            END:VJOURNAL
            """);

        var updated = ICalendarWriter.UpdateJournal(original, new NoteEdit("New", "Only part"));

        StringAssert.Contains(updated, "X-CUSTOM:keep me");
        StringAssert.Contains(updated, "CATEGORIES:Work");
        StringAssert.Contains(updated, "DESCRIPTION:Alarm text stays");
        StringAssert.Contains(updated, "SEQUENCE:4");
        Assert.DoesNotContain("First part", updated);
        Assert.DoesNotContain("SUMMARY:Old", updated);
        var note = ICalendar.ParseJournals(updated, London).Single();
        Assert.AreEqual("New", note.Summary);
        Assert.AreEqual("Only part", note.Description);
    }

    // ------------------------------------------------------------------ tasks

    [TestMethod]
    public void ParseTodos_ReadsDueDatesStatusAndPriority_SkippingOverrides()
    {
        var ics = Ics("""
            BEGIN:VTODO
            UID:t1
            SUMMARY:Pay rent
            DUE;VALUE=DATE:20261101
            PRIORITY:1
            RRULE:FREQ=MONTHLY
            END:VTODO
            BEGIN:VTODO
            UID:t1
            RECURRENCE-ID;VALUE=DATE:20261201
            SUMMARY:Pay rent (moved)
            END:VTODO
            BEGIN:VTODO
            UID:t2
            SUMMARY:Call Ada
            DUE;TZID=Europe/London:20260715T143000
            STATUS:COMPLETED
            COMPLETED:20260715T120000Z
            END:VTODO
            BEGIN:VTODO
            UID:t3
            SUMMARY:Draft
            STATUS:IN-PROCESS
            PERCENT-COMPLETE:40
            PRIORITY:5
            END:VTODO
            """);

        var todos = ICalendar.ParseTodos(ics, London);
        Assert.HasCount(3, todos);

        var rent = todos.Single(t => t.Uid == "t1");
        Assert.IsTrue(rent.DueIsDate);
        Assert.AreEqual(new DateTimeOffset(2026, 11, 1, 0, 0, 0, TimeSpan.Zero), rent.Due);
        Assert.AreEqual(TaskPriority.High, ICalendar.PriorityOf(rent.Priority));
        Assert.IsNotNull(rent.RRule);
        Assert.IsFalse(rent.IsCompleted);

        var call = todos.Single(t => t.Uid == "t2");
        Assert.IsFalse(call.DueIsDate);
        Assert.AreEqual(new DateTimeOffset(2026, 7, 15, 13, 30, 0, TimeSpan.Zero), call.Due!.Value.ToUniversalTime()); // BST
        Assert.IsTrue(call.IsCompleted);

        var draft = todos.Single(t => t.Uid == "t3");
        Assert.IsFalse(draft.IsCompleted);
        Assert.AreEqual(TaskPriority.Medium, ICalendar.PriorityOf(draft.Priority));
    }

    [TestMethod]
    public void NewTodo_WithTimedDue_WritesZoneAndRoundTrips()
    {
        var edit = new TaskEdit("Submit report", "Section 3 first", new DateTime(2026, 1, 20, 17, 0, 0), true, false, TaskPriority.Low);
        var ics = ICalendarWriter.NewTodo("t9", edit, London);

        StringAssert.Contains(ics, "BEGIN:VTIMEZONE");
        StringAssert.Contains(ics, "DUE;TZID=Europe/London:20260120T170000");
        StringAssert.Contains(ics, "STATUS:NEEDS-ACTION");
        var todo = ICalendar.ParseTodos(ics, TimeZoneInfo.Utc).Single();
        Assert.AreEqual("Submit report", todo.Summary);
        Assert.AreEqual("Section 3 first", todo.Description);
        Assert.AreEqual(new DateTimeOffset(2026, 1, 20, 17, 0, 0, TimeSpan.Zero), todo.Due);
        Assert.AreEqual(TaskPriority.Low, ICalendar.PriorityOf(todo.Priority));
    }

    [TestMethod]
    public void UpdateTodo_WithoutTickingIt_KeepsProgress()
    {
        var original = Ics("""
            BEGIN:VTODO
            UID:t3
            SUMMARY:Draft
            STATUS:IN-PROCESS
            PERCENT-COMPLETE:40
            X-APPLE-SORT-ORDER:12
            END:VTODO
            """);

        var updated = ICalendarWriter.UpdateTodo(original,
            new TaskEdit("Draft v2", null, new DateTime(2026, 2, 1), false, false, TaskPriority.None), London);

        StringAssert.Contains(updated, "STATUS:IN-PROCESS");
        StringAssert.Contains(updated, "PERCENT-COMPLETE:40");
        StringAssert.Contains(updated, "X-APPLE-SORT-ORDER:12");
        StringAssert.Contains(updated, "DUE;VALUE=DATE:20260201");
        StringAssert.Contains(updated, "SUMMARY:Draft v2");
        Assert.DoesNotContain("VTIMEZONE", updated);
    }

    [TestMethod]
    public void UpdateTodo_Ticked_MarksCompleted_AndDropsWhatConflictsWithDue()
    {
        var original = Ics("""
            BEGIN:VTODO
            UID:t4
            SUMMARY:Book flights
            DTSTART;VALUE=DATE:20260310
            DURATION:P2D
            STATUS:IN-PROCESS
            PERCENT-COMPLETE:50
            END:VTODO
            """);

        var updated = ICalendarWriter.UpdateTodo(original,
            new TaskEdit("Book flights", null, new DateTime(2026, 3, 1), false, true, TaskPriority.None), London);

        StringAssert.Contains(updated, "STATUS:COMPLETED");
        StringAssert.Contains(updated, "PERCENT-COMPLETE:100");
        StringAssert.Contains(updated, "COMPLETED:");
        Assert.DoesNotContain("IN-PROCESS", updated);
        Assert.DoesNotContain("DURATION", updated);
        Assert.DoesNotContain("DTSTART", updated); // was after the new due date
        Assert.IsTrue(ICalendar.ParseTodos(updated, London).Single().IsCompleted);
    }

    [TestMethod]
    public void SetTodoCompleted_ChangesOnlyStatus()
    {
        var original = Ics("""
            BEGIN:VTODO
            UID:t5
            SUMMARY:Water plants
            DUE;TZID=America/New_York:20260601T080000
            SEQUENCE:1
            END:VTODO
            """);

        var done = ICalendarWriter.SetTodoCompleted(original, true);
        StringAssert.Contains(done, "DUE;TZID=America/New_York:20260601T080000");
        StringAssert.Contains(done, "SUMMARY:Water plants");
        StringAssert.Contains(done, "STATUS:COMPLETED");
        StringAssert.Contains(done, "SEQUENCE:2");

        var undone = ICalendarWriter.SetTodoCompleted(done, false);
        StringAssert.Contains(undone, "STATUS:NEEDS-ACTION");
        Assert.DoesNotContain("COMPLETED:", undone.Replace("STATUS:COMPLETED", ""));
        Assert.DoesNotContain("PERCENT-COMPLETE", undone);
        Assert.IsFalse(ICalendar.ParseTodos(undone, London).Single().IsCompleted);
    }
}
