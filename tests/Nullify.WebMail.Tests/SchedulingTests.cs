// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using System.Text;
using Nullify.WebMail.Services;
using Nullify.WebMail.Shared;

namespace Nullify.WebMail.Tests;

[TestClass]
public class SchedulingTests
{
    private static readonly TimeZoneInfo London = TimeZoneInfo.FindSystemTimeZoneById("Europe/London");
    private static readonly SenderIdentity Me = new("Simon", "simon@example.test");
    private static readonly string[] Mine = ["simon@example.test", "alias@example.test"];

    private static ICalendarWriter.EventTimes Timed(int day, int h) =>
        new(new DateTime(2026, 11, day, h, 0, 0), new DateTime(2026, 11, day, h + 1, 0, 0), false, London);

    private static EventEdit Meeting(string summary, params EventAttendee[] guests) =>
        new(summary, "Room 1", null, false, default, default, EventRepeat.None, guests, Me);

    private static readonly EventAttendee Bob = new("bob@example.org", "Bob");
    private static readonly EventAttendee Carol = new("carol@example.org", "Carol, Finance", Optional: true);

    private static string Invite() => ICalendarWriter.NewEvent("m1", Meeting("Planning", Bob, Carol), Timed(3, 9), null);

    private static string Unfolded(string ics) => ics.Replace("\r\n ", "");

    /// <summary>The stored copy after Bob accepted (as a reply would record it).</summary>
    private static string Accepted(string ics) =>
        Unfolded(ics).Replace("ATTENDEE;CN=Bob;ROLE=REQ-PARTICIPANT;PARTSTAT=NEEDS-ACTION", "ATTENDEE;CN=Bob;ROLE=REQ-PARTICIPANT;PARTSTAT=ACCEPTED");

    [TestMethod]
    public void NewMeeting_WritesOrganizerAndGuests_ForClientScheduling()
    {
        var ics = Unfolded(Invite());
        StringAssert.Contains(ics, "ORGANIZER;CN=Simon:mailto:simon@example.test");
        StringAssert.Contains(ics, "ATTENDEE;CN=Bob;ROLE=REQ-PARTICIPANT;PARTSTAT=NEEDS-ACTION;RSVP=TRUE;SCHEDULE-AGENT=CLIENT:mailto:bob@example.org");
        StringAssert.Contains(ics.Replace("\r\n ", ""), "ATTENDEE;CN=\"Carol, Finance\";ROLE=OPT-PARTICIPANT");

        var ev = ICalendar.ParseEvents(ics, London).Single();
        Assert.AreEqual("simon@example.test", ev.Organizer?.Email);
        CollectionAssert.AreEqual(new[] { "bob@example.org", "carol@example.org" }, ev.Attendees.Select(a => a.Email).ToArray());
        Assert.AreEqual("Carol, Finance", ev.Attendees[1].Name);
        Assert.IsTrue(ev.Attendees[1].Optional);
        Assert.AreEqual(AttendeeStatus.NeedsAction, ev.Attendees[0].Status);
    }

    [TestMethod]
    public void NewMeeting_InvitesEveryGuestButMe()
    {
        var edit = Meeting("Planning", Bob, new EventAttendee("Alias@Example.test"));
        var messages = Scheduling.ForSave(null, ICalendarWriter.NewEvent("m1", edit, Timed(3, 9), null), Mine);

        var m = messages.Single();
        Assert.AreEqual(SchedulingKind.Invitation, m.Kind);
        Assert.AreEqual("REQUEST", m.Method);
        CollectionAssert.AreEqual(new[] { "bob@example.org" }, m.Recipients.Select(r => r.Email).ToArray());
        Assert.AreEqual("simon@example.test", m.Sender.Email);
        StringAssert.Contains(m.Ics, "METHOD:REQUEST");
        Assert.DoesNotContain("SCHEDULE-AGENT", m.Ics);
    }

    [TestMethod]
    public void Request_LeavesAlarmsOut()
    {
        var stored = Invite().Replace("END:VEVENT", "BEGIN:VALARM\r\nACTION:DISPLAY\r\nTRIGGER:-PT10M\r\nEND:VALARM\r\nEND:VEVENT");
        var m = Scheduling.ForSave(null, stored, Mine).Single();
        Assert.DoesNotContain("VALARM", m.Ics);
        Assert.HasCount(1, ICalendar.ParseEvents(m.Ics, London));
    }

    [TestMethod]
    public void Retitling_KeepsAnswers_AndUpdatesEveryone()
    {
        var before = Accepted(Invite());
        var after = ICalendarWriter.UpdateMaster(before, Meeting("Planning (agenda inside)", Bob, Carol), Timed(3, 9), null, false);

        StringAssert.Contains(after, "PARTSTAT=ACCEPTED");
        var m = Scheduling.ForSave(before, after, Mine).Single();
        Assert.AreEqual(SchedulingKind.Update, m.Kind);
        Assert.HasCount(2, m.Recipients);
        StringAssert.Contains(after, "SEQUENCE:1");
    }

    [TestMethod]
    public void Rescheduling_AsksEveryoneAgain()
    {
        var before = Accepted(Invite());
        var after = ICalendarWriter.UpdateMaster(before, Meeting("Planning", Bob, Carol), Timed(4, 9), null, false);
        Assert.DoesNotContain("PARTSTAT=ACCEPTED", after);
        Assert.AreEqual(SchedulingKind.Update, Scheduling.ForSave(before, after, Mine).Single().Kind);
    }

    [TestMethod]
    public void AddingAGuest_InvitesOnlyThem()
    {
        var before = Accepted(Invite());
        var dan = new EventAttendee("dan@example.org");
        var after = ICalendarWriter.UpdateMaster(before, Meeting("Planning", Bob, Carol, dan), Timed(3, 9), null, false);

        var m = Scheduling.ForSave(before, after, Mine).Single();
        Assert.AreEqual(SchedulingKind.Invitation, m.Kind);
        CollectionAssert.AreEqual(new[] { "dan@example.org" }, m.Recipients.Select(r => r.Email).ToArray());
        StringAssert.Contains(after, "PARTSTAT=ACCEPTED"); // Bob's answer stands
    }

    [TestMethod]
    public void RemovingAGuest_CancelsForThemOnly()
    {
        var before = Invite();
        var after = ICalendarWriter.UpdateMaster(before, Meeting("Planning", Bob), Timed(3, 9), null, false);
        Assert.DoesNotContain("carol@example.org", after);

        var m = Scheduling.ForSave(before, after, Mine).Single();
        Assert.AreEqual(SchedulingKind.Cancellation, m.Kind);
        CollectionAssert.AreEqual(new[] { "carol@example.org" }, m.Recipients.Select(r => r.Email).ToArray());
        StringAssert.Contains(m.Ics, "METHOD:CANCEL");
        StringAssert.Contains(m.Ics, "STATUS:CANCELLED");
        StringAssert.Contains(m.Ics, "SEQUENCE:1");
        Assert.DoesNotContain("bob@example.org", m.Ics);
    }

    [TestMethod]
    public void EmptyingTheGuestList_CancelsForEveryone_AndStopsBeingAMeeting()
    {
        var before = Invite();
        var after = ICalendarWriter.UpdateMaster(before, Meeting("Planning"), Timed(3, 9), null, false);
        Assert.DoesNotContain("ORGANIZER", after);
        Assert.DoesNotContain("ATTENDEE", after);

        var m = Scheduling.ForSave(before, after, Mine).Single();
        Assert.AreEqual(SchedulingKind.Cancellation, m.Kind);
        Assert.HasCount(2, m.Recipients);
    }

    [TestMethod]
    public void EditWithoutGuestList_KeepsTheServersAttendees()
    {
        var before = Invite();
        var edit = new EventEdit("Planning", null, null, false, default, default, EventRepeat.None);
        var after = ICalendarWriter.UpdateMaster(before, edit, Timed(3, 9), null, false);
        StringAssert.Contains(after, "mailto:bob@example.org");
        StringAssert.Contains(after, "ORGANIZER");
    }

    [TestMethod]
    public void SomeoneElsesMeeting_SendsNothing()
    {
        var theirs = Invite().Replace("mailto:simon@example.test", "mailto:boss@example.org");
        Assert.HasCount(0, Scheduling.ForSave(theirs, theirs, Mine));
        Assert.HasCount(0, Scheduling.ForDelete(theirs, null, false, Mine));
    }

    [TestMethod]
    public void DeletingOneOccurrence_CancelsThatOccurrence()
    {
        var edit = Meeting("Standup", Bob) with { Repeat = EventRepeat.Weekly };
        var series = ICalendarWriter.NewEvent("s1", edit, Timed(3, 9), "FREQ=WEEKLY");
        var occurrence = new DateTimeOffset(2026, 11, 10, 9, 0, 0, TimeSpan.Zero); // 09:00 GMT

        var m = Scheduling.ForDelete(series, occurrence, false, Mine).Single();
        StringAssert.Contains(m.Ics, "RECURRENCE-ID:20261110T090000Z");
        var ev = ICalendar.ParseEvents(m.Ics, London).Single();
        Assert.IsNull(ev.RRule);
        Assert.AreEqual(occurrence, ev.Start);
        Assert.AreEqual(occurrence.AddHours(1), ev.End);
        StringAssert.Contains(Scheduling.Describe(m, London).Text, "cancelled this occurrence");
    }

    [TestMethod]
    public void DeletingTheMeeting_CancelsForEveryone()
    {
        var m = Scheduling.ForDelete(Invite(), null, false, Mine).Single();
        Assert.AreEqual("CANCEL", m.Method);
        Assert.HasCount(2, m.Recipients);
        Assert.HasCount(2, ICalendar.ParseEvents(m.Ics, London).Single().Attendees);
    }

    [TestMethod]
    public void Answering_RecordsIt_AndRepliesWithOnlyMe()
    {
        var invited = """
            BEGIN:VCALENDAR
            VERSION:2.0
            PRODID:-//Other//EN
            BEGIN:VEVENT
            UID:their-meeting
            DTSTAMP:20261020T100000Z
            SEQUENCE:2
            DTSTART:20261103T140000Z
            DTEND:20261103T150000Z
            SUMMARY:Budget review
            ORGANIZER;CN=Boss:mailto:boss@example.org
            ATTENDEE;CN=Boss;PARTSTAT=ACCEPTED:mailto:boss@example.org
            ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:mailto:ALIAS@example.test
            ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:mailto:eve@example.org
            END:VEVENT
            END:VCALENDAR
            """.Replace("\n", "\r\n");

        var (updated, reply) = Scheduling.Answer(invited, Mine, AttendeeStatus.Tentative);

        var mine = ICalendar.ParseEvents(updated, London).Single().Attendees.Single(a => a.Email == "ALIAS@example.test");
        Assert.AreEqual(AttendeeStatus.Tentative, mine.Status);
        StringAssert.Contains(Unfolded(updated), "ORGANIZER;CN=Boss;SCHEDULE-AGENT=CLIENT:mailto:boss@example.org");

        Assert.AreEqual("REPLY", reply.Method);
        CollectionAssert.AreEqual(new[] { "boss@example.org" }, reply.Recipients.Select(r => r.Email).ToArray());
        Assert.AreEqual("ALIAS@example.test", reply.Sender.Email);
        StringAssert.Contains(reply.Ics, "METHOD:REPLY");
        StringAssert.Contains(reply.Ics, "SEQUENCE:2");
        Assert.DoesNotContain("eve@example.org", reply.Ics);
        Assert.DoesNotContain("SCHEDULE-AGENT", reply.Ics);
        var replied = ICalendar.ParseEvents(reply.Ics, London).Single();
        Assert.AreEqual(AttendeeStatus.Tentative, replied.Attendees.Single().Status);
        StringAssert.StartsWith(Scheduling.Describe(reply, London).Subject, "Tentative: Budget review");

        Assert.ThrowsExactly<InvalidOperationException>(() => Scheduling.Answer(Invite(), Mine, AttendeeStatus.Accepted));
    }

    [TestMethod]
    public void Describe_GivesWhenWhereAndGuests_InTheViewersZone()
    {
        var m = Scheduling.ForSave(null, Invite(), Mine).Single();
        var (subject, text) = Scheduling.Describe(m, London);
        Assert.AreEqual("Invitation: Planning @ Tue 3 Nov 2026, 09:00 – 10:00 (Europe/London)", subject);
        StringAssert.Contains(text, "Simon has invited you");
        StringAssert.Contains(text, "Where: Room 1");
        StringAssert.Contains(text, "Carol, Finance <carol@example.org> (optional)");
    }

    // ------------------------------------------------------------------ incoming

    private static readonly string[] Guest = ["bob@example.org"];

    [TestMethod]
    public void RoundTrip_InviteAnswerAndRecordTheReply()
    {
        var stored = Invite();
        var request = Scheduling.Read(Scheduling.ForSave(null, stored, Mine).Single().Ics, London)!;
        Assert.AreEqual("REQUEST", request.Method);
        Assert.AreEqual("m1", request.Uid);
        Assert.AreEqual("Planning", request.Summary);

        // Bob's side: the copy for his calendar has no METHOD; he accepts.
        var copy = Scheduling.ForCalendar(request);
        Assert.DoesNotContain("METHOD", copy);
        var (_, reply) = Scheduling.Answer(copy, Guest, AttendeeStatus.Accepted);

        // Back with the organiser.
        var incoming = Scheduling.Read(reply.Ics, London)!;
        Assert.AreEqual("REPLY", incoming.Method);
        var (updated, guest) = Scheduling.ApplyReply(stored, incoming, ["bob@example.org"], Mine);
        Assert.AreEqual(AttendeeStatus.Accepted, guest.Status);
        var bob = ICalendar.ParseEvents(updated, London).Single().Attendees.Single(a => a.Email == "bob@example.org");
        Assert.AreEqual(AttendeeStatus.Accepted, bob.Status);
        Assert.AreEqual(AttendeeStatus.NeedsAction,
            ICalendar.ParseEvents(updated, London).Single().Attendees.Single(a => a.Email == "carol@example.org").Status);
    }

    private const string BareReply = """
        BEGIN:VCALENDAR
        METHOD:REPLY
        PRODID:-//Other//EN
        VERSION:2.0
        BEGIN:VEVENT
        UID:m1
        DTSTAMP:20261027T090000Z
        SEQUENCE:0
        ORGANIZER:mailto:simon@example.test
        ATTENDEE;PARTSTAT=DECLINED:mailto:bob@example.org
        END:VEVENT
        END:VCALENDAR
        """;

    [TestMethod]
    public void Reply_WithoutTimes_IsStillRead()
    {
        var reply = Scheduling.Read(BareReply, London)!;
        Assert.IsNull(reply.Event);
        Assert.AreEqual(AttendeeStatus.Declined, reply.Attendees.Single().Status);
        var (updated, _) = Scheduling.ApplyReply(Invite(), reply, ["Bob@Example.org"], Mine);
        StringAssert.Contains(updated, "PARTSTAT=DECLINED");
    }

    [TestMethod]
    public void Reply_FromSomeoneElse_OrAboutAnotherMeeting_IsRefused()
    {
        var reply = Scheduling.Read(BareReply, London)!;
        var spoofed = Assert.ThrowsExactly<InvalidOperationException>(() => Scheduling.ApplyReply(Invite(), reply, ["mallory@example.net"], Mine));
        StringAssert.Contains(spoofed.Message, "bob@example.org");

        var theirs = Invite().Replace("mailto:simon@example.test", "mailto:boss@example.org");
        Assert.ThrowsExactly<InvalidOperationException>(() => Scheduling.ApplyReply(theirs, reply, ["bob@example.org"], Mine));

        var stranger = Scheduling.Read(BareReply.Replace("bob@example.org", "eve@example.org"), London)!;
        Assert.ThrowsExactly<InvalidOperationException>(() => Scheduling.ApplyReply(Invite(), stranger, ["eve@example.org"], Mine));
    }

    [TestMethod]
    public void Reply_ToTimesTheMeetingNoLongerHas_IsOutOfDate()
    {
        var original = Invite();
        var (_, reply) = Scheduling.Answer(Scheduling.ForCalendar(Scheduling.Read(Scheduling.ForSave(null, original, Mine).Single().Ics, London)!),
            Guest, AttendeeStatus.Accepted);
        var moved = ICalendarWriter.UpdateMaster(original, Meeting("Planning", Bob, Carol), Timed(5, 9), null, false);

        var ex = Assert.ThrowsExactly<InvalidOperationException>(() =>
            Scheduling.ApplyReply(moved, Scheduling.Read(reply.Ics, London)!, Guest, Mine));
        StringAssert.Contains(ex.Message, "earlier version");
    }

    [TestMethod]
    public void Cancellation_MustComeFromTheStoredOrganiser()
    {
        var cancel = Scheduling.Read(Scheduling.ForDelete(Invite(), null, false, Mine).Single().Ics, London)!;
        Assert.AreEqual("CANCEL", cancel.Method);
        Assert.IsFalse(cancel.ForOccurrence);
        var bobsCopy = Scheduling.ForCalendar(Scheduling.Read(Scheduling.ForSave(null, Invite(), Mine).Single().Ics, London)!);

        Assert.IsNull(Scheduling.WhyNotFromOrganizer(cancel, bobsCopy, ["Simon@example.test"]));
        StringAssert.Contains(Scheduling.WhyNotFromOrganizer(cancel, bobsCopy, ["mallory@example.net"])!, "wasn't sent by the organiser");
        var someoneElses = bobsCopy.Replace("mailto:simon@example.test", "mailto:boss@example.org");
        StringAssert.Contains(Scheduling.WhyNotFromOrganizer(cancel, someoneElses, ["simon@example.test"])!, "organised by");
    }

    [TestMethod]
    public void OccurrenceCancellation_SaysWhichOccurrence()
    {
        var series = ICalendarWriter.NewEvent("s1", Meeting("Standup", Bob) with { Repeat = EventRepeat.Weekly }, Timed(3, 9), "FREQ=WEEKLY");
        var occurrence = new DateTimeOffset(2026, 11, 10, 9, 0, 0, TimeSpan.Zero);
        var cancel = Scheduling.Read(Scheduling.ForDelete(series, occurrence, false, Mine).Single().Ics, London)!;
        Assert.IsTrue(cancel.ForOccurrence);
        Assert.AreEqual(occurrence, cancel.RecurrenceId);

        var after = ICalendarWriter.ExcludeOccurrence(series, cancel.RecurrenceId!.Value, false);
        var left = ICalendar.Expand(ICalendar.ParseEvents(after, London), occurrence.AddDays(-1), occurrence.AddDays(1));
        Assert.HasCount(0, left);
    }

    [TestMethod]
    public void PlainCalendarFile_IsNotAnInvitation()
    {
        Assert.IsNull(Scheduling.Read(Invite(), London));
        Assert.IsNull(Scheduling.Read(BareReply.Replace("METHOD:REPLY", "METHOD:PUBLISH"), London));
    }

    [TestMethod]
    public void InvitationEmail_IsFound_AndItsCalendarPartIsNotListedAsAFile()
    {
        var m = Scheduling.ForSave(null, Invite(), Mine).Single();
        var req = new SendRequest("simon@example.test", ["bob@example.org"], null, null, "Invitation", "Text", null, null,
            false, false, null, Attachments: [new OutgoingAttachment("invite.ics", "application/ics", Encoding.UTF8.GetBytes(m.Ics))],
            Calendar: new CalendarPart(m.Method, m.Ics));
        var parsed = MimeParser.Parse(Encoding.ASCII.GetBytes(MailService.BuildMimeMessage(req, "simon@example.test")));

        var found = MailService.FindScheduling(parsed);
        Assert.IsNotNull(found);
        Assert.AreEqual("m1", Scheduling.Read(found, London)?.Uid);
        Assert.HasCount(1, parsed.Attachments.Where(a => !a.IsInline)); // just the invite.ics attachment

        // An .ics attachment alone (some clients send only that) is found too.
        var attachedOnly = MimeParser.Parse(Encoding.ASCII.GetBytes(MailService.BuildMimeMessage(req with { Calendar = null }, "simon@example.test")));
        Assert.IsNotNull(MailService.FindScheduling(attachedOnly));
        Assert.IsNull(MailService.FindScheduling(MimeParser.Parse(Encoding.ASCII.GetBytes(
            MailService.BuildMimeMessage(req with { Calendar = null, Attachments = null }, "simon@example.test")))));
    }

    [TestMethod]
    public void InvitationEmail_CarriesTheCalendarAsAnAlternative()
    {
        var m = Scheduling.ForSave(null, Invite(), Mine).Single();
        var req = new SendRequest("simon@example.test", ["Bob <bob@example.org>"], null, null, "Invitation", "Text", null, null,
            false, false, null, Calendar: new CalendarPart(m.Method, m.Ics));

        var mime = MailService.BuildMimeMessage(req, "simon@example.test");
        StringAssert.Contains(mime, "multipart/alternative");
        StringAssert.Contains(mime, "Content-Type: text/calendar; method=REQUEST; charset=utf-8");

        var parsed = MimeParser.Parse(Encoding.ASCII.GetBytes(mime));
        Assert.AreEqual("Text", parsed.TextBody?.Trim());
    }
}
