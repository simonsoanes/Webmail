// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using System.Net;
using Nullify.WebMail.Shared;

namespace Nullify.WebMail.Services;

/// <summary>
/// Creating, editing and deleting events. Edits always start from a fresh GET of the .ics so
/// the series master (with its RRULE) is what gets changed, and writes are conditional on the
/// ETag so a change made elsewhere is never silently overwritten.
/// </summary>
public sealed partial class CalDavAccountService
{
    /// <summary>
    /// Create (when <paramref name="existing"/> is null) or update an event. For an occurrence
    /// of a repeating event the change applies to the whole series: a moved occurrence moves
    /// every occurrence by the same amount.
    /// </summary>
    /// <returns>The .ics before (null when new) and as written, to work out what to tell guests.</returns>
    /// <exception cref="CalDavException">The server refused the change (read-only, conflict...).</exception>
    public async Task<(string? Before, string After)> SaveEventAsync(CalendarEvent? existing, EventEdit edit, string calendarId, TimeZoneInfo zone)
    {
        var account = await ResolveAccountAsync() ?? throw new CalDavException("No calendar server is configured.");
        var calendarUri = new Uri(calendarId.EndsWith('/') ? calendarId : calendarId + "/");

        if (existing?.Href == null)
        {
            var uid = Guid.NewGuid().ToString();
            var ics = ICalendarWriter.NewEvent(uid, edit, Times(edit, zone), ICalendarWriter.RuleFor(edit.Repeat));
            var created = await SendResourceAsync(account, HttpMethod.Put, new Uri(calendarUri, uid + ".ics"), ics,
                "text/calendar; charset=utf-8", new() { ["If-None-Match"] = "*" });
            EnsureWriteSucceeded(created.Status, "event");
            return (null, ics);
        }

        var href = new Uri(existing.Href);
        var (raw, etag) = await FetchEventAsync(account, href);
        var master = ICalendar.ParseEvents(raw, zone).FirstOrDefault(e => e.RecurrenceIdWall == null)
            ?? throw new CalDavException("This event can't be edited here (it has no main component).");

        var times = Times(edit, zone);
        string? rrule;
        var dropExceptions = false;
        if (master.RRule != null && edit.Repeat != EventRepeat.None)
        {
            // Editing one occurrence of a series: shift the series start by however far this
            // occurrence moved, and keep the original rule unless the repeat choice changed.
            var occurrence = Local(existing.OccurrenceId ?? existing.Start, zone, existing.AllDay);
            var shift = (edit.AllDay ? edit.StartLocal.Date : edit.StartLocal) - occurrence;
            var masterStart = Local(master.Start, zone, master.AllDay && edit.AllDay);
            var length = times.EndLocal - times.StartLocal;
            times = times with { StartLocal = masterStart + shift, EndLocal = masterStart + shift + length };
            var sameRepeat = ICalendarWriter.RepeatOf(master.RRule) == edit.Repeat;
            rrule = sameRepeat ? master.RRule : ICalendarWriter.RuleFor(edit.Repeat);
            dropExceptions = shift != TimeSpan.Zero || !sameRepeat || master.AllDay != edit.AllDay;
        }
        else
        {
            rrule = ICalendarWriter.RuleFor(edit.Repeat);
            dropExceptions = master.RRule != null; // stopped repeating
        }

        var updated = ICalendarWriter.UpdateMaster(raw, edit, times, rrule, dropExceptions);
        var targetCalendar = existing.CalendarId ?? calendarId;
        if (targetCalendar == calendarId)
        {
            var put = await SendResourceAsync(account, HttpMethod.Put, href, updated, "text/calendar; charset=utf-8",
                etag != null ? new() { ["If-Match"] = etag } : []);
            EnsureWriteSucceeded(put.Status, "event");
            return (raw, updated);
        }

        // Moving to another calendar: create it there first, then remove the original.
        var newHref = new Uri(calendarUri, Uri.EscapeDataString(master.Uid) + ".ics");
        var copy = await SendResourceAsync(account, HttpMethod.Put, newHref, updated, "text/calendar; charset=utf-8",
            new() { ["If-None-Match"] = "*" });
        EnsureWriteSucceeded(copy.Status, "event");
        var delete = await SendResourceAsync(account, HttpMethod.Delete, href, null, null,
            etag != null ? new() { ["If-Match"] = etag } : []);
        if (delete.Status != HttpStatusCode.NotFound) EnsureWriteSucceeded(delete.Status, "event");
        return (raw, updated);
    }

    /// <summary>Delete an event; for a repeating event either just this occurrence or the whole series.</summary>
    /// <returns>The .ics as it was, to work out who to tell; null when it was already gone.</returns>
    public async Task<string?> DeleteEventAsync(CalendarEvent ev, bool onlyThisOccurrence)
    {
        var account = await ResolveAccountAsync() ?? throw new CalDavException("No calendar server is configured.");
        if (ev.Href == null) throw new CalDavException("This event can't be deleted (unknown location on the server).");
        var href = new Uri(ev.Href);

        if (onlyThisOccurrence && ev.IsRecurring)
        {
            var (raw, etag) = await FetchEventAsync(account, href);
            var updated = ICalendarWriter.ExcludeOccurrence(raw, ev.OccurrenceId ?? ev.Start, ev.AllDay);
            var put = await SendResourceAsync(account, HttpMethod.Put, href, updated, "text/calendar; charset=utf-8",
                etag != null ? new() { ["If-Match"] = etag } : []);
            EnsureWriteSucceeded(put.Status, "event");
            return raw;
        }

        // Read it first only for a meeting: the guests are told from what it held.
        string? before = null;
        if (ev.Organizer != null)
            try { (before, _) = await FetchEventAsync(account, href); }
            catch (CalDavException) { /* deleted elsewhere; the DELETE says so */ }
        var resp = await SendResourceAsync(account, HttpMethod.Delete, href, null, null,
            ev.ETag != null ? new() { ["If-Match"] = ev.ETag } : []);
        if (resp.Status == HttpStatusCode.NotFound) return null;
        EnsureWriteSucceeded(resp.Status, "event");
        return before;
    }

    /// <summary>
    /// Answer an invitation in the user's calendar: store their answer and return the reply
    /// to email the organiser.
    /// </summary>
    /// <exception cref="InvalidOperationException">The user isn't a guest of this meeting.</exception>
    public async Task<SchedulingMessage> AnswerAsync(CalendarEvent ev, IReadOnlyCollection<string> mine, AttendeeStatus answer)
    {
        var account = await ResolveAccountAsync() ?? throw new CalDavException("No calendar server is configured.");
        if (ev.Href == null) throw new CalDavException("This event can't be changed (unknown location on the server).");
        var href = new Uri(ev.Href);
        var (raw, etag) = await FetchEventAsync(account, href);
        var (updated, reply) = Scheduling.Answer(raw, mine, answer);
        var put = await SendResourceAsync(account, HttpMethod.Put, href, updated, "text/calendar; charset=utf-8",
            etag != null ? new() { ["If-Match"] = etag } : []);
        EnsureWriteSucceeded(put.Status, "event");
        return reply;
    }

    /// <summary>The repeat setting of the series an event belongs to (for the editor).</summary>
    public async Task<EventRepeat> GetRepeatAsync(CalendarEvent ev)
    {
        if (!ev.IsRecurring || ev.Href == null) return EventRepeat.None;
        var account = await ResolveAccountAsync() ?? throw new CalDavException("No calendar server is configured.");
        var (raw, _) = await FetchEventAsync(account, new Uri(ev.Href));
        var master = ICalendar.ParseEvents(raw, TimeZoneInfo.Utc).FirstOrDefault(e => e.RecurrenceIdWall == null);
        return ICalendarWriter.RepeatOf(master?.RRule);
    }

    /// <summary>The calendars events can be added to, or null when no calendar server is configured.</summary>
    public async Task<IReadOnlyList<CalendarInfo>?> GetCalendarsAsync() =>
        await DiscoveredAsync() is { } d ? d.Found.EventCalendars.Where(c => !c.Info.ReadOnly).Select(c => c.Info).ToList() : null;

    /// <summary>
    /// Copy the events in an .ics file into a calendar, one resource per UID. Events the
    /// calendar already holds are left as they are and counted in <c>Existing</c>.
    /// </summary>
    /// <exception cref="CalDavException">The server refused an event; earlier ones stay imported.</exception>
    public async Task<(int Added, int Existing)> ImportEventsAsync(string ics, string calendarId)
    {
        var account = await ResolveAccountAsync() ?? throw new CalDavException("No calendar server is configured.");
        var calendarUri = new Uri(calendarId.EndsWith('/') ? calendarId : calendarId + "/");
        int added = 0, existing = 0;
        foreach (var (uid, body) in ICalendar.SplitForImport(ics))
        {
            var put = await SendResourceAsync(account, HttpMethod.Put, new Uri(calendarUri, Uri.EscapeDataString(uid) + ".ics"),
                body, "text/calendar; charset=utf-8", new() { ["If-None-Match"] = "*" });
            if (put.Status == HttpStatusCode.PreconditionFailed) { existing++; continue; }
            EnsureWriteSucceeded(put.Status, "event");
            added++;
        }
        return (added, existing);
    }

    // ------------------------------------------------------------------ invitations by email

    /// <summary>An event resource as stored, found by UID.</summary>
    public sealed record StoredEvent(string CalendarId, string Href, string Raw, string? ETag);

    /// <summary>The event with this UID in any of the user's calendars, or null.</summary>
    public async Task<StoredEvent?> FindEventAsync(string uid)
    {
        if (await DiscoveredAsync() is not { } d) return null;
        var body = $"""
            <?xml version="1.0" encoding="utf-8"?>
            <c:calendar-query xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav">
              <d:prop><d:getetag/><c:calendar-data/></d:prop>
              <c:filter><c:comp-filter name="VCALENDAR"><c:comp-filter name="VEVENT">
                <c:prop-filter name="UID"><c:text-match collation="i;octet">{System.Security.SecurityElement.Escape(uid)}</c:text-match></c:prop-filter>
              </c:comp-filter></c:comp-filter></c:filter>
            </c:calendar-query>
            """;
        foreach (var c in d.Found.EventCalendars)
        {
            System.Xml.Linq.XDocument doc;
            try { (_, doc) = await SendAsync(d.Account, "REPORT", c.Href, 1, body); }
            catch (CalDavException ex)
            {
                logger.LogInformation("CalDAV UID search in {Calendar} failed: {Msg}", c.Href, ex.Message);
                continue;
            }
            foreach (var r in doc.Descendants(Dav + "response"))
            {
                var data = r.Descendants(Cal + "calendar-data").FirstOrDefault()?.Value;
                var href = r.Element(Dav + "href")?.Value.Trim();
                // text-match is a substring match: check the UID itself.
                if (string.IsNullOrEmpty(data) || string.IsNullOrEmpty(href) ||
                    !ICalendar.ParseEvents(data, TimeZoneInfo.Utc).Any(e => e.Uid == uid)) continue;
                var etag = r.Descendants(Dav + "getetag").FirstOrDefault()?.Value.Trim();
                return new StoredEvent(c.Info.Id, new Uri(c.Href, href).AbsoluteUri, data, string.IsNullOrWhiteSpace(etag) ? null : etag);
            }
        }
        return null;
    }

    /// <summary>
    /// Answer an emailed invitation: store it (in <paramref name="calendarId"/> when it's new, or
    /// over the copy already in the calendar unless that copy is newer) with the user's answer,
    /// and return the reply for the organiser. Declining a new invitation stores nothing.
    /// </summary>
    /// <param name="from">The email's From and Sender addresses.</param>
    /// <exception cref="InvalidOperationException">The user isn't a guest, or it can't replace the stored copy.</exception>
    public async Task<SchedulingMessage> AnswerInvitationAsync(IncomingScheduling invitation, string calendarId,
        IReadOnlyCollection<string> mine, AttendeeStatus answer, IReadOnlyCollection<string> from)
    {
        var account = await ResolveAccountAsync() ?? throw new CalDavException("No calendar server is configured.");
        var stored = await FindEventAsync(invitation.Uid);
        var content = Scheduling.ForCalendar(invitation);
        if (stored != null)
        {
            if (Scheduling.SequenceOf(stored.Raw) > invitation.Sequence) content = stored.Raw; // answer the newer copy
            else if (Scheduling.WhyNotFromOrganizer(invitation, stored.Raw, from) is { } why)
                throw new InvalidOperationException("It can't replace the event in your calendar. " + why);
        }
        var (updated, reply) = Scheduling.Answer(content, mine, answer);
        if (stored == null && answer == AttendeeStatus.Declined) return reply;

        var put = stored != null
            ? await SendResourceAsync(account, HttpMethod.Put, new Uri(stored.Href), updated, "text/calendar; charset=utf-8",
                stored.ETag != null ? new() { ["If-Match"] = stored.ETag } : [])
            : await SendResourceAsync(account, HttpMethod.Put,
                new Uri(new Uri(calendarId.EndsWith('/') ? calendarId : calendarId + "/"), Uri.EscapeDataString(invitation.Uid) + ".ics"),
                updated, "text/calendar; charset=utf-8", new() { ["If-None-Match"] = "*" });
        EnsureWriteSucceeded(put.Status, "event");
        return reply;
    }

    /// <summary>Apply an organiser's cancellation: delete the event, or skip the cancelled occurrence.</summary>
    /// <exception cref="InvalidOperationException">It isn't in the calendar, or didn't come from its organiser.</exception>
    public async Task ApplyCancellationAsync(IncomingScheduling cancel, IReadOnlyCollection<string> from)
    {
        var account = await ResolveAccountAsync() ?? throw new CalDavException("No calendar server is configured.");
        var stored = await FindEventAsync(cancel.Uid) ?? throw new InvalidOperationException("This event isn't in your calendar.");
        if (Scheduling.WhyNotFromOrganizer(cancel, stored.Raw, from) is { } why) throw new InvalidOperationException(why);
        var match = stored.ETag != null ? new Dictionary<string, string> { ["If-Match"] = stored.ETag } : [];
        if (cancel.RecurrenceId is { } occurrence)
        {
            var allDay = cancel.Event?.AllDay ?? false;
            var updated = ICalendarWriter.ExcludeOccurrence(stored.Raw, occurrence, allDay);
            var put = await SendResourceAsync(account, HttpMethod.Put, new Uri(stored.Href), updated, "text/calendar; charset=utf-8", match);
            EnsureWriteSucceeded(put.Status, "event");
            return;
        }
        var delete = await SendResourceAsync(account, HttpMethod.Delete, new Uri(stored.Href), null, null, match);
        if (delete.Status != HttpStatusCode.NotFound) EnsureWriteSucceeded(delete.Status, "event");
    }

    /// <summary>Record a guest's emailed answer in a meeting the user organises. Returns the guest as they answered.</summary>
    /// <exception cref="InvalidOperationException">The reply can't be applied; the message says why.</exception>
    public async Task<EventAttendee> ApplyReplyAsync(IncomingScheduling reply, IReadOnlyCollection<string> from, IReadOnlyCollection<string> mine)
    {
        var account = await ResolveAccountAsync() ?? throw new CalDavException("No calendar server is configured.");
        var stored = await FindEventAsync(reply.Uid) ?? throw new InvalidOperationException("This meeting isn't in your calendar any more.");
        var (updated, guest) = Scheduling.ApplyReply(stored.Raw, reply, from, mine);
        var put = await SendResourceAsync(account, HttpMethod.Put, new Uri(stored.Href), updated, "text/calendar; charset=utf-8",
            stored.ETag != null ? new() { ["If-Match"] = stored.ETag } : []);
        EnsureWriteSucceeded(put.Status, "event");
        return guest;
    }

    private Task<(string Raw, string? ETag)> FetchEventAsync(CalDavAccount account, Uri href) =>
        FetchObjectAsync(account, href, "event", "calendar");

    private static ICalendarWriter.EventTimes Times(EventEdit edit, TimeZoneInfo zone) =>
        new(edit.AllDay ? edit.StartLocal.Date : edit.StartLocal, edit.AllDay ? edit.EndLocal.Date : edit.EndLocal, edit.AllDay, zone);

    private static DateTime Local(DateTimeOffset t, TimeZoneInfo zone, bool allDay) =>
        allDay ? t.UtcDateTime.Date : TimeZoneInfo.ConvertTime(t, zone).DateTime;
}
