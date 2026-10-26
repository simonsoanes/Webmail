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
    /// <exception cref="CalDavException">The server refused the change (read-only, conflict...).</exception>
    public async Task SaveEventAsync(CalendarEvent? existing, EventEdit edit, string calendarId, TimeZoneInfo zone)
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
            return;
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
            return;
        }

        // Moving to another calendar: create it there first, then remove the original.
        var newHref = new Uri(calendarUri, Uri.EscapeDataString(master.Uid) + ".ics");
        var copy = await SendResourceAsync(account, HttpMethod.Put, newHref, updated, "text/calendar; charset=utf-8",
            new() { ["If-None-Match"] = "*" });
        EnsureWriteSucceeded(copy.Status, "event");
        var delete = await SendResourceAsync(account, HttpMethod.Delete, href, null, null,
            etag != null ? new() { ["If-Match"] = etag } : []);
        if (delete.Status != HttpStatusCode.NotFound) EnsureWriteSucceeded(delete.Status, "event");
    }

    /// <summary>Delete an event; for a repeating event either just this occurrence or the whole series.</summary>
    public async Task DeleteEventAsync(CalendarEvent ev, bool onlyThisOccurrence)
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
            return;
        }

        var resp = await SendResourceAsync(account, HttpMethod.Delete, href, null, null,
            ev.ETag != null ? new() { ["If-Match"] = ev.ETag } : []);
        if (resp.Status != HttpStatusCode.NotFound) EnsureWriteSucceeded(resp.Status, "event");
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

    /// <summary>The account's event calendars, or null when no calendar server is configured.</summary>
    public async Task<IReadOnlyList<CalendarInfo>?> GetCalendarsAsync() =>
        await DiscoveredAsync() is { } d ? d.Found.Collections.Where(c => c.Supports("VEVENT")).Select(c => c.Info).ToList() : null;

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

    private Task<(string Raw, string? ETag)> FetchEventAsync(CalDavAccount account, Uri href) =>
        FetchObjectAsync(account, href, "event", "calendar");

    private static ICalendarWriter.EventTimes Times(EventEdit edit, TimeZoneInfo zone) =>
        new(edit.AllDay ? edit.StartLocal.Date : edit.StartLocal, edit.AllDay ? edit.EndLocal.Date : edit.EndLocal, edit.AllDay, zone);

    private static DateTime Local(DateTimeOffset t, TimeZoneInfo zone, bool allDay) =>
        allDay ? t.UtcDateTime.Date : TimeZoneInfo.ConvertTime(t, zone).DateTime;
}
