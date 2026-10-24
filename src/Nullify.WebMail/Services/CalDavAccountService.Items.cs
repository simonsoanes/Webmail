// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using System.Net;
using System.Security;
using System.Xml.Linq;
using Nullify.WebMail.Shared;

namespace Nullify.WebMail.Services;

/// <summary>
/// Notes (VJOURNAL) and tasks (VTODO), kept in the account's CalDAV collections that accept
/// them. Edits start from a fresh GET so properties this app doesn't show are kept, and the
/// write is conditional on the ETag the user opened, so a change made elsewhere since then is
/// reported rather than overwritten.
/// </summary>
public sealed partial class CalDavAccountService
{
    public const string NoteComponent = "VJOURNAL", TaskComponent = "VTODO";

    // ------------------------------------------------------------------ notes

    /// <summary>All notes, most recently changed first; null when no server is configured.</summary>
    /// <exception cref="CalDavException">Discovery failed (bad URL or credentials).</exception>
    public async Task<NoteList?> GetNotesAsync(TimeZoneInfo zone, bool refresh = false)
    {
        if (refresh) _discovered = null;
        if (await DiscoveredAsync() is not { } discovered) return null;
        var (account, found) = discovered;
        var lists = found.Collections.Where(c => c.Supports(NoteComponent)).ToList();

        var (notes, errors) = await QueryItemsAsync(account, lists, NoteComponent, (data, href, etag, list) =>
            ICalendar.ParseJournals(data, zone).Where(j => j.Status != "CANCELLED").Select(j =>
                new NoteItem(j.Uid, j.Summary, j.Description, j.Modified, list) { Href = href, ETag = etag, Categories = j.Categories }));

        return new NoteList(lists.Select(l => l.Info).ToList(),
            notes.OrderByDescending(n => n.Modified ?? DateTimeOffset.MinValue).ThenBy(n => n.Title, StringComparer.CurrentCultureIgnoreCase).ToList(),
            errors);
    }

    /// <summary>Create (when <paramref name="existing"/> is null) or update a note; returns its URL.</summary>
    /// <exception cref="CalDavException">The server refused the change (read-only, conflict...).</exception>
    public async Task<string> SaveNoteAsync(NoteItem? existing, NoteEdit edit, string collectionId)
    {
        var account = await ResolveAccountAsync() ?? throw new CalDavException("No calendar server is configured.");
        if (existing?.Href == null)
        {
            var uid = Guid.NewGuid().ToString();
            return await CreateItemAsync(account, collectionId, uid, ICalendarWriter.NewJournal(uid, edit), "note");
        }
        var href = new Uri(existing.Href);
        var (raw, etag) = await FetchObjectAsync(account, href, "note", "notes");
        return await WriteItemAsync(account, href, existing.ETag ?? etag, existing.CollectionId, collectionId,
            existing.Uid, ICalendarWriter.UpdateJournal(raw, edit), "note");
    }

    public Task DeleteNoteAsync(NoteItem note) => DeleteItemAsync(note.Href, note.ETag, "note");

    // ------------------------------------------------------------------ tasks

    /// <summary>All tasks (cancelled ones are left out); null when no server is configured.</summary>
    /// <exception cref="CalDavException">Discovery failed (bad URL or credentials).</exception>
    public async Task<TaskList?> GetTasksAsync(TimeZoneInfo zone, bool refresh = false)
    {
        if (refresh) _discovered = null;
        if (await DiscoveredAsync() is not { } discovered) return null;
        var (account, found) = discovered;
        var lists = found.Collections.Where(c => c.Supports(TaskComponent)).ToList();

        var (tasks, errors) = await QueryItemsAsync(account, lists, TaskComponent, (data, href, etag, list) =>
            ICalendar.ParseTodos(data, zone).Where(t => t.Status != "CANCELLED").Select(t =>
                new TaskItem(t.Uid, t.Summary.Length > 0 ? t.Summary : "(no title)", t.Description, t.Due, t.DueIsDate,
                    t.IsCompleted, ICalendar.PriorityOf(t.Priority), list)
                {
                    Href = href, ETag = etag, CompletedAt = t.Completed, Created = t.Created, IsRecurring = t.RRule != null,
                }));

        return new TaskList(lists.Select(l => l.Info).ToList(), tasks, errors);
    }

    /// <summary>Create (when <paramref name="existing"/> is null) or update a task; returns its URL.</summary>
    /// <exception cref="CalDavException">The server refused the change (read-only, conflict...).</exception>
    public async Task<string> SaveTaskAsync(TaskItem? existing, TaskEdit edit, string collectionId, TimeZoneInfo zone)
    {
        var account = await ResolveAccountAsync() ?? throw new CalDavException("No calendar server is configured.");
        if (existing?.Href == null)
        {
            var uid = Guid.NewGuid().ToString();
            return await CreateItemAsync(account, collectionId, uid, ICalendarWriter.NewTodo(uid, edit, zone), "task");
        }
        var href = new Uri(existing.Href);
        var (raw, etag) = await FetchObjectAsync(account, href, "task", "tasks");
        return await WriteItemAsync(account, href, existing.ETag ?? etag, existing.CollectionId, collectionId,
            existing.Uid, ICalendarWriter.UpdateTodo(raw, edit, zone), "task");
    }

    /// <summary>Tick or untick a task without touching anything else.</summary>
    public async Task SetTaskCompletedAsync(TaskItem task, bool completed)
    {
        var account = await ResolveAccountAsync() ?? throw new CalDavException("No calendar server is configured.");
        if (task.Href == null) throw new CalDavException("This task can't be changed (unknown location on the server).");
        var href = new Uri(task.Href);
        var (raw, etag) = await FetchObjectAsync(account, href, "task", "tasks");
        // The fresh ETag is enough here: only the completion properties change.
        var put = await SendResourceAsync(account, HttpMethod.Put, href, ICalendarWriter.SetTodoCompleted(raw, completed),
            "text/calendar; charset=utf-8", etag != null ? new() { ["If-Match"] = etag } : []);
        EnsureWriteSucceeded(put.Status, "task");
    }

    public Task DeleteTaskAsync(TaskItem task) => DeleteItemAsync(task.Href, task.ETag, "task");

    // ------------------------------------------------------------------ collections

    /// <summary>
    /// Make a new collection for notes or tasks (MKCALENDAR, RFC 4791 5.3.1) in the calendar
    /// home; returns its id. Many servers' default calendars don't accept notes, so this is
    /// how most people get a place to keep them.
    /// </summary>
    public async Task<string> CreateCollectionAsync(string name, string component)
    {
        if (component is not (NoteComponent or TaskComponent)) throw new ArgumentOutOfRangeException(nameof(component));
        if (await DiscoveredAsync() is not { } discovered) throw new CalDavException("No calendar server is configured.");
        var (account, found) = discovered;

        var home = found.Home.AbsoluteUri.EndsWith('/') ? found.Home : new Uri(found.Home.AbsoluteUri + "/");
        var url = new Uri(home, Guid.NewGuid().ToString("N") + "/");
        var body = $"""
            <?xml version="1.0" encoding="utf-8"?>
            <c:mkcalendar xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav">
              <d:set><d:prop>
                <d:displayname>{SecurityElement.Escape(name.Trim())}</d:displayname>
                <c:supported-calendar-component-set><c:comp name="{component}"/></c:supported-calendar-component-set>
              </d:prop></d:set>
            </c:mkcalendar>
            """;
        var resp = await SendResourceAsync(account, new HttpMethod("MKCALENDAR"), url, body, "application/xml; charset=utf-8", []);
        if (resp.Status is HttpStatusCode.Forbidden or HttpStatusCode.MethodNotAllowed or HttpStatusCode.NotImplemented)
            throw new CalDavException("The server doesn't allow new lists to be created here. Create one in your calendar server's own app.");
        EnsureWriteSucceeded(resp.Status, "list");
        _discovered = null;
        return url.AbsoluteUri;
    }

    // ------------------------------------------------------------------ shared

    /// <summary>
    /// Every <paramref name="component"/> in each collection. A collection that fails is
    /// reported in the errors rather than failing the rest.
    /// </summary>
    private async Task<(List<T> Items, List<string> Errors)> QueryItemsAsync<T>(CalDavAccount account,
        IReadOnlyList<CalCollection> collections, string component, Func<string, string?, string?, string, IEnumerable<T>> map)
    {
        var body = $"""
            <?xml version="1.0" encoding="utf-8"?>
            <c:calendar-query xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav">
              <d:prop><d:getetag/><c:calendar-data/></d:prop>
              <c:filter><c:comp-filter name="VCALENDAR"><c:comp-filter name="{component}"/></c:comp-filter></c:filter>
            </c:calendar-query>
            """;
        var results = await Task.WhenAll(collections.Select(async c =>
        {
            try
            {
                var (_, doc) = await SendAsync(account, "REPORT", c.Href, 1, body);
                var items = doc.Descendants(Dav + "response").SelectMany(r =>
                {
                    var data = r.Descendants(Cal + "calendar-data").FirstOrDefault()?.Value;
                    if (string.IsNullOrEmpty(data)) return [];
                    var href = r.Element(Dav + "href")?.Value.Trim();
                    var etag = r.Descendants(Dav + "getetag").FirstOrDefault()?.Value.Trim();
                    return map(data, string.IsNullOrEmpty(href) ? null : new Uri(c.Href, href).AbsoluteUri,
                        string.IsNullOrWhiteSpace(etag) ? null : etag, c.Info.Id);
                }).ToList();
                return (Items: items, Error: (string?)null);
            }
            catch (Exception ex) when (ex is CalDavException or HttpRequestException or TaskCanceledException or System.Xml.XmlException)
            {
                logger.LogInformation("CalDAV {Component} query {Collection} failed: {Msg}", component, c.Href, ex.Message);
                return (Items: new List<T>(), Error: (string?)$"{c.Info.Name}: {ex.Message}");
            }
        }));
        return (results.SelectMany(r => r.Items).ToList(), results.Where(r => r.Error != null).Select(r => r.Error!).ToList());
    }

    private async Task<string> CreateItemAsync(CalDavAccount account, string collectionId, string uid, string ics, string noun)
    {
        var href = new Uri(CollectionUri(collectionId), Uri.EscapeDataString(uid) + ".ics");
        var created = await SendResourceAsync(account, HttpMethod.Put, href, ics, "text/calendar; charset=utf-8",
            new() { ["If-None-Match"] = "*" });
        EnsureWriteSucceeded(created.Status, noun);
        return href.AbsoluteUri;
    }

    /// <summary>Write an updated item in place, or move it: create it in the new collection, then remove the original.</summary>
    private async Task<string> WriteItemAsync(CalDavAccount account, Uri href, string? etag,
        string fromCollection, string toCollection, string uid, string ics, string noun)
    {
        var ifMatch = etag != null ? new Dictionary<string, string> { ["If-Match"] = etag } : [];
        if (fromCollection == toCollection)
        {
            var put = await SendResourceAsync(account, HttpMethod.Put, href, ics, "text/calendar; charset=utf-8", ifMatch);
            EnsureWriteSucceeded(put.Status, noun);
            return href.AbsoluteUri;
        }
        var created = await CreateItemAsync(account, toCollection, uid, ics, noun);
        var delete = await SendResourceAsync(account, HttpMethod.Delete, href, null, null, ifMatch);
        if (delete.Status != HttpStatusCode.NotFound) EnsureWriteSucceeded(delete.Status, noun);
        return created;
    }

    private async Task DeleteItemAsync(string? href, string? etag, string noun)
    {
        var account = await ResolveAccountAsync() ?? throw new CalDavException("No calendar server is configured.");
        if (href == null) throw new CalDavException($"This {noun} can't be deleted (unknown location on the server).");
        var resp = await SendResourceAsync(account, HttpMethod.Delete, new Uri(href), null, null,
            etag != null ? new() { ["If-Match"] = etag } : []);
        if (resp.Status != HttpStatusCode.NotFound) EnsureWriteSucceeded(resp.Status, noun);
    }

    private async Task<(string Raw, string? ETag)> FetchObjectAsync(CalDavAccount account, Uri href, string noun, string view)
    {
        var get = await SendResourceAsync(account, HttpMethod.Get, href, null, null, []);
        if (get.Status == HttpStatusCode.NotFound)
            throw new CalDavException($"This {noun} no longer exists on the server. Refresh the {view}.");
        if (get.Status != HttpStatusCode.OK || string.IsNullOrEmpty(get.Body))
            throw new CalDavException($"Couldn't read the {noun} from the server (HTTP {(int)get.Status}).");
        return (get.Body, get.ETag);
    }

    private static Uri CollectionUri(string id) => new(id.EndsWith('/') ? id : id + "/");
}
