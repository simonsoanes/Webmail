// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using System.Net;
using System.Text.Json;
using Nullify.WebMail.Shared;

namespace Nullify.WebMail.Services;

/// <summary>
/// A calendar the user added by its address: a published internet calendar (an .ics feed, often
/// a webcal:// link), or a CalDAV calendar on their own server that isn't in their calendar home
/// (someone's public calendar).
/// </summary>
/// <param name="CalDav">A CalDAV collection on the user's server, read with their credentials; otherwise an .ics feed.</param>
public sealed record CalendarSubscription(string Url, string Name, string? Color, bool CalDav, bool ReadOnly = true)
{
    /// <summary>A CalDAV calendar is known by its URL, as calendars in the home are, so events save to it.</summary>
    public string Id => CalDav ? Url : FeedPrefix + Url;

    public const string FeedPrefix = "feed:";

    public CalendarInfo ToInfo() => new(Id, Name, Color) { Kind = CalendarKind.Subscribed, ReadOnly = ReadOnly || !CalDav };
}

public sealed partial class CalDavAccountService
{
    private const string SubscriptionsKey = "calendar.subscriptions";
    private static readonly TimeSpan FeedLifetime = TimeSpan.FromMinutes(15);

    // Feeds are fetched at most every FeedLifetime per circuit (Refresh fetches them again).
    private readonly Dictionary<string, (DateTime At, string Body)> _feeds = new();

    public async Task<IReadOnlyList<CalendarSubscription>> GetSubscriptionsAsync()
    {
        var json = (await api.GetPreferencesAsync()).FirstOrDefault(p => p.Key == SubscriptionsKey)?.Value;
        if (string.IsNullOrEmpty(json)) return [];
        try { return JsonSerializer.Deserialize<List<CalendarSubscription>>(json) ?? []; }
        catch (JsonException) { return []; }
    }

    private Task SaveSubscriptionsAsync(IEnumerable<CalendarSubscription> list) =>
        api.SetPreferenceAsync(SubscriptionsKey, list.Any() ? JsonSerializer.Serialize(list.ToList()) : null);

    /// <summary>
    /// Add a calendar by its address. On the user's own CalDAV server a calendar collection is
    /// read over CalDAV (with their credentials); anything else must be an iCalendar feed.
    /// </summary>
    /// <param name="name">What to call it; blank uses the name the calendar gives itself.</param>
    /// <exception cref="CalDavException">It can't be added; the message says why.</exception>
    public async Task<CalendarSubscription> SubscribeAsync(string address, string? name)
    {
        var url = FeedUrl(address);
        var existing = await GetSubscriptionsAsync();
        if (existing.Any(s => s.Url == url.AbsoluteUri))
            throw new CalDavException("That calendar is already in your list.");

        CalDavAccount? account = null;
        try { account = await ResolveAccountAsync(); }
        catch (InvalidOperationException) { /* the saved password needs re-entering; feeds still work */ }

        CalendarSubscription? added = null;
        if (account != null && OnServer(url, account))
        {
            var found = await DiscoveredAsync();
            if (found is { } d && d.Found.Collections.Concat(d.Found.Delegated).Any(c => SamePath(c.Href, url)))
                throw new CalDavException("That calendar is already in your list.");
            try
            {
                var (at, doc) = await PropfindAsync(account, url, 0, ListProps);
                var self = doc.Descendants(Dav + "response").FirstOrDefault();
                if (self != null && IsCalendar(self))
                {
                    var c = ToCalendar(self, at);
                    if (!c.Supports("VEVENT")) throw new CalDavException("That calendar holds no events (only tasks or notes).");
                    added = new CalendarSubscription(c.Href.AbsoluteUri, Clean(name) ?? c.Info.Name, c.Info.Color, CalDav: true, c.Info.ReadOnly);
                }
            }
            catch (CalDavException ex) when (ex.Message.StartsWith("The server doesn't look like CalDAV", StringComparison.Ordinal)
                                              || ex.Message.StartsWith("Nothing was found", StringComparison.Ordinal))
            {
                // Not a collection: perhaps a published .ics on the same server.
            }
        }

        if (added == null)
        {
            var body = await FetchFeedAsync(url, account, cached: false);
            var (feedName, color) = ICalendar.CalendarProperties(body);
            added = new CalendarSubscription(url.AbsoluteUri, Clean(name) ?? feedName ?? url.Host, color, CalDav: false);
        }

        await SaveSubscriptionsAsync([.. existing, added]);
        return added;
    }

    public async Task UnsubscribeAsync(string calendarId)
    {
        var list = await GetSubscriptionsAsync();
        _feeds.Clear();
        await SaveSubscriptionsAsync(list.Where(s => s.Id != calendarId));
    }

    /// <summary>Events of one subscription in [from, to).</summary>
    private async Task<IReadOnlyList<CalendarEvent>> SubscriptionEventsAsync(
        CalendarSubscription sub, CalDavAccount? account, DateTimeOffset from, DateTimeOffset to, TimeZoneInfo viewerZone)
    {
        if (sub.CalDav)
        {
            if (account == null) throw new CalDavException("No calendar server is configured.");
            return await QueryAsync(account, new Uri(sub.Url), sub.Id, from, to, viewerZone);
        }
        var body = await FetchFeedAsync(new Uri(sub.Url), account, cached: true);
        return ICalendar.Expand(ICalendar.ParseEvents(body, viewerZone), from, to)
            .Select(e => new CalendarEvent(e.Uid, e.Summary.Length > 0 ? e.Summary : "(no title)",
                e.Start, e.End, e.Location, e.Description, e.AllDay, sub.Id)
            {
                IsRecurring = e.IsRecurring,
                OccurrenceId = e.OccurrenceId,
                Organizer = e.Organizer,
                Attendees = e.Attendees,
                Reminders = ReminderMinutes(e.Alarms),
            }).ToList();
    }

    /// <summary>
    /// GET an iCalendar feed. Credentials are only ever sent to the user's own CalDAV server,
    /// and only that server may be on a private network.
    /// </summary>
    private async Task<string> FetchFeedAsync(Uri url, CalDavAccount? account, bool cached)
    {
        if (cached && _feeds.TryGetValue(url.AbsoluteUri, out var hit) && DateTime.UtcNow - hit.At < FeedLifetime) return hit.Body;

        var http = httpFactory.CreateClient(PublicNetwork.HttpClientName);
        using var req = new HttpRequestMessage(HttpMethod.Get, url);
        req.Headers.Accept.ParseAdd("text/calendar");
        req.Headers.Accept.ParseAdd("*/*;q=0.5");
        if (account != null && OnServer(url, account))
        {
            req.Options.Set(PublicNetwork.AllowedHost, url.Host);
            req.Headers.Authorization = BasicAuth(account);
        }

        string body;
        try
        {
            using var resp = await http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead);
            switch (resp.StatusCode)
            {
                case HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden:
                    throw new CalDavException("That calendar isn't public: the server asked for a password.");
                case HttpStatusCode.NotFound or HttpStatusCode.Gone:
                    throw new CalDavException("Nothing was found at that address — check the link.");
                case var s when (int)s >= 400:
                    throw new CalDavException($"The calendar couldn't be downloaded (HTTP {(int)s} {resp.ReasonPhrase}).");
            }
            if (resp.Content.Headers.ContentLength > PublicNetwork.MaxResponseBytes)
                throw new CalDavException("That calendar is too large to show.");
            await using var stream = await resp.Content.ReadAsStreamAsync();
            using var limited = new MemoryStream();
            var buffer = new byte[81920];
            int read;
            while ((read = await stream.ReadAsync(buffer)) > 0)
            {
                if (limited.Length + read > PublicNetwork.MaxResponseBytes) throw new CalDavException("That calendar is too large to show.");
                limited.Write(buffer, 0, read);
            }
            body = System.Text.Encoding.UTF8.GetString(limited.GetBuffer(), 0, (int)limited.Length);
        }
        catch (Exception ex) when (ex is HttpRequestException or IOException && PublicNetwork.Blocked(ex) is { } blocked)
        {
            throw new CalDavException(blocked.Message);
        }
        catch (HttpRequestException ex)
        {
            throw new CalDavException($"Could not reach {url.Host}: {ex.InnerException?.Message ?? ex.Message}");
        }
        catch (TaskCanceledException)
        {
            throw new CalDavException($"{url.Host} did not respond in time.");
        }

        if (!body.Contains("BEGIN:VCALENDAR", StringComparison.OrdinalIgnoreCase))
            throw new CalDavException("That address isn't a calendar: it didn't return iCalendar (.ics) data.");
        _feeds[url.AbsoluteUri] = (DateTime.UtcNow, body);
        return body;
    }

    /// <summary>webcal:// and webcals:// are https:// (RFC-less but universal); bare host names get https://.</summary>
    /// <exception cref="CalDavException">Not a web address.</exception>
    public static Uri FeedUrl(string address)
    {
        var text = address.Trim();
        if (text.StartsWith("webcals://", StringComparison.OrdinalIgnoreCase)) text = "https://" + text[10..];
        else if (text.StartsWith("webcal://", StringComparison.OrdinalIgnoreCase)) text = "https://" + text[9..];
        else if (!text.Contains("://")) text = "https://" + text;
        if (!Uri.TryCreate(text, UriKind.Absolute, out var uri) || uri.Scheme is not ("http" or "https") || string.IsNullOrEmpty(uri.Host))
            throw new CalDavException("Enter a calendar's web address (https:// or webcal://).");
        if (!string.IsNullOrEmpty(uri.UserInfo))
            throw new CalDavException("Leave the user name and password out of the address.");
        return uri;
    }

    private static bool OnServer(Uri url, CalDavAccount account) =>
        url.Host.Equals(account.Url.Host, StringComparison.OrdinalIgnoreCase) && url.Port == account.Url.Port;

    private static string? Clean(string? name) => string.IsNullOrWhiteSpace(name) ? null : name.Trim();
}
