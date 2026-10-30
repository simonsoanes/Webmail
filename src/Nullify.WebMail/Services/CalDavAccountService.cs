// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Xml.Linq;
using Microsoft.EntityFrameworkCore;
using Nullify.WebMail.Data;
using Nullify.WebMail.Shared;

namespace Nullify.WebMail.Services;

/// <summary>The CalDAV account to use, after defaults and the password source are applied.</summary>
public sealed record CalDavAccount(Uri Url, string Username, string Password);

/// <summary>A CalDAV failure with a message fit to show the user.</summary>
public sealed class CalDavException(string message) : Exception(message);

/// <summary>How a server lets its users share calendars with each other over CalDAV.</summary>
public enum SharingProtocol { None, ResourceSharing, CalendarServer }

/// <summary>
/// A calendar collection, the components (VEVENT, VTODO, VJOURNAL) it accepts, its owner's
/// principal (when the server says) and how it can be shared.
/// </summary>
internal sealed record CalCollection(Uri Href, CalendarInfo Info, IReadOnlySet<string> Components,
    Uri? Owner = null, SharingProtocol Sharing = SharingProtocol.None)
{
    /// <summary>A collection that doesn't advertise a component set accepts any (RFC 4791 5.2.3).</summary>
    public bool Supports(string component) => Components.Count == 0 || Components.Contains(component);
}

/// <summary>
/// Per-user CalDAV settings. URL and username fall back to the domain/server default and the
/// mail login; the password is the mail password unless the user saved a separate one, which
/// is sealed with <see cref="SecretBox"/> under a key derived from the current mail password.
/// </summary>
public sealed partial class CalDavAccountService(
    ApiService api,
    UserSession session,
    SettingsService settings,
    IDbContextFactory<AppDbContext> dbFactory,
    IHttpClientFactory httpFactory,
    ILogger<CalDavAccountService> logger)
{
    public const string HttpClientName = "caldav";
    private const string UrlKey = "caldav.url", UserKey = "caldav.username", SecretKey = "caldav.password";

    private static readonly XNamespace Dav = "DAV:";
    private static readonly XNamespace Cal = "urn:ietf:params:xml:ns:caldav";
    private static readonly XNamespace Apple = "http://apple.com/ns/ical/";
    private static readonly XNamespace CS = "http://calendarserver.org/ns/";

    // Discovery is a few round-trips; reuse it for the life of the circuit unless settings change.
    private (string Key, Discovery Found)? _discovered;

    /// <summary>
    /// The calendar home (where new collections are made), every collection in it (the user's
    /// own and those shared with them), the calendars of people who made the user their
    /// delegate, and how the server lets calendars be shared.
    /// </summary>
    private sealed record Discovery(Uri Home, IReadOnlyList<CalCollection> Collections,
        IReadOnlyList<CalCollection> Delegated, SharingProtocol Sharing)
    {
        public IEnumerable<CalCollection> EventCalendars => Collections.Where(c => c.Supports("VEVENT"));
    }

    private CredentialInfo Cred =>
        session.Credential ?? throw new InvalidOperationException("Not authenticated.");

    private string SealContext => "nullify.caldav.v1|" + Cred.Login.ToLowerInvariant();

    public async Task<CalDavSettingsDto> GetSettingsAsync()
    {
        var prefs = await LoadPrefsAsync();
        return new CalDavSettingsDto(
            prefs.GetValueOrDefault(UrlKey), prefs.GetValueOrDefault(UserKey),
            PasswordSource(prefs.GetValueOrDefault(SecretKey)),
            await DefaultUrlAsync(), Cred.Login);
    }

    /// <summary>
    /// Save settings. <paramref name="newPassword"/>: null/empty keeps a working saved password
    /// (or uses the mail password when there is none); a value replaces it.
    /// <paramref name="useMailPassword"/> discards any saved password.
    /// </summary>
    public async Task SaveAsync(string? url, string? username, string? newPassword, bool useMailPassword)
    {
        url = string.IsNullOrWhiteSpace(url) ? null : NormalizeUrl(url);
        username = string.IsNullOrWhiteSpace(username) ? null : username.Trim();

        InvalidateCache();
        await api.SetPreferenceAsync(UrlKey, url);
        await api.SetPreferenceAsync(UserKey, username);

        if (useMailPassword)
        {
            await api.SetPreferenceAsync(SecretKey, null);
        }
        else if (!string.IsNullOrEmpty(newPassword))
        {
            await api.SetPreferenceAsync(SecretKey, SecretBox.Seal(newPassword, Cred.Password, SealContext));
        }
        else
        {
            // A saved password sealed under an old mail password can never open again; drop it
            // so the account falls back to the mail password rather than failing forever.
            var prefs = await LoadPrefsAsync();
            if (PasswordSource(prefs.GetValueOrDefault(SecretKey)) == DavPasswordSource.NeedsReentry)
                await api.SetPreferenceAsync(SecretKey, null);
        }
    }

    public async Task ResetAsync()
    {
        InvalidateCache();
        await api.SetPreferenceAsync(UrlKey, null);
        await api.SetPreferenceAsync(UserKey, null);
        await api.SetPreferenceAsync(SecretKey, null);
    }

    /// <summary>The effective account, or null when no server URL is configured anywhere.</summary>
    /// <param name="contacts">
    /// For CardDAV: the user's own server is used for both; otherwise an admin-set CardDAV URL
    /// wins over the CalDAV one.
    /// </param>
    /// <exception cref="InvalidOperationException">A saved password no longer opens.</exception>
    public async Task<CalDavAccount?> ResolveAccountAsync(bool contacts = false)
    {
        var prefs = await LoadPrefsAsync();
        var url = prefs.GetValueOrDefault(UrlKey)
                  ?? (contacts ? await DefaultUrlAsync(card: true) : null)
                  ?? await DefaultUrlAsync();
        if (string.IsNullOrWhiteSpace(url)) return null;
        return new CalDavAccount(new Uri(NormalizeUrl(url)),
            prefs.GetValueOrDefault(UserKey) ?? Cred.Login,
            OpenPassword(prefs.GetValueOrDefault(SecretKey)));
    }

    /// <summary>
    /// The CalDAV/CardDAV username and password with the usual fallbacks (mail login and
    /// password). Documents (WebDAV) uses these unless the user gives it its own.
    /// </summary>
    /// <exception cref="InvalidOperationException">A saved CalDAV password no longer opens.</exception>
    public async Task<(string Username, string Password, bool SeparatePassword)> ResolveCredentialsAsync()
    {
        var prefs = await LoadPrefsAsync();
        var secret = prefs.GetValueOrDefault(SecretKey);
        return (prefs.GetValueOrDefault(UserKey) ?? Cred.Login, OpenPassword(secret), !string.IsNullOrEmpty(secret));
    }

    /// <summary>
    /// Test settings without saving them. Blank fields fall back to what is saved, then to
    /// the defaults (server URL, mail login, mail password).
    /// </summary>
    public async Task<CalDavTestResult> TestAsync(string? url, string? username, string? password)
    {
        var prefs = await LoadPrefsAsync();
        var effectiveUrl = !string.IsNullOrWhiteSpace(url) ? url : prefs.GetValueOrDefault(UrlKey) ?? await DefaultUrlAsync();
        if (string.IsNullOrWhiteSpace(effectiveUrl))
            return new(false, "Enter a CalDAV server URL — this server has no default.", []);

        Uri target;
        try { target = new Uri(NormalizeUrl(effectiveUrl)); }
        catch (FormatException ex) { return new(false, ex.Message, []); }

        string effectivePassword;
        try
        {
            effectivePassword = !string.IsNullOrEmpty(password) ? password : OpenPassword(prefs.GetValueOrDefault(SecretKey));
        }
        catch (InvalidOperationException ex)
        {
            return new(false, ex.Message, []);
        }
        var account = new CalDavAccount(target,
            !string.IsNullOrWhiteSpace(username) ? username.Trim() : prefs.GetValueOrDefault(UserKey) ?? Cred.Login,
            effectivePassword);

        try
        {
            var calendars = await DiscoverCalendarsAsync(account);
            // Contacts are optional: not every CalDAV server offers CardDAV.
            IReadOnlyList<string> books = [];
            try { books = await DiscoverAddressBookNamesAsync(account); }
            catch (Exception ex) when (ex is CalDavException or HttpRequestException or TaskCanceledException) { }

            static string Count(int n, string noun) => $"{n} {noun}{(n == 1 ? "" : "s")}";
            var found = calendars.Count == 0 && books.Count == 0
                ? "Connected, but no calendars or address books were found for this account."
                : $"Connected — found {Count(calendars.Count, "calendar")} and {Count(books.Count, "address book")}.";
            return new(true, found, calendars, books);
        }
        catch (CalDavException ex)
        {
            return new(false, ex.Message, []);
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException)
        {
            logger.LogInformation("CalDAV test {Url} failed: {Msg}", target, ex.Message);
            return new(false, ex is TaskCanceledException ? "The server did not respond in time." : $"Could not connect: {ex.Message}", []);
        }
    }

    // ------------------------------------------------------------------ discovery

    /// <summary>Names of the account's calendars (used by the connection test).</summary>
    public async Task<IReadOnlyList<string>> DiscoverCalendarsAsync(CalDavAccount account) =>
        (await DiscoverAsync(account)).EventCalendars.Select(c => c.Info.Name).ToList();

    /// <summary>Discovery for the signed-in account, cached until settings change or a refresh.</summary>
    private async Task<(CalDavAccount Account, Discovery Found)?> DiscoveredAsync()
    {
        var account = await ResolveAccountAsync();
        if (account == null) return null;
        var key = $"{account.Url}|{account.Username}|{account.Password.GetHashCode()}";
        if (_discovered?.Key != key) _discovered = (key, await DiscoverAsync(account));
        return (account, _discovered.Value.Found);
    }

    private const string ListProps =
        "<d:resourcetype/><d:displayname/><a:calendar-color/><c:supported-calendar-component-set/>" +
        "<d:owner/><d:current-user-privilege-set/><cs:allowed-sharing-modes/>";
    private const string DelegationProps = "<cs:calendar-proxy-read-for/><cs:calendar-proxy-write-for/>";

    /// <summary>RFC 4791/6764 discovery: the URL itself, its principal's calendar-home-set, then the home's calendars.</summary>
    private async Task<Discovery> DiscoverAsync(CalDavAccount account)
    {
        var (start, doc) = await PropfindAsync(account, account.Url, 0,
            ListProps + "<d:current-user-principal/><c:calendar-home-set/>" + DelegationProps);

        // The URL may already be a calendar collection.
        var self = doc.Descendants(Dav + "response").FirstOrDefault();
        if (self != null && IsCalendar(self))
            return new Discovery(new Uri(start, start.AbsolutePath.EndsWith('/') ? "../" : "./"), [ToCalendar(self, start)], [], SharingProtocol.None);

        var principal = Href(doc, Dav + "current-user-principal", start);
        var home = Href(doc, Cal + "calendar-home-set", start);
        var principalDoc = home != null ? doc : null;
        if (home == null)
        {
            if (principal == null)
                throw new CalDavException("The server answered but did not identify a calendar account — check the URL.");
            var (pUri, pDoc) = await PropfindAsync(account, principal, 0, "<c:calendar-home-set/>" + DelegationProps);
            principalDoc = pDoc;
            home = Href(pDoc, Cal + "calendar-home-set", pUri)
                   ?? throw new CalDavException("This account has no calendar home on the server.");
        }
        principal ??= start; // the URL was the principal itself

        var (homeUri, list) = await PropfindAsync(account, home, 1, ListProps);
        var sharing = await SharingProtocolAsync(account, homeUri);
        var collections = list.Descendants(Dav + "response").Where(IsCalendar)
            .Select(r => ToCalendar(r, homeUri, principal, sharing)).ToList();
        collections = await NameOwnersAsync(account, collections);
        var delegated = await DelegatedCalendarsAsync(account, principalDoc!, principal, collections);
        return new Discovery(homeUri, collections, delegated, sharing);
    }

    /// <summary>
    /// Calendars of the people who made the user their delegate (CalendarServer calendar-proxy).
    /// Best effort: a delegator whose calendars can't be read is left out.
    /// </summary>
    private async Task<IReadOnlyList<CalCollection>> DelegatedCalendarsAsync(
        CalDavAccount account, XDocument principalDoc, Uri principal, IReadOnlyList<CalCollection> own)
    {
        var owners = new List<(Uri Principal, bool Write)>();
        foreach (var (prop, write) in new[] { (CS + "calendar-proxy-read-for", false), (CS + "calendar-proxy-write-for", true) })
            foreach (var href in principalDoc.Descendants(prop).Elements(Dav + "href"))
                if (!string.IsNullOrWhiteSpace(href.Value))
                    owners.Add((new Uri(principal, href.Value.Trim()), write));

        var result = new List<CalCollection>();
        var seen = own.Select(c => c.Info.Id).ToHashSet();
        foreach (var (owner, write) in owners.DistinctBy(o => o.Principal.AbsoluteUri))
        {
            try
            {
                var (pUri, pDoc) = await PropfindAsync(account, owner, 0, "<d:displayname/><c:calendar-home-set/>");
                var home = Href(pDoc, Cal + "calendar-home-set", pUri);
                if (home == null) continue;
                var name = pDoc.Descendants(Dav + "displayname").FirstOrDefault()?.Value.Trim();
                if (string.IsNullOrEmpty(name)) name = LastSegment(owner.AbsolutePath);
                var (homeUri, list) = await PropfindAsync(account, home, 1, ListProps);
                foreach (var r in list.Descendants(Dav + "response").Where(IsCalendar))
                {
                    var c = ToCalendar(r, homeUri, principal, SharingProtocol.None);
                    if (!seen.Add(c.Info.Id) || !c.Supports("VEVENT")) continue;
                    // The proxy grant decides; a server that reports privileges may narrow it further.
                    var readOnly = !write || c.Info.ReadOnly;
                    result.Add(c with { Info = c.Info with { Kind = CalendarKind.Delegated, OwnerName = name, ReadOnly = readOnly } });
                }
            }
            catch (Exception ex) when (ex is CalDavException or HttpRequestException or TaskCanceledException)
            {
                logger.LogInformation("CalDAV delegated calendars of {Owner} failed: {Msg}", owner, ex.Message);
            }
        }
        return result;
    }

    /// <summary>Put the owners' names on calendars shared with the user (best effort; falls back to their user name).</summary>
    private async Task<List<CalCollection>> NameOwnersAsync(CalDavAccount account, List<CalCollection> collections)
    {
        var names = new Dictionary<string, string>();
        foreach (var owner in collections.Where(c => c.Info.Kind == CalendarKind.Shared && c.Owner != null).Select(c => c.Owner!).DistinctBy(o => o.AbsoluteUri))
        {
            var name = LastSegment(owner.AbsolutePath);
            try
            {
                var (_, doc) = await PropfindAsync(account, owner, 0, "<d:displayname/>");
                var display = doc.Descendants(Dav + "displayname").FirstOrDefault()?.Value.Trim();
                if (!string.IsNullOrEmpty(display)) name = display;
            }
            catch (Exception ex) when (ex is CalDavException or HttpRequestException or TaskCanceledException) { }
            names[owner.AbsoluteUri] = name;
        }
        return collections.Select(c => c.Owner != null && names.TryGetValue(c.Owner.AbsoluteUri, out var n)
            ? c with { Info = c.Info with { OwnerName = n } } : c).ToList();
    }

    /// <summary>Which sharing extension the server offers, from the DAV header of an OPTIONS request.</summary>
    private async Task<SharingProtocol> SharingProtocolAsync(CalDavAccount account, Uri home)
    {
        try
        {
            var http = httpFactory.CreateClient(HttpClientName);
            using var req = new HttpRequestMessage(HttpMethod.Options, home);
            req.Headers.Authorization = BasicAuth(account);
            using var resp = await http.SendAsync(req);
            return SharingFromDavHeader(resp.Headers.TryGetValues("DAV", out var values) ? values : []);
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException)
        {
            return SharingProtocol.None;
        }
    }

    /// <summary>
    /// "resource-sharing" is draft-pot-webdav-resource-sharing (SabreDAV 4, Cyrus);
    /// "calendarserver-sharing" is Apple's CalendarServer extension (SabreDAV, iCloud, Nextcloud).
    /// </summary>
    public static SharingProtocol SharingFromDavHeader(IEnumerable<string> davHeaders)
    {
        var tokens = davHeaders.SelectMany(h => h.Split(',')).Select(t => t.Trim()).ToHashSet(StringComparer.OrdinalIgnoreCase);
        if (tokens.Contains("resource-sharing")) return SharingProtocol.ResourceSharing;
        if (tokens.Contains("calendarserver-sharing")) return SharingProtocol.CalendarServer;
        return SharingProtocol.None;
    }

    private static string LastSegment(string path) => Uri.UnescapeDataString(path.TrimEnd('/').Split('/')[^1]);

    // ------------------------------------------------------------------ events

    /// <summary>
    /// Events overlapping [from, to) across the account's event calendars, the calendars of
    /// people the user is a delegate for, and the user's subscriptions. A calendar that fails is
    /// reported in <see cref="CalendarRange.Errors"/> rather than failing the rest. Null when
    /// there's no calendar server and nothing subscribed.
    /// </summary>
    /// <param name="fetch">Which calendars to read; the rest (turned off by the user) are listed without their events.</param>
    /// <exception cref="CalDavException">Discovery failed (bad URL or credentials).</exception>
    public async Task<CalendarRange?> GetEventsAsync(DateTimeOffset from, DateTimeOffset to, TimeZoneInfo viewerZone,
        Func<CalendarInfo, bool>? fetch = null)
    {
        var subscriptions = await GetSubscriptionsAsync();
        var discovered = await DiscoveredAsync();
        if (discovered == null && subscriptions.Count == 0) return null;
        var account = discovered?.Account;

        var sources = new List<(CalendarInfo Info, Func<Task<IReadOnlyList<CalendarEvent>>> Fetch)>();
        if (discovered is { } d)
            foreach (var c in d.Found.EventCalendars.Concat(d.Found.Delegated))
                sources.Add((c.Info, () => QueryAsync(d.Account, c.Href, c.Info.Id, from, to, viewerZone)));
        foreach (var sub in subscriptions)
            sources.Add((sub.ToInfo(), () => SubscriptionEventsAsync(sub, account, from, to, viewerZone)));

        var tasks = sources.Select(async s =>
        {
            if (fetch?.Invoke(s.Info) == false) return (Events: (IReadOnlyList<CalendarEvent>)[], Error: (string?)null);
            try { return (Events: await s.Fetch(), Error: (string?)null); }
            catch (Exception ex) when (ex is CalDavException or HttpRequestException or TaskCanceledException)
            {
                logger.LogInformation("Calendar query {Calendar} failed: {Msg}", s.Info.Name, ex.Message);
                return (Events: (IReadOnlyList<CalendarEvent>)[], Error: (string?)$"{s.Info.Name}: {ex.Message}");
            }
        }).ToList();
        var results = await Task.WhenAll(tasks);

        return new CalendarRange(
            sources.Select(s => s.Info).ToList(),
            results.SelectMany(r => r.Events).OrderBy(e => e.Start).ThenByDescending(e => e.AllDay).ToList(),
            results.Where(r => r.Error != null).Select(r => r.Error!).ToList());
    }

    /// <summary>Forget discovered calendars (after settings change or a manual refresh).</summary>
    public void InvalidateCache()
    {
        _discovered = null;
        _feeds.Clear();
        _discoveredBooks = null;
        _contacts = null;
    }

    private async Task<IReadOnlyList<CalendarEvent>> QueryAsync(
        CalDavAccount account, Uri calendar, string calendarId, DateTimeOffset from, DateTimeOffset to, TimeZoneInfo viewerZone)
    {
        var range = $"""start="{from.UtcDateTime:yyyyMMdd'T'HHmmss'Z'}" end="{to.UtcDateTime:yyyyMMdd'T'HHmmss'Z'}" """;
        // <c:expand> asks the server to expand recurrences into instances; servers that ignore it
        // return the master event with its RRULE, which ICalendar.Expand handles.
        var body = $"""
            <?xml version="1.0" encoding="utf-8"?>
            <c:calendar-query xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav">
              <d:prop><d:getetag/><c:calendar-data><c:expand {range}/></c:calendar-data></d:prop>
              <c:filter><c:comp-filter name="VCALENDAR"><c:comp-filter name="VEVENT"><c:time-range {range}/></c:comp-filter></c:comp-filter></c:filter>
            </c:calendar-query>
            """;
        var (_, doc) = await SendAsync(account, "REPORT", calendar, 1, body);

        // Expand per resource so each instance keeps its .ics URL and ETag for editing.
        return doc.Descendants(Dav + "response").SelectMany(r =>
        {
            var data = r.Descendants(Cal + "calendar-data").FirstOrDefault()?.Value;
            if (string.IsNullOrEmpty(data)) return [];
            var href = r.Element(Dav + "href")?.Value.Trim();
            var etag = r.Descendants(Dav + "getetag").FirstOrDefault()?.Value.Trim();
            var abs = string.IsNullOrEmpty(href) ? null : new Uri(calendar, href).AbsoluteUri;
            return ICalendar.Expand(ICalendar.ParseEvents(data, viewerZone), from, to)
                .Select(e => new CalendarEvent(e.Uid, e.Summary.Length > 0 ? e.Summary : "(no title)",
                    e.Start, e.End, e.Location, e.Description, e.AllDay, calendarId)
                {
                    Href = abs,
                    ETag = string.IsNullOrWhiteSpace(etag) ? null : etag,
                    IsRecurring = e.IsRecurring,
                    OccurrenceId = e.OccurrenceId,
                    Organizer = e.Organizer,
                    Attendees = e.Attendees,
                    Reminders = ReminderMinutes(e.Alarms),
                });
        }).ToList();
    }

    /// <summary>Alarm offsets as whole minutes before the start, for the UI.</summary>
    internal static IReadOnlyList<int> ReminderMinutes(IEnumerable<TimeSpan> alarms) =>
        alarms.Select(a => (int)Math.Round(a.TotalMinutes)).Distinct().ToList();

    private Task<(Uri Url, XDocument Doc)> PropfindAsync(CalDavAccount account, Uri url, int depth, string props) =>
        SendAsync(account, "PROPFIND", url, depth,
            $"""<?xml version="1.0" encoding="utf-8"?><d:propfind xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav" xmlns:a="http://apple.com/ns/ical/" xmlns:cs="http://calendarserver.org/ns/"><d:prop>{props}</d:prop></d:propfind>""");

    private async Task<(Uri Url, XDocument Doc)> SendAsync(CalDavAccount account, string method, Uri url, int depth, string body)
    {
        var http = httpFactory.CreateClient(HttpClientName);

        // Follow redirects by hand: HttpClient would drop the method/body, and the
        // credentials must not be sent to a different host.
        for (var hop = 0; hop < 4; hop++)
        {
            using var req = new HttpRequestMessage(new HttpMethod(method), url);
            req.Headers.Authorization = BasicAuth(account);
            req.Headers.Add("Depth", depth.ToString());
            req.Content = new StringContent(body, Encoding.UTF8, "application/xml");
            using var resp = await http.SendAsync(req);

            if ((int)resp.StatusCode is >= 300 and < 400 && resp.Headers.Location is { } location)
            {
                var next = location.IsAbsoluteUri ? location : new Uri(url, location);
                if (next.Host != url.Host || next.Scheme is not ("http" or "https"))
                    throw new CalDavException($"The server redirected to {next.GetLeftPart(UriPartial.Authority)}; use that address instead.");
                url = next;
                continue;
            }
            if (resp.StatusCode == HttpStatusCode.Unauthorized)
                throw new CalDavException("The server rejected the username or password.");
            if (resp.StatusCode == HttpStatusCode.Forbidden)
                throw new CalDavException("Signed in, but this account isn't allowed to access that URL.");
            if (resp.StatusCode == HttpStatusCode.NotFound)
                throw new CalDavException("Nothing was found at that URL — check the path.");
            if (resp.StatusCode != HttpStatusCode.MultiStatus)
                throw new CalDavException($"The server doesn't look like CalDAV (HTTP {(int)resp.StatusCode} {resp.ReasonPhrase}).");

            try
            {
                return (url, XDocument.Parse(await resp.Content.ReadAsStringAsync()));
            }
            catch (System.Xml.XmlException)
            {
                throw new CalDavException("The server sent a response that isn't valid WebDAV XML.");
            }
        }
        throw new CalDavException("Too many redirects.");
    }

    private static AuthenticationHeaderValue BasicAuth(CalDavAccount account) =>
        new("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes($"{account.Username}:{account.Password}")));

    /// <param name="principal">The user's principal: a calendar another principal owns is shared with them.</param>
    /// <param name="sharing">How the server shares calendars (from its DAV header).</param>
    private static CalCollection ToCalendar(XElement response, Uri baseUri, Uri? principal = null, SharingProtocol sharing = SharingProtocol.None)
    {
        var href = response.Element(Dav + "href")?.Value.Trim();
        var abs = string.IsNullOrEmpty(href) ? baseUri : new Uri(baseUri, href);
        var color = response.Descendants(Apple + "calendar-color").FirstOrDefault()?.Value.Trim();
        // Apple stores #RRGGBBAA; CSS wants #RRGGBB.
        if (color is { Length: 9 } && color[0] == '#') color = color[..7];
        if (color != null && !System.Text.RegularExpressions.Regex.IsMatch(color, "^#[0-9A-Fa-f]{6}$")) color = null;
        var components = response.Descendants(Cal + "supported-calendar-component-set").Elements(Cal + "comp")
            .Select(c => ((string?)c.Attribute("name"))?.ToUpperInvariant()).OfType<string>()
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        var ownerHref = response.Descendants(Dav + "owner").Elements(Dav + "href").FirstOrDefault()?.Value.Trim();
        var owner = string.IsNullOrEmpty(ownerHref) ? null : new Uri(baseUri, ownerHref);
        var shared = owner != null && principal != null && !SamePath(owner, principal);
        var readOnly = IsReadOnly(response);
        // CalendarServer marks each calendar that can be shared, even where the DAV header doesn't say.
        if (sharing == SharingProtocol.None && response.Descendants(CS + "allowed-sharing-modes").Elements(CS + "can-be-shared").Any())
            sharing = SharingProtocol.CalendarServer;
        var info = new CalendarInfo(abs.AbsoluteUri, DisplayName(response, baseUri), color)
        {
            Kind = shared ? CalendarKind.Shared : CalendarKind.Own,
            ReadOnly = readOnly,
            CanShare = !shared && !readOnly && sharing != SharingProtocol.None,
        };
        return new CalCollection(abs, info, components, owner, shared ? SharingProtocol.None : sharing);
    }

    /// <summary>
    /// A collection whose current-user-privilege-set (RFC 3744) grants no way to add or change
    /// objects. Servers that don't report privileges are assumed to allow writes.
    /// </summary>
    public static bool IsReadOnly(XElement response)
    {
        var set = response.Descendants(Dav + "current-user-privilege-set").FirstOrDefault();
        if (set == null) return false;
        var granted = set.Elements(Dav + "privilege").Elements().Select(e => e.Name).ToHashSet();
        if (granted.Count == 0) return false; // an empty set is how some servers say "not reported"
        return !granted.Overlaps([Dav + "all", Dav + "write", Dav + "write-content", Dav + "bind"]);
    }

    private static bool SamePath(Uri a, Uri b) =>
        a.Host.Equals(b.Host, StringComparison.OrdinalIgnoreCase) &&
        Uri.UnescapeDataString(a.AbsolutePath).TrimEnd('/').Equals(Uri.UnescapeDataString(b.AbsolutePath).TrimEnd('/'), StringComparison.OrdinalIgnoreCase);

    /// <summary>A calendar collection (of events, tasks or notes).</summary>
    private static bool IsCalendar(XElement response) =>
        response.Descendants(Dav + "resourcetype").Elements(Cal + "calendar").Any();

    // ------------------------------------------------------------------ resource writes (shared by contacts and events)

    private sealed record ResourceResponse(HttpStatusCode Status, string? ETag, string? Body);

    /// <summary>PUT/GET/DELETE one resource (a .vcf or .ics). Redirects are not followed for writes.</summary>
    private async Task<ResourceResponse> SendResourceAsync(CalDavAccount account, HttpMethod method, Uri url,
        string? body, string? contentType, Dictionary<string, string> headers)
    {
        var http = httpFactory.CreateClient(HttpClientName);
        using var req = new HttpRequestMessage(method, url);
        req.Headers.Authorization = BasicAuth(account);
        foreach (var (k, v) in headers) req.Headers.TryAddWithoutValidation(k, v);
        if (body != null)
        {
            req.Content = new StringContent(body, Encoding.UTF8);
            req.Content.Headers.ContentType = MediaTypeHeaderValue.Parse(contentType ?? "text/plain; charset=utf-8");
        }
        using var resp = await http.SendAsync(req);
        var etag = resp.Headers.ETag?.ToString();
        var text = method == HttpMethod.Get ? await resp.Content.ReadAsStringAsync() : null;
        if (method != HttpMethod.Get && resp.IsSuccessStatusCode && url.AbsolutePath.EndsWith(".ics", StringComparison.OrdinalIgnoreCase))
            CalendarWritten?.Invoke();
        return new ResourceResponse(resp.StatusCode, etag, text);
    }

    /// <summary>Raised after an .ics resource is written or deleted here, so reminders can be looked up again.</summary>
    public event Action? CalendarWritten;

    private static void EnsureWriteSucceeded(HttpStatusCode status, string noun)
    {
        switch (status)
        {
            case HttpStatusCode.OK or HttpStatusCode.Created or HttpStatusCode.NoContent:
                return;
            case HttpStatusCode.PreconditionFailed:
                throw new CalDavException($"This {noun} was changed somewhere else since you opened it. Refresh and try again.");
            case HttpStatusCode.Unauthorized:
                throw new CalDavException("The server rejected the username or password.");
            case HttpStatusCode.Forbidden or HttpStatusCode.MethodNotAllowed:
                throw new CalDavException($"The server doesn't allow changes here — the {noun switch { "contact" => "address book", "event" => "calendar", _ => "list" }} may be read-only.");
            case HttpStatusCode.UnsupportedMediaType or HttpStatusCode.BadRequest or HttpStatusCode.UnprocessableEntity:
                throw new CalDavException($"The server rejected the {noun} as invalid (HTTP {(int)status}).");
            default:
                throw new CalDavException($"Saving the {noun} failed (HTTP {(int)status}).");
        }
    }

    private static string DisplayName(XElement response, Uri baseUri)
    {
        var name = response.Descendants(Dav + "displayname").FirstOrDefault()?.Value;
        if (!string.IsNullOrWhiteSpace(name)) return name.Trim();
        var href = response.Element(Dav + "href")?.Value ?? baseUri.AbsolutePath;
        return Uri.UnescapeDataString(href.TrimEnd('/').Split('/')[^1]);
    }

    private static Uri? Href(XDocument doc, XName property, Uri baseUri)
    {
        var href = doc.Descendants(property).Elements(Dav + "href").FirstOrDefault()?.Value;
        return string.IsNullOrWhiteSpace(href) ? null : new Uri(baseUri, href.Trim());
    }

    // ------------------------------------------------------------------ helpers

    private string OpenPassword(string? sealedSecret)
    {
        if (string.IsNullOrEmpty(sealedSecret)) return Cred.Password;
        if (SecretBox.TryOpen(sealedSecret, Cred.Password, SealContext, out var password)) return password;
        throw new InvalidOperationException(
            "Your saved CalDAV password can't be unlocked because your mail password has changed. Please enter it again.");
    }

    private DavPasswordSource PasswordSource(string? sealedSecret)
    {
        if (string.IsNullOrEmpty(sealedSecret)) return DavPasswordSource.MailPassword;
        return SecretBox.TryOpen(sealedSecret, Cred.Password, SealContext, out _)
            ? DavPasswordSource.Saved
            : DavPasswordSource.NeedsReentry;
    }

    private async Task<Dictionary<string, string>> LoadPrefsAsync() =>
        (await api.GetPreferencesAsync())
            .Where(p => p.Key.StartsWith("caldav.", StringComparison.Ordinal) && !string.IsNullOrEmpty(p.Value))
            .ToDictionary(p => p.Key, p => p.Value!);

    /// <summary>The admin-configured CalDAV (or CardDAV) URL for the user's domain, else the global one.</summary>
    private async Task<string?> DefaultUrlAsync(bool card = false)
    {
        var domain = AuthService.ExtractDomain(Cred.Login);
        if (!string.IsNullOrEmpty(domain))
        {
            await using var db = await dbFactory.CreateDbContextAsync();
            var mapped = await db.Domains.Where(d => d.Name == domain)
                .Select(d => card ? d.CardDavUrl : d.CalDavUrl).FirstOrDefaultAsync();
            if (!string.IsNullOrWhiteSpace(mapped)) return mapped;
        }
        var global = card ? settings.Current.CardDavUrl : settings.Current.CalDavUrl;
        return string.IsNullOrWhiteSpace(global) ? null : global;
    }

    public static string NormalizeUrl(string url)
    {
        url = url.Trim();
        if (!url.Contains("://")) url = "https://" + url;
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) || uri.Scheme is not ("http" or "https"))
            throw new FormatException("Enter a full http:// or https:// address.");
        return uri.ToString();
    }

}
