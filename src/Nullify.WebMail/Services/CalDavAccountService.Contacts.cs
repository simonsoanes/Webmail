// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using System.Net;
using System.Xml.Linq;
using Nullify.WebMail.Shared;

namespace Nullify.WebMail.Services;

/// <summary>
/// CardDAV (RFC 6352) on the same account as the calendar: address books are found through the
/// principal's addressbook-home-set, which is how Nextcloud, Radicale, iCloud, Fastmail and
/// SabreDAV-based servers expose both from one login.
/// </summary>
public sealed partial class CalDavAccountService
{
    private static readonly XNamespace Card = "urn:ietf:params:xml:ns:carddav";

    private (string Key, IReadOnlyList<(Uri Href, CalendarInfo Info)> Books)? _discoveredBooks;
    private (string Key, ContactList List)? _contacts;

    /// <summary>All contacts across the account's address books; null when no server is configured.</summary>
    /// <exception cref="CalDavException">Discovery failed (bad URL or credentials).</exception>
    /// <exception cref="InvalidOperationException">A saved password no longer opens.</exception>
    public async Task<ContactList?> GetContactsAsync(bool refresh = false)
    {
        var account = await ResolveAccountAsync(contacts: true);
        if (account == null) return null;

        var key = $"{account.Url}|{account.Username}|{account.Password.GetHashCode()}";
        if (!refresh && _contacts?.Key == key) return _contacts.Value.List;
        if (refresh || _discoveredBooks?.Key != key) _discoveredBooks = (key, await DiscoverAddressBooksAsync(account));
        var books = _discoveredBooks.Value.Books;

        var results = await Task.WhenAll(books.Select(async b =>
        {
            try { return (Contacts: await QueryContactsAsync(account, b.Href, b.Info.Id), Error: (string?)null); }
            catch (Exception ex) when (ex is CalDavException or HttpRequestException or TaskCanceledException)
            {
                logger.LogInformation("CardDAV query {Book} failed: {Msg}", b.Href, ex.Message);
                return (Contacts: (IReadOnlyList<ContactInfo>)[], Error: (string?)$"{b.Info.Name}: {ex.Message}");
            }
        }));

        var list = new ContactList(
            books.Select(b => b.Info).ToList(),
            results.SelectMany(r => r.Contacts)
                .OrderBy(c => c.FullName, StringComparer.CurrentCultureIgnoreCase).ToList(),
            results.Where(r => r.Error != null).Select(r => r.Error!).ToList());
        _contacts = (key, list);
        return list;
    }

    /// <summary>Address book names (used by the connection test).</summary>
    public async Task<IReadOnlyList<string>> DiscoverAddressBookNamesAsync(CalDavAccount account) =>
        (await DiscoverAddressBooksAsync(account)).Select(b => b.Info.Name).ToList();

    private async Task<IReadOnlyList<(Uri Href, CalendarInfo Info)>> DiscoverAddressBooksAsync(CalDavAccount account)
    {
        const string listProps = "<d:resourcetype/><d:displayname/>";
        var (start, doc) = await CardPropfindAsync(account, account.Url, 0,
            listProps + "<d:current-user-principal/><card:addressbook-home-set/>");

        var self = doc.Descendants(Dav + "response").FirstOrDefault();
        if (self != null && IsAddressBook(self)) return [ToAddressBook(self, start)];

        var home = Href(doc, Card + "addressbook-home-set", start);
        if (home == null)
        {
            var principal = Href(doc, Dav + "current-user-principal", start)
                ?? throw new CalDavException("The server answered but did not identify an account — check the URL.");
            var (pUri, pDoc) = await CardPropfindAsync(account, principal, 0, "<card:addressbook-home-set/>");
            home = Href(pDoc, Card + "addressbook-home-set", pUri)
                   ?? throw new CalDavException("This account has no address books on the server.");
        }

        var (homeUri, list) = await CardPropfindAsync(account, home, 1, listProps);
        return list.Descendants(Dav + "response").Where(IsAddressBook).Select(r => ToAddressBook(r, homeUri)).ToList();
    }

    private async Task<IReadOnlyList<ContactInfo>> QueryContactsAsync(CalDavAccount account, Uri book, string bookId)
    {
        // An addressbook-query with no filter returns every card. A few servers insist on a
        // filter, so fall back to listing the cards and fetching them with addressbook-multiget.
        const string query = """
            <?xml version="1.0" encoding="utf-8"?>
            <card:addressbook-query xmlns:d="DAV:" xmlns:card="urn:ietf:params:xml:ns:carddav">
              <d:prop><d:getetag/><card:address-data/></d:prop>
            </card:addressbook-query>
            """;
        XDocument doc;
        try
        {
            (_, doc) = await SendAsync(account, "REPORT", book, 1, query);
        }
        catch (CalDavException)
        {
            var (_, listing) = await CardPropfindAsync(account, book, 1, "<d:getetag/><d:getcontenttype/>");
            var hrefs = listing.Descendants(Dav + "response")
                .Where(r => r.Descendants(Dav + "getcontenttype").Any(t => t.Value.Contains("vcard", StringComparison.OrdinalIgnoreCase)))
                .Select(r => r.Element(Dav + "href")?.Value).Where(h => !string.IsNullOrEmpty(h)).ToList();
            if (hrefs.Count == 0) return [];
            var multiget = """<?xml version="1.0" encoding="utf-8"?><card:addressbook-multiget xmlns:d="DAV:" xmlns:card="urn:ietf:params:xml:ns:carddav"><d:prop><d:getetag/><card:address-data/></d:prop>"""
                + string.Concat(hrefs.Select(h => $"<d:href>{System.Security.SecurityElement.Escape(h)}</d:href>"))
                + "</card:addressbook-multiget>";
            (_, doc) = await SendAsync(account, "REPORT", book, 1, multiget);
        }

        // Keep each card's URL and ETag so it can be edited safely later.
        return doc.Descendants(Dav + "response").SelectMany(r =>
        {
            var data = r.Descendants(Card + "address-data").FirstOrDefault()?.Value;
            if (string.IsNullOrEmpty(data)) return [];
            var href = r.Element(Dav + "href")?.Value.Trim();
            var etag = r.Descendants(Dav + "getetag").FirstOrDefault()?.Value.Trim();
            var abs = string.IsNullOrEmpty(href) ? null : new Uri(book, href).AbsoluteUri;
            return VCard.Parse(data, bookId).Select(c => c with { Href = abs, ETag = NullIfBlank(etag) });
        }).ToList();
    }

    // ------------------------------------------------------------------ writes

    /// <summary>
    /// Create (when <paramref name="existing"/> is null) or update a contact. Updates are
    /// conditional on the card's ETag, so a change made elsewhere is never silently overwritten.
    /// Returns the contact as the server now stores it.
    /// </summary>
    /// <exception cref="CalDavException">The server refused the change (read-only, conflict...).</exception>
    public async Task<ContactInfo> SaveContactAsync(ContactInfo? existing, ContactEdit edit, string? addressBookId)
    {
        var account = await ResolveAccountAsync(contacts: true)
            ?? throw new CalDavException("No address book server is configured.");
        var list = await GetContactsAsync() ?? throw new CalDavException("No address book server is configured.");

        Uri href;
        string uid;
        var headers = new Dictionary<string, string>();
        if (existing?.Href != null)
        {
            href = new Uri(existing.Href);
            uid = existing.Uid;
            if (existing.ETag != null) headers["If-Match"] = existing.ETag;
        }
        else
        {
            var bookId = addressBookId ?? list.AddressBooks.FirstOrDefault()?.Id
                ?? throw new CalDavException("There is no address book to add the contact to.");
            uid = Guid.NewGuid().ToString();
            href = new Uri(new Uri(bookId.EndsWith('/') ? bookId : bookId + "/"), uid + ".vcf");
            headers["If-None-Match"] = "*";
        }

        var card = VCard.Write(existing?.RawCard, edit, uid);
        var put = await SendResourceAsync(account, HttpMethod.Put, href, card, "text/vcard; charset=utf-8", headers);
        EnsureWriteSucceeded(put.Status, "contact");

        // Re-read: servers may normalise the card, and many don't return an ETag on PUT.
        var saved = await TryGetContactAsync(account, href, existing?.AddressBookId ?? addressBookId ?? list.AddressBooks.First().Id)
                    ?? VCard.Parse(card, existing?.AddressBookId ?? addressBookId).First() with { Href = href.AbsoluteUri, ETag = put.ETag };
        UpdateContactCache(existing, saved);
        return saved;
    }

    public async Task DeleteContactAsync(ContactInfo contact)
    {
        var account = await ResolveAccountAsync(contacts: true)
            ?? throw new CalDavException("No address book server is configured.");
        if (contact.Href == null) throw new CalDavException("This contact can't be deleted (unknown location on the server).");
        var headers = contact.ETag != null ? new Dictionary<string, string> { ["If-Match"] = contact.ETag } : [];
        var resp = await SendResourceAsync(account, HttpMethod.Delete, new Uri(contact.Href), null, null, headers);
        if (resp.Status != HttpStatusCode.NotFound) EnsureWriteSucceeded(resp.Status, "contact");
        UpdateContactCache(contact, null);
    }

    private async Task<ContactInfo?> TryGetContactAsync(CalDavAccount account, Uri href, string bookId)
    {
        try
        {
            var get = await SendResourceAsync(account, HttpMethod.Get, href, null, null, []);
            if (get.Status != HttpStatusCode.OK || string.IsNullOrEmpty(get.Body)) return null;
            return VCard.Parse(get.Body, bookId).FirstOrDefault() is { } c ? c with { Href = href.AbsoluteUri, ETag = get.ETag } : null;
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException)
        {
            return null;
        }
    }

    private void UpdateContactCache(ContactInfo? old, ContactInfo? replacement)
    {
        if (_contacts is not { } cached) return;
        var contacts = cached.List.Contacts.Where(c => old == null || c.Href != old.Href || c.Uid != old.Uid).ToList();
        if (replacement != null) contacts.Add(replacement);
        contacts.Sort((a, b) => string.Compare(a.FullName, b.FullName, StringComparison.CurrentCultureIgnoreCase));
        _contacts = (cached.Key, cached.List with { Contacts = contacts });
    }

    private static string? NullIfBlank(string? s) => string.IsNullOrWhiteSpace(s) ? null : s;

    private Task<(Uri Url, XDocument Doc)> CardPropfindAsync(CalDavAccount account, Uri url, int depth, string props) =>
        SendAsync(account, "PROPFIND", url, depth,
            $"""<?xml version="1.0" encoding="utf-8"?><d:propfind xmlns:d="DAV:" xmlns:card="urn:ietf:params:xml:ns:carddav"><d:prop>{props}</d:prop></d:propfind>""");

    private static bool IsAddressBook(XElement response) =>
        response.Descendants(Dav + "resourcetype").Elements(Card + "addressbook").Any();

    private static (Uri Href, CalendarInfo Info) ToAddressBook(XElement response, Uri baseUri)
    {
        var href = response.Element(Dav + "href")?.Value.Trim();
        var abs = string.IsNullOrEmpty(href) ? baseUri : new Uri(baseUri, href);
        return (abs, new CalendarInfo(abs.AbsoluteUri, DisplayName(response, baseUri), null));
    }
}
