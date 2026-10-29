// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using System.Net;
using System.Xml.Linq;
using Nullify.WebMail.Shared;

namespace Nullify.WebMail.Services;

/// <summary>
/// Sharing a calendar with other people over CalDAV. There is no single standard: servers offer
/// either draft-pot-webdav-resource-sharing (DAV:share-resource) or Apple's CalendarServer
/// sharing (CS:share), and say which in their DAV header. Calendars on servers with neither
/// can't be shared from here (many manage sharing in their own web interface instead).
/// </summary>
public sealed partial class CalDavAccountService
{
    /// <summary>Who the calendar is shared with, and what they may do.</summary>
    /// <exception cref="CalDavException">The server refused, or the calendar can't be shared.</exception>
    public async Task<IReadOnlyList<CalendarSharee>> GetShareesAsync(string calendarId)
    {
        var (account, calendar) = await ShareableAsync(calendarId);
        var (_, doc) = await PropfindAsync(account, calendar.Href, 0,
            calendar.Sharing == SharingProtocol.ResourceSharing ? "<d:invite/>" : "<cs:invite/>");
        return ParseSharees(doc, calendar.Sharing);
    }

    /// <summary>Share the calendar with someone, or change what they may do with it.</summary>
    /// <param name="who">An email address (or a principal URL the server gave).</param>
    public async Task ShareAsync(string calendarId, string who, string? name, bool canEdit)
    {
        var (account, calendar) = await ShareableAsync(calendarId);
        await PostShareAsync(account, calendar, SharingRequest(calendar.Sharing, ShareeAddress(who), name, canEdit), who);
    }

    /// <summary>Stop sharing the calendar with someone.</summary>
    public async Task UnshareAsync(string calendarId, string address)
    {
        var (account, calendar) = await ShareableAsync(calendarId);
        await PostShareAsync(account, calendar, SharingRequest(calendar.Sharing, address, null, null), address);
    }

    private async Task<(CalDavAccount, CalCollection)> ShareableAsync(string calendarId)
    {
        var d = await DiscoveredAsync() ?? throw new CalDavException("No calendar server is configured.");
        var calendar = d.Found.Collections.FirstOrDefault(c => c.Info.Id == calendarId);
        if (calendar == null || !calendar.Info.CanShare || calendar.Sharing == SharingProtocol.None)
            throw new CalDavException("This calendar can't be shared from here.");
        return (d.Account, calendar);
    }

    private async Task PostShareAsync(CalDavAccount account, CalCollection calendar, XDocument request, string who)
    {
        var contentType = calendar.Sharing == SharingProtocol.ResourceSharing
            ? "application/davsharing+xml; charset=utf-8"
            : "application/xml; charset=utf-8";
        var resp = await SendResourceAsync(account, HttpMethod.Post, calendar.Href,
            request.Declaration + request.ToString(SaveOptions.DisableFormatting), contentType, []);
        switch (resp.Status)
        {
            case HttpStatusCode.OK or HttpStatusCode.Created or HttpStatusCode.NoContent or HttpStatusCode.MultiStatus:
                return;
            case HttpStatusCode.Unauthorized:
                throw new CalDavException("The server rejected the username or password.");
            case HttpStatusCode.Forbidden:
                throw new CalDavException("The server doesn't let you share this calendar.");
            case HttpStatusCode.NotFound or HttpStatusCode.Conflict or HttpStatusCode.BadRequest or HttpStatusCode.PreconditionFailed:
                throw new CalDavException($"The server couldn't share it with {who} — check the address is someone on this server (HTTP {(int)resp.Status}).");
            default:
                throw new CalDavException($"Sharing failed (HTTP {(int)resp.Status}).");
        }
    }

    /// <summary>A bare email address becomes a mailto: URI; anything else (a principal URL) is used as it is.</summary>
    public static string ShareeAddress(string who)
    {
        who = who.Trim();
        if (who.StartsWith("mailto:", StringComparison.OrdinalIgnoreCase) || who.StartsWith('/') || who.Contains("://")) return who;
        if (!who.Contains('@')) throw new CalDavException("Enter the email address of the person to share with.");
        return "mailto:" + who;
    }

    /// <summary>
    /// The POST body that shares (<paramref name="canEdit"/> set) or stops sharing (null) a
    /// calendar with <paramref name="address"/>, in the server's protocol.
    /// </summary>
    public static XDocument SharingRequest(SharingProtocol protocol, string address, string? name, bool? canEdit)
    {
        var decl = new XDeclaration("1.0", "utf-8", null);
        if (protocol == SharingProtocol.ResourceSharing)
        {
            var access = canEdit switch { true => "read-write", false => "read", null => "no-access" };
            var sharee = new XElement(Dav + "sharee", new XElement(Dav + "href", address));
            if (!string.IsNullOrWhiteSpace(name) && canEdit != null)
                sharee.Add(new XElement(Dav + "prop", new XElement(Dav + "displayname", name.Trim())));
            sharee.Add(new XElement(Dav + "share-access", new XElement(Dav + access)));
            return new XDocument(decl, new XElement(Dav + "share-resource", new XAttribute(XNamespace.Xmlns + "d", Dav.NamespaceName), sharee));
        }

        XElement change;
        if (canEdit is { } edit)
        {
            change = new XElement(CS + "set", new XElement(Dav + "href", address));
            if (!string.IsNullOrWhiteSpace(name)) change.Add(new XElement(CS + "common-name", name.Trim()));
            change.Add(new XElement(CS + (edit ? "read-write" : "read")));
        }
        else
        {
            change = new XElement(CS + "remove", new XElement(Dav + "href", address));
        }
        return new XDocument(decl, new XElement(CS + "share",
            new XAttribute(XNamespace.Xmlns + "d", Dav.NamespaceName), new XAttribute(XNamespace.Xmlns + "cs", CS.NamespaceName), change));
    }

    /// <summary>The sharees in a PROPFIND answer for DAV:invite or CS:invite. The owner isn't one.</summary>
    public static IReadOnlyList<CalendarSharee> ParseSharees(XDocument doc, SharingProtocol protocol)
    {
        var result = new List<CalendarSharee>();
        if (protocol == SharingProtocol.ResourceSharing)
        {
            foreach (var s in doc.Descendants(Dav + "invite").Elements(Dav + "sharee"))
            {
                var href = s.Element(Dav + "href")?.Value.Trim();
                var access = s.Element(Dav + "share-access")?.Elements().FirstOrDefault()?.Name.LocalName;
                if (string.IsNullOrEmpty(href) || access is not ("read" or "read-write")) continue; // owner, no-access, not-shared
                var name = s.Descendants(Dav + "displayname").FirstOrDefault()?.Value.Trim();
                result.Add(new CalendarSharee(href, string.IsNullOrEmpty(name) ? null : name, access == "read-write", StatusOf(s, Dav)));
            }
            return result;
        }

        foreach (var u in doc.Descendants(CS + "invite").Elements(CS + "user"))
        {
            var href = u.Element(Dav + "href")?.Value.Trim();
            if (string.IsNullOrEmpty(href)) continue;
            var name = u.Element(CS + "common-name")?.Value.Trim();
            var canEdit = u.Element(CS + "access")?.Element(CS + "read-write") != null;
            result.Add(new CalendarSharee(href, string.IsNullOrEmpty(name) ? null : name, canEdit, StatusOf(u, CS)));
        }
        return result;
    }

    private static ShareStatus StatusOf(XElement sharee, XNamespace ns) =>
        sharee.Element(ns + "invite-accepted") != null ? ShareStatus.Accepted
        : sharee.Element(ns + "invite-declined") != null ? ShareStatus.Declined
        : sharee.Element(ns + "invite-invalid") != null ? ShareStatus.Invalid
        : ShareStatus.Pending;
}
