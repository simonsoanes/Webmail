// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using System.Xml.Linq;
using Nullify.WebMail.Services;
using Nullify.WebMail.Shared;

namespace Nullify.WebMail.Tests;

[TestClass]
public class CalendarViewsTests
{
    private static readonly DateOnly Day = new(2026, 10, 29);

    private static DateTime At(int h, int m = 0) => Day.ToDateTime(new TimeOnly(h, m));

    private static List<CalendarLayout.Placed<string>> Lay(params (string Name, DateTime Start, DateTime End)[] items) =>
        CalendarLayout.Day(items, i => (i.Start, i.End), Day)
            .Select(p => new CalendarLayout.Placed<string>(p.Item.Name, p.Top, p.Height, p.Column, p.Columns)).ToList();

    [TestMethod]
    public void Layout_SeparateEvents_TakeTheFullWidth()
    {
        var placed = Lay(("a", At(9), At(10)), ("b", At(10), At(11)));
        Assert.IsTrue(placed.All(p => p.Columns == 1 && p.Column == 0));
        var a = placed.Single(p => p.Item == "a");
        Assert.AreEqual(9 * 100.0 / 24, a.Top, 0.001);
        Assert.AreEqual(100.0 / 24, a.Height, 0.001);
    }

    [TestMethod]
    public void Layout_OverlappingEvents_ShareColumns_AndFreeColumnsAreReused()
    {
        var placed = Lay(("long", At(9), At(12)), ("a", At(9, 30), At(10)), ("b", At(10), At(11)), ("later", At(13), At(14)));
        var byName = placed.ToDictionary(p => p.Item);
        Assert.AreEqual(2, byName["long"].Columns);
        Assert.AreEqual(0, byName["long"].Column);
        Assert.AreEqual(1, byName["a"].Column);
        Assert.AreEqual(1, byName["b"].Column, "b starts when a ends, so it takes a's column");
        Assert.AreEqual(1, byName["later"].Columns, "a later event is its own group");
    }

    [TestMethod]
    public void Layout_ClipsToTheDay_AndGivesShortEventsAMinimumHeight()
    {
        var placed = Lay(("overnight", At(22), At(23).AddHours(3)), ("blip", At(8), At(8)), ("late", At(23, 55), At(23, 59)));
        var overnight = placed.Single(p => p.Item == "overnight");
        Assert.AreEqual(100.0, overnight.Top + overnight.Height, 0.001);
        Assert.AreEqual(20 / 14.4, placed.Single(p => p.Item == "blip").Height, 0.001);
        var late = placed.Single(p => p.Item == "late");
        Assert.AreEqual(100.0, late.Top + late.Height, 0.001, "pushed up to fit");
    }

    [TestMethod]
    public void Slot_Contains_AllDayAndTimed()
    {
        var allDay = new CalendarSlot(At(0), At(0).AddDays(1), AllDay: true);
        Assert.IsTrue(allDay.Contains(Day));
        Assert.IsTrue(allDay.Contains(Day.AddDays(1)), "an all-day slot's end is its last day");
        Assert.IsFalse(allDay.Contains(Day.AddDays(2)));

        var timed = new CalendarSlot(At(22), At(0).AddDays(1), AllDay: false);
        Assert.IsTrue(timed.Contains(Day));
        Assert.IsFalse(timed.Contains(Day.AddDays(1)), "a timed slot ending at midnight doesn't touch the next day");
    }

    [TestMethod]
    public void FeedUrl_AcceptsWebcalAndBareHosts_RejectsOthers()
    {
        Assert.AreEqual("https://example.org/cal.ics", CalDavAccountService.FeedUrl(" webcal://example.org/cal.ics ").AbsoluteUri);
        Assert.AreEqual("https://example.org/cal.ics", CalDavAccountService.FeedUrl("webcals://example.org/cal.ics").AbsoluteUri);
        Assert.AreEqual("https://example.org/cal.ics", CalDavAccountService.FeedUrl("example.org/cal.ics").AbsoluteUri);
        Assert.ThrowsExactly<CalDavException>(() => CalDavAccountService.FeedUrl("ftp://example.org/cal.ics"));
        Assert.ThrowsExactly<CalDavException>(() => CalDavAccountService.FeedUrl("file:///etc/passwd"));
        Assert.ThrowsExactly<CalDavException>(() => CalDavAccountService.FeedUrl("https://me:secret@example.org/cal.ics"));
    }

    [TestMethod]
    public void CalendarProperties_ReadsTheCalendarsOwnNameAndColour()
    {
        var ics = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nX-WR-CALNAME:UK bank\r\n  holidays\r\nX-APPLE-CALENDAR-COLOR:#1BADF8FF\r\n" +
                  "BEGIN:VEVENT\r\nUID:1\r\nNAME:Not the calendar\r\nSUMMARY:Christmas\r\nDTSTART;VALUE=DATE:20261225\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
        var (name, color) = ICalendar.CalendarProperties(ics);
        Assert.AreEqual("UK bank holidays", name);
        Assert.AreEqual("#1BADF8", color);

        Assert.AreEqual("Rfc 7986", ICalendar.CalendarProperties("BEGIN:VCALENDAR\r\nX-WR-CALNAME:Old\r\nNAME:Rfc 7986\r\nEND:VCALENDAR\r\n").Name);
        Assert.IsNull(ICalendar.CalendarProperties("BEGIN:VCALENDAR\r\nEND:VCALENDAR\r\n").Name);
    }

    [TestMethod]
    public void Sharing_IsChosenFromTheDavHeader()
    {
        Assert.AreEqual(SharingProtocol.CalendarServer,
            CalDavAccountService.SharingFromDavHeader(["1, 3, extended-mkcol, access-control, calendarserver-principal-property-search", "calendar-access, calendarserver-sharing"]));
        Assert.AreEqual(SharingProtocol.ResourceSharing, CalDavAccountService.SharingFromDavHeader(["1, 3, resource-sharing, calendarserver-sharing"]));
        Assert.AreEqual(SharingProtocol.None, CalDavAccountService.SharingFromDavHeader(["1, 3, access-control, calendar-access, calendar-proxy"]));
    }

    [TestMethod]
    public void SharingRequest_ResourceSharing()
    {
        var share = CalDavAccountService.SharingRequest(SharingProtocol.ResourceSharing, "mailto:bob@example.org", "Bob <&>", canEdit: true);
        XNamespace d = "DAV:";
        var sharee = share.Root!.Element(d + "sharee")!;
        Assert.AreEqual(d + "share-resource", share.Root.Name);
        Assert.AreEqual("mailto:bob@example.org", sharee.Element(d + "href")!.Value);
        Assert.AreEqual("Bob <&>", sharee.Descendants(d + "displayname").Single().Value);
        Assert.IsNotNull(sharee.Element(d + "share-access")!.Element(d + "read-write"));

        var stop = CalDavAccountService.SharingRequest(SharingProtocol.ResourceSharing, "mailto:bob@example.org", null, canEdit: null);
        Assert.IsNotNull(stop.Root!.Descendants(d + "no-access").SingleOrDefault());
    }

    [TestMethod]
    public void SharingRequest_CalendarServer()
    {
        XNamespace d = "DAV:", cs = "http://calendarserver.org/ns/";
        var share = CalDavAccountService.SharingRequest(SharingProtocol.CalendarServer, "mailto:bob@example.org", "Bob", canEdit: false);
        var set = share.Root!.Element(cs + "set")!;
        Assert.AreEqual(cs + "share", share.Root.Name);
        Assert.AreEqual("mailto:bob@example.org", set.Element(d + "href")!.Value);
        Assert.AreEqual("Bob", set.Element(cs + "common-name")!.Value);
        Assert.IsNotNull(set.Element(cs + "read"));

        var stop = CalDavAccountService.SharingRequest(SharingProtocol.CalendarServer, "mailto:bob@example.org", null, canEdit: null);
        Assert.AreEqual("mailto:bob@example.org", stop.Root!.Element(cs + "remove")!.Element(d + "href")!.Value);
    }

    [TestMethod]
    public void ParseSharees_CalendarServerInvite()
    {
        var doc = XDocument.Parse("""
            <d:multistatus xmlns:d="DAV:" xmlns:cs="http://calendarserver.org/ns/"><d:response><d:href>/cal/me/work/</d:href><d:propstat><d:prop>
              <cs:invite>
                <cs:organizer><d:href>mailto:me@example.org</d:href></cs:organizer>
                <cs:user><d:href>mailto:bob@example.org</d:href><cs:common-name>Bob</cs:common-name><cs:invite-accepted/><cs:access><cs:read-write/></cs:access></cs:user>
                <cs:user><d:href>mailto:eve@example.org</d:href><cs:invite-noresponse/><cs:access><cs:read/></cs:access></cs:user>
              </cs:invite>
            </d:prop></d:propstat></d:response></d:multistatus>
            """);
        var sharees = CalDavAccountService.ParseSharees(doc, SharingProtocol.CalendarServer);
        Assert.HasCount(2, sharees);
        Assert.AreEqual(new CalendarSharee("mailto:bob@example.org", "Bob", true, ShareStatus.Accepted), sharees[0]);
        Assert.AreEqual("eve@example.org", sharees[1].Display);
        Assert.IsFalse(sharees[1].CanEdit);
        Assert.AreEqual(ShareStatus.Pending, sharees[1].Status);
    }

    [TestMethod]
    public void ParseSharees_ResourceSharingInvite_LeavesOutTheOwner()
    {
        var doc = XDocument.Parse("""
            <d:multistatus xmlns:d="DAV:"><d:response><d:href>/cal/me/work/</d:href><d:propstat><d:prop>
              <d:invite>
                <d:sharee><d:href>/principals/me/</d:href><d:share-access><d:shared-owner/></d:share-access><d:invite-accepted/></d:sharee>
                <d:sharee><d:href>mailto:bob@example.org</d:href><d:prop><d:displayname>Bob</d:displayname></d:prop><d:share-access><d:read/></d:share-access><d:invite-declined/></d:sharee>
              </d:invite>
            </d:prop></d:propstat></d:response></d:multistatus>
            """);
        var sharee = CalDavAccountService.ParseSharees(doc, SharingProtocol.ResourceSharing).Single();
        Assert.AreEqual("Bob", sharee.Display);
        Assert.IsFalse(sharee.CanEdit);
        Assert.AreEqual(ShareStatus.Declined, sharee.Status);
    }

    [TestMethod]
    public void ShareeAddress_MakesEmailsMailtoUris()
    {
        Assert.AreEqual("mailto:bob@example.org", CalDavAccountService.ShareeAddress(" bob@example.org "));
        Assert.AreEqual("mailto:bob@example.org", CalDavAccountService.ShareeAddress("mailto:bob@example.org"));
        Assert.AreEqual("/principals/bob/", CalDavAccountService.ShareeAddress("/principals/bob/"));
        Assert.ThrowsExactly<CalDavException>(() => CalDavAccountService.ShareeAddress("bob"));
    }

    [TestMethod]
    public void IsReadOnly_FromCurrentUserPrivilegeSet()
    {
        static XElement Response(string privileges) => XElement.Parse(
            $"""<d:response xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav"><d:propstat><d:prop><d:current-user-privilege-set>{privileges}</d:current-user-privilege-set></d:prop></d:propstat></d:response>""");

        Assert.IsTrue(CalDavAccountService.IsReadOnly(Response("<d:privilege><d:read/></d:privilege><d:privilege><c:read-free-busy/></d:privilege>")));
        Assert.IsFalse(CalDavAccountService.IsReadOnly(Response("<d:privilege><d:read/></d:privilege><d:privilege><d:write/></d:privilege>")));
        Assert.IsFalse(CalDavAccountService.IsReadOnly(Response("<d:privilege><d:all/></d:privilege>")));
        Assert.IsFalse(CalDavAccountService.IsReadOnly(XElement.Parse("""<d:response xmlns:d="DAV:"/>""")), "not reported: assume writable");
    }

    [TestMethod]
    public void Subscription_Ids_KeepCalDavCalendarsAddressable()
    {
        var feed = new CalendarSubscription("https://example.org/h.ics", "Holidays", null, CalDav: false, ReadOnly: false);
        Assert.AreEqual("feed:https://example.org/h.ics", feed.Id);
        Assert.IsTrue(feed.ToInfo().ReadOnly, "a feed is always read-only");
        Assert.AreEqual(CalendarKind.Subscribed, feed.ToInfo().Kind);

        var dav = new CalendarSubscription("https://dav.example.org/cal/alice/team/", "Team", "#123456", CalDav: true, ReadOnly: false);
        Assert.AreEqual(dav.Url, dav.Id);
        Assert.IsFalse(dav.ToInfo().ReadOnly);
    }
}
