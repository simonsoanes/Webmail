// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using System.Text;
using Nullify.WebMail.Services;
using Nullify.WebMail.Shared;

namespace Nullify.WebMail.Tests;

[TestClass]
public class MimeTests
{
    [ClassInitialize]
    public static void Init(TestContext _) =>
        Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);

    private static byte[] Crlf(string s) => Encoding.UTF8.GetBytes(s.Replace("\r\n", "\n").Replace("\n", "\r\n"));

    [TestMethod]
    public void NestedMultipart_FindsBodiesAndAttachmentsWithPartIds()
    {
        var raw = Crlf("""
            From: Alice <alice@example.org>
            Subject: =?utf-8?B?UXVhcnRlcmx5IHJlcG9ydCDigJQgUTM=?=
            Content-Type: multipart/mixed; boundary="outer"

            --outer
            Content-Type: multipart/alternative; boundary="alt"

            --alt
            Content-Type: text/plain; charset=utf-8
            Content-Transfer-Encoding: quoted-printable

            Caf=C3=A9 soon=
             please
            --alt
            Content-Type: text/html; charset=utf-8

            <p>Café</p>
            --alt--
            --outer
            Content-Type: application/pdf; name="r.pdf"
            Content-Disposition: attachment; filename*=UTF-8''Q3%20r%C3%A9port.pdf
            Content-Transfer-Encoding: base64

            SGVsbG8=
            --outer--
            """);

        var parts = MimeParser.Parse(raw);

        Assert.AreEqual("Quarterly report — Q3", parts.Headers["Subject"]);
        Assert.AreEqual("Café soon please", parts.TextBody);
        Assert.AreEqual("<p>Café</p>", parts.HtmlBody);
        Assert.HasCount(1, parts.Attachments);
        var att = parts.Attachments[0];
        Assert.AreEqual("2", att.PartId);
        Assert.AreEqual("Q3 réport.pdf", att.Filename);
        Assert.AreEqual("Hello", Encoding.ASCII.GetString(att.Data));
    }

    [TestMethod]
    public void SinglePartBase64_IsDecoded()
    {
        var raw = Crlf("""
            Subject: hi
            Content-Type: text/plain; charset=utf-8
            Content-Transfer-Encoding: base64

            SGVsbG8gd29ybGQg4pyT
            """);
        Assert.AreEqual("Hello world ✓", MimeParser.Parse(raw).TextBody);
    }

    [TestMethod]
    public void Latin1QuotedPrintable_UsesDeclaredCharset()
    {
        var raw = Crlf("""
            Content-Type: text/plain; charset=iso-8859-1
            Content-Transfer-Encoding: quoted-printable

            tr=E8s bon
            """);
        Assert.AreEqual("très bon", MimeParser.Parse(raw).TextBody);
    }

    [TestMethod]
    public void BuiltMessage_RoundTripsThroughParser()
    {
        var req = new SendRequest(
            "Tëst User <me@example.test>", ["Bob <bob@example.org>"], ["carol@example.org"], null,
            "Grüße ✓", "Body ✓", null, null, false, false, null,
            "<orig@example.org>", "<orig@example.org>",
            [new OutgoingAttachment("notes.txt", "text/plain", Encoding.UTF8.GetBytes("attached"))]);

        var mime = MailService.BuildMimeMessage(req, "fallback@example.test");
        StringAssert.Contains(mime, "In-Reply-To: <orig@example.org>");
        Assert.IsFalse(mime.Any(c => c > 127), "Outgoing MIME must be 7-bit clean");

        var parsed = MimeParser.Parse(Encoding.ASCII.GetBytes(mime));
        Assert.AreEqual("Grüße ✓", parsed.Headers["Subject"]);
        Assert.AreEqual("Body ✓", parsed.TextBody?.TrimEnd());
        Assert.AreEqual("notes.txt", parsed.Attachments.Single().Filename);
        Assert.AreEqual("Tëst User <me@example.test>", parsed.Headers["From"]);
    }

    [TestMethod]
    public void InlinePhotos_GoInMultipartRelatedBesideTheHtml()
    {
        var png = new byte[] { 0x89, 0x50, 0x4E, 0x47, 1, 2, 3 };
        var req = new SendRequest("me@example.test", ["bob@example.org"], null, null, "Photo", "Look [photo.png]",
            """<div>Look <img src="cid:img1.abc@webmail"></div>""", null, false, false, null,
            Attachments:
            [
                new OutgoingAttachment("photo.png", "image/png", png, "img1.abc@webmail"),
                new OutgoingAttachment("notes.txt", "text/plain", Encoding.UTF8.GetBytes("attached")),
            ],
            Important: true);

        var mime = MailService.BuildMimeMessage(req, "fallback@example.test");
        StringAssert.Contains(mime, "Importance: high");
        StringAssert.Contains(mime, "X-Priority: 1 (Highest)");
        StringAssert.Contains(mime, "multipart/related");
        StringAssert.Contains(mime, "Content-ID: <img1.abc@webmail>");

        var parsed = MimeParser.Parse(Encoding.ASCII.GetBytes(mime));
        StringAssert.Contains(parsed.HtmlBody, "cid:img1.abc@webmail");
        Assert.AreEqual("Look [photo.png]", parsed.TextBody?.TrimEnd());
        var photo = parsed.Attachments.Single(a => a.Filename == "photo.png");
        Assert.AreEqual("img1.abc@webmail", photo.ContentId?.Trim('<', '>'));
        Assert.IsTrue(photo.IsInline);
        Assert.IsTrue(parsed.Attachments.Any(a => a.Filename == "notes.txt" && !a.IsInline));
    }

    [TestMethod]
    public void UnimportantMessages_CarryNoPriorityHeaders()
    {
        var req = new SendRequest("me@example.test", ["bob@example.org"], null, null, "Hi", "Hello", null, null, false, false, null);
        var mime = MailService.BuildMimeMessage(req, "fallback@example.test");
        Assert.IsFalse(mime.Contains("Importance:") || mime.Contains("X-Priority:"));
        StringAssert.StartsWith(mime[mime.IndexOf("Content-Type:")..], "Content-Type: text/plain");
    }

    [TestMethod]
    public void UidSet_CompactsRuns() =>
        Assert.AreEqual("1:3,7,9:10", ImapSession.UidSet([3, 1, 2, 7, 10, 9]));

    [TestMethod]
    public void Utf7_RoundTrips()
    {
        var name = "Entwürfe & Notes";
        var encoded = ImapUtf7.Encode(name);
        Assert.AreEqual("Entw&APw-rfe &- Notes", encoded);
        Assert.AreEqual(name, ImapUtf7.Decode(encoded));
    }

    [TestMethod]
    public void AddressList_SplitsOnlyOutsideQuotes()
    {
        var list = MailFormat.ParseAddressList("\"Doe, Jane\" <jane@x.org>, bob@y.org");
        Assert.HasCount(2, list);
        Assert.AreEqual("Doe, Jane", list[0].Name);
        Assert.AreEqual("bob@y.org", list[1].Email);
    }

    [TestMethod]
    public void ParseDate_HandlesRfc5322Forms()
    {
        Assert.IsNotNull(MailFormat.ParseDate("Mon, 20 Oct 2026 10:00:00 +0000 (UTC)"));
        Assert.IsNotNull(MailFormat.ParseDate("20 Oct 2026 10:00:00 GMT"));
        Assert.AreEqual(2, MailFormat.ParseDate("Tue, 20 Oct 2026 12:00:00 +0200")!.Value.Offset.Hours);
    }

    [TestMethod]
    public void TextToHtml_EncodesAndLinkifies()
    {
        var html = MailFormat.TextToHtml("see https://a.example/x. <b>\n> quoted");
        StringAssert.Contains(html, "<a href=\"https://a.example/x\"");
        StringAssert.Contains(html, "&lt;b&gt;");
        StringAssert.Contains(html, "<blockquote>quoted");
    }
}
