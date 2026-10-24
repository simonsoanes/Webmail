// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using Nullify.WebMail.Services;

namespace Nullify.WebMail.Tests;

[TestClass]
public class VCardTests
{
    [TestMethod]
    public void Parses_Vcard3_WithGroupsBareTypesAndFolding()
    {
        var cards = VCard.Parse("""
            BEGIN:VCARD
            VERSION:3.0
            UID:alice-1
            FN:Alice Chen
            N:Chen;Alice;;;
            ORG:Example Org;Finance
            TITLE:CFO
            item1.EMAIL;type=INTERNET;type=WORK;type=pref:alice@example.org
            EMAIL;TYPE=HOME:alice.home@example.net
            TEL;CELL:+44 7700 900123
            TEL;TYPE=WORK,VOICE:+44 20 7946 0000
            NOTE:Met at the conference\, 2025.\nPrefers email
              over phone.
            BDAY:1990-05-17
            END:VCARD
            """.Replace("\n", "\r\n"), "book1");

        var c = cards.Single();
        Assert.AreEqual("Alice Chen", c.FullName);
        Assert.AreEqual("Example Org, Finance", c.Organization);
        Assert.AreEqual("CFO", c.Title);
        Assert.HasCount(2, c.Emails);
        Assert.AreEqual("alice@example.org", c.Email);
        Assert.AreEqual("Work", c.Emails[0].Label);
        Assert.AreEqual("Home", c.Emails[1].Label);
        Assert.AreEqual("Mobile", c.Phones[0].Label);
        Assert.AreEqual("Work", c.Phones[1].Label);
        Assert.AreEqual("Met at the conference, 2025.\nPrefers email over phone.", c.Note);
        Assert.AreEqual("book1", c.AddressBookId);
    }

    [TestMethod]
    public void Vcard4_NameFromN_InlinePhoto_TelUri()
    {
        var cards = VCard.Parse("""
            BEGIN:VCARD
            VERSION:4.0
            N:Hopper;Grace;Brewster;Rear Admiral;
            TEL;VALUE=uri;TYPE=cell:tel:+1-555-0100
            PHOTO:data:image/png;base64,iVBORw0KGgo=
            END:VCARD
            """);

        var c = cards.Single();
        Assert.AreEqual("Rear Admiral Grace Brewster Hopper", c.FullName);
        Assert.AreEqual("+1-555-0100", c.Phone);
        Assert.AreEqual("data:image/png;base64,iVBORw0KGgo=", c.Photo);
    }

    [TestMethod]
    public void RemotePhotos_AndGroups_AreSkipped()
    {
        var cards = VCard.Parse("""
            BEGIN:VCARD
            VERSION:3.0
            FN:Tracked Person
            PHOTO;VALUE=uri:https://tracker.example/p.jpg
            END:VCARD
            BEGIN:VCARD
            VERSION:4.0
            KIND:group
            FN:Book club
            END:VCARD
            BEGIN:VCARD
            VERSION:3.0
            PHOTO;ENCODING=b;TYPE=JPEG:/9j/4AAQ
            EMAIL:only-email@example.org
            END:VCARD
            """);

        Assert.HasCount(2, cards);
        Assert.IsNull(cards[0].Photo);
        Assert.AreEqual("only-email@example.org", cards[1].FullName); // falls back to the address
        Assert.AreEqual("data:image/jpeg;base64,/9j/4AAQ", cards[1].Photo);
    }
}
