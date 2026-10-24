// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using Nullify.WebMail.Services;
using Nullify.WebMail.Shared;

namespace Nullify.WebMail.Tests;

[TestClass]
public class RecipientSuggesterTests
{
    private static readonly List<RecipientCandidate> People = RecipientSuggester.FromContacts(
    [
        new ContactInfo("1", "Alice Chen", null, null, null)
        {
            Emails = [new("alice@example.org", "Work"), new("alice.home@example.net", "Home"), new("not-an-address", null)],
        },
        new ContactInfo("2", "Bob Builder", null, null, null) { Emails = [new("bob@example.org", null)] },
        new ContactInfo("3", "Malice Smith", null, null, null) { Emails = [new("ms@other.example", null)] },
        new ContactInfo("4", "Alice Duplicate", null, null, null) { Emails = [new("ALICE@example.org", null)] },
    ]);

    [TestMethod]
    public void FromContacts_FlattensEmails_DropsInvalidAndDuplicates() =>
        Assert.HasCount(4, People); // alice work+home, bob, ms — duplicate address and non-address dropped

    [TestMethod]
    public void Rank_NamePrefix_BeatsWordPrefix_BeatsSubstring()
    {
        var names = RecipientSuggester.Rank(People, "ali", []).Select(c => c.Email).ToList();
        // Both Alice addresses (name prefix) first; "Malice" only via substring.
        CollectionAssert.AreEqual(new[] { "alice@example.org", "alice.home@example.net", "ms@other.example" }, names);

        Assert.AreEqual("bob@example.org", RecipientSuggester.Rank(People, "build", []).Single().Email); // word prefix
        Assert.AreEqual("ms@other.example", RecipientSuggester.Rank(People, "@other", []).Single().Email); // domain
        Assert.IsEmpty(RecipientSuggester.Rank(People, "li", []).Where(c => c.Name == "Malice Smith")); // substrings need 3+ chars
    }

    [TestMethod]
    public void Rank_SkipsAddressesAlreadyInTheField() =>
        Assert.AreEqual("alice.home@example.net",
            RecipientSuggester.Rank(People, "alice", ["Alice@Example.org"]).First().Email);

    [TestMethod]
    public void CurrentToken_IsTheTextAfterTheLastUnquotedSeparator()
    {
        Assert.AreEqual(("", "al"), RecipientSuggester.CurrentToken("al"));
        Assert.AreEqual(("Bob <bob@example.org>,", "al"), RecipientSuggester.CurrentToken("Bob <bob@example.org>, al"));
        // A comma inside a quoted display name is not a separator.
        Assert.AreEqual(("", "\"Chen, Al"), RecipientSuggester.CurrentToken("\"Chen, Al"));
    }

    [TestMethod]
    public void Formatted_IsAValidAddressForTheField() =>
        Assert.AreEqual("Alice Chen <alice@example.org>", People[0].Formatted);
}
