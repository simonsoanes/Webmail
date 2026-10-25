// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Nullify.WebMail.Data;
using Nullify.WebMail.Services;
using Nullify.WebMail.Shared;

namespace Nullify.WebMail.Tests;

/// <summary>Tags (IMAP keywords), folder order and subscriptions, and sender identities.</summary>
[TestClass]
public class MailOrganisationTests
{
    // ---- tags ----

    [TestMethod]
    public void SelectResponse_FlagLists_AreRead()
    {
        CollectionAssert.AreEqual(new[] { "\\Seen", "$label1", "Work" },
            ImapSession.FlagList("* FLAGS (\\Seen $label1 Work)", "* FLAGS (").ToArray());
        CollectionAssert.AreEqual(new[] { "\\Seen", "\\*" },
            ImapSession.FlagList("* OK [PERMANENTFLAGS (\\Seen \\*)] Flags permitted.", "[PERMANENTFLAGS (").ToArray());
        Assert.IsEmpty(ImapSession.FlagList("* OK [UIDVALIDITY 1]", "[PERMANENTFLAGS ("));
    }

    [TestMethod]
    public void Tags_HideSystemKeywords()
    {
        var tags = MailTags.Tags(["$Forwarded", "$MDNSent", "NonJunk", "$Junk", "Work", "$label2", "\\Seen"]).ToList();
        CollectionAssert.AreEqual(new[] { "Work", "$label2" }, tags);
    }

    [TestMethod]
    public void Tags_LabelsMatchOtherClients()
    {
        Assert.AreEqual("Important", MailTags.Label("$label1"));
        Assert.AreEqual("To Do", MailTags.Label("$label4"));
        Assert.AreEqual("Blue Tag", MailTags.Label("Blue_Tag"));
        Assert.AreEqual("Café", MailTags.Label("Caf&AOk-"));
    }

    [TestMethod]
    public void Tags_NewNames_BecomeValidKeywords()
    {
        Assert.AreEqual("Blue_Tag", MailTags.ToKeyword(" Blue Tag "));
        Assert.AreEqual("Caf&AOk-", MailTags.ToKeyword("Café"));
        Assert.AreEqual("a_b_c_d", MailTags.ToKeyword("a(b)c\"d"));
        Assert.IsNull(MailTags.ToKeyword("   "));
        Assert.IsNull(MailTags.ToKeyword("$Forwarded"));
        foreach (var name in new[] { "Blue Tag", "Café", "x{y}%z*", "Ünïcødé tag" })
            Assert.IsTrue(MailTags.IsValidKeyword(MailTags.ToKeyword(name)!), name);
        Assert.IsFalse(MailTags.IsValidKeyword("two words"));
        Assert.IsFalse(MailTags.IsValidKeyword("\\Seen"));
    }

    [TestMethod]
    public void Tags_ColourComesFromTheName()
    {
        Assert.AreEqual(MailTags.Color("Blue_Tag"), MailTags.Color("blue"));
        Assert.AreNotEqual(MailTags.Color("Blue_Tag"), MailTags.Color("Red_Tag"));
        Assert.AreEqual(MailTags.Color("Newsletter"), MailTags.Color("Newsletter"), "stable for other names");
    }

    // ---- folder order ----

    private static FolderInfo F(string name, string? use = null) => new(name, "", 0, 0, ".", use);

    private static readonly FolderInfo[] Folders =
    [
        F("INBOX", "Inbox"), F("Trash", "Trash"), F("Sent", "Sent"), F("Zeta"), F("Alpha"), F("Alpha.Child2"), F("Alpha.Child1"),
    ];

    private static string[] Names(IEnumerable<FolderInfo> folders) => folders.Select(f => f.Name).ToArray();

    [TestMethod]
    public void OrderFolders_Default_SpecialFirst_ThenTree()
    {
        CollectionAssert.AreEqual(new[] { "INBOX", "Sent", "Trash", "Alpha", "Alpha.Child1", "Alpha.Child2", "Zeta" },
            Names(MailFormat.OrderFolders(Folders)));
    }

    [TestMethod]
    public void MoveFolder_ReordersSiblings_AndKeepsChildrenWithParent()
    {
        var order = MailFormat.MoveFolder(Folders, [], "Zeta", "INBOX", after: false)!;
        CollectionAssert.AreEqual(new[] { "Zeta", "INBOX", "Sent", "Trash", "Alpha", "Alpha.Child1", "Alpha.Child2" },
            Names(MailFormat.OrderFolders(Folders, order)));

        order = MailFormat.MoveFolder(Folders, order, "Alpha", "Zeta", after: false)!;
        CollectionAssert.AreEqual(new[] { "Alpha", "Alpha.Child1", "Alpha.Child2", "Zeta", "INBOX", "Sent", "Trash" },
            Names(MailFormat.OrderFolders(Folders, order)));

        order = MailFormat.MoveFolder(Folders, order, "Alpha.Child1", "Alpha.Child2", after: true)!;
        CollectionAssert.AreEqual(new[] { "Alpha", "Alpha.Child2", "Alpha.Child1", "Zeta", "INBOX", "Sent", "Trash" },
            Names(MailFormat.OrderFolders(Folders, order)));
    }

    [TestMethod]
    public void MoveFolder_RefusesDifferentLevels() =>
        Assert.IsNull(MailFormat.MoveFolder(Folders, [], "Alpha.Child1", "Zeta", after: false));

    [TestMethod]
    public void OrderFolders_InboxChildren_AreTopLevel()
    {
        FolderInfo[] dovecot = [F("INBOX", "Inbox"), F("INBOX.Work"), F("INBOX.Sent", "Sent"), F("INBOX.Work.Q3")];
        CollectionAssert.AreEqual(new[] { "INBOX", "INBOX.Sent", "INBOX.Work", "INBOX.Work.Q3" }, Names(MailFormat.OrderFolders(dovecot)));
        Assert.IsNotNull(MailFormat.MoveFolder(dovecot, [], "INBOX.Work", "INBOX", after: false));
    }

    // ---- identities ----

    private sealed class Factory(DbContextOptions<AppDbContext> options) : IDbContextFactory<AppDbContext>
    {
        public AppDbContext CreateDbContext() => new(options);
    }

    private static async Task<(IdentityService Service, SqliteConnection Connection)> IdentitiesAsync()
    {
        var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync();
        var options = new DbContextOptionsBuilder<AppDbContext>().UseSqlite(connection).Options;
        await using (var db = new AppDbContext(options))
        {
            await db.Database.EnsureCreatedAsync();
            db.Users.Add(new User { Username = "jo@example.org", Email = "jo@example.org" });
            db.Domains.Add(new Domain { Name = "example.org" });
            db.Domains.Add(new Domain { Name = "closed.example" });
            await db.SaveChangesAsync();
        }
        return (new IdentityService(new Factory(options), new WriteGate()), connection);
    }

    [TestMethod]
    public async Task Aliases_OnlyAtDomainsTheAdminAllows()
    {
        var (identities, connection) = await IdentitiesAsync();
        await using var _ = connection;
        const string login = "jo@example.org";

        await Assert.ThrowsExactlyAsync<InvalidOperationException>(() => identities.SaveAliasAsync(login, "Sales", "sales@example.org"));

        await identities.SetDomainAllowsAliasesAsync("example.org", true);
        await identities.SaveAliasAsync(login, "Sales Team", "sales@example.org");
        await Assert.ThrowsExactlyAsync<InvalidOperationException>(() => identities.SaveAliasAsync(login, "x", "x@closed.example"));
        await Assert.ThrowsExactlyAsync<InvalidOperationException>(() => identities.SaveAliasAsync(login, "x", "not an address"));

        await identities.SetDisplayNameAsync(login, "Jo \"Boss\" Bloggs\r\n");
        var senders = await identities.SendersAsync(login);
        CollectionAssert.AreEqual(new[] { "Jo Boss Bloggs <jo@example.org>", "Sales Team <sales@example.org>" },
            senders.Select(s => s.ToString()).ToArray());

        // Renaming keeps one alias per address; turning the domain off stops sending from it.
        await identities.SaveAliasAsync(login, "Sales", "SALES@example.org");
        Assert.HasCount(1, (await identities.GetAsync(login)).Aliases);
        await identities.SetDomainAllowsAliasesAsync("example.org", false);
        Assert.HasCount(1, await identities.SendersAsync(login));

        await identities.RemoveAliasAsync(login, "sales@example.org");
        Assert.IsEmpty((await identities.GetAsync(login)).Aliases);
    }

    [TestMethod]
    public async Task ResolveFrom_AcceptsOnlyTheUsersOwnAddresses()
    {
        var (identities, connection) = await IdentitiesAsync();
        await using var _ = connection;
        const string login = "jo@example.org";
        await identities.SetDomainAllowsAliasesAsync("example.org", true);
        await identities.SaveAliasAsync(login, "Help Desk", "help@example.org");
        await identities.SetDisplayNameAsync(login, "Jo");

        Assert.AreEqual("Jo <jo@example.org>", await identities.ResolveFromAsync(login, null));
        // The stored name is used, whatever name the request carries.
        Assert.AreEqual("Help Desk <help@example.org>", await identities.ResolveFromAsync(login, "\"CEO\" <help@example.org>"));
        await Assert.ThrowsExactlyAsync<UnauthorizedAccessException>(() => identities.ResolveFromAsync(login, "Jo <ceo@example.org>"));
    }
}
