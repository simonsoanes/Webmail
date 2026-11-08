// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using Microsoft.Extensions.Time.Testing;
using Nullify.WebMail.Services;
using Nullify.WebMail.Shared;

namespace Nullify.WebMail.Tests;

[TestClass]
public class ComposeHandoffTests
{
    private static ComposeHandoff.Draft Sample() => new(
        ComposeMode.Reply, "INBOX", 42, "me@example.test", "you@example.test", "", "", false, false,
        "Re: hello", "<div>hi</div>", false, "<a@example.test>", "<a@example.test>",
        [new OutgoingAttachment("a.png", "image/png", [1, 2, 3], "img1@webmail")], true, false, false);

    [TestMethod]
    public void Take_ReturnsTheDraftOnce()
    {
        var handoff = new ComposeHandoff(new FakeTimeProvider());
        var token = handoff.Put("me@example.test", Sample());

        var draft = handoff.Take("ME@example.test", token);
        Assert.IsNotNull(draft);
        Assert.AreEqual("Re: hello", draft.Subject);
        Assert.AreEqual(1, draft.Attachments.Count);
        Assert.IsNull(handoff.Take("me@example.test", token));
    }

    [TestMethod]
    public void Take_RefusesAnotherUser_AndLeavesItForTheOwner()
    {
        var handoff = new ComposeHandoff(new FakeTimeProvider());
        var token = handoff.Put("me@example.test", Sample());

        Assert.IsNull(handoff.Take("someone@example.test", token));
        Assert.IsNotNull(handoff.Take("me@example.test", token));
    }

    [TestMethod]
    public void Take_AfterLifetime_ReturnsNull()
    {
        var clock = new FakeTimeProvider();
        var handoff = new ComposeHandoff(clock);
        var token = handoff.Put("me@example.test", Sample());

        clock.Advance(ComposeHandoff.Lifetime + TimeSpan.FromSeconds(1));
        Assert.IsNull(handoff.Take("me@example.test", token));
    }

    [TestMethod]
    public void Put_GivesEachDraftItsOwnUrlSafeToken()
    {
        var handoff = new ComposeHandoff(new FakeTimeProvider());
        var a = handoff.Put("me@example.test", Sample());
        var b = handoff.Put("me@example.test", Sample());

        Assert.AreNotEqual(a, b);
        Assert.AreEqual(a, Uri.EscapeDataString(a));
    }
}
