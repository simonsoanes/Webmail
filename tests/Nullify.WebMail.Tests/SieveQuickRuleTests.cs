// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using Nullify.WebMail.Services;

namespace Nullify.WebMail.Tests;

[TestClass]
public class SieveQuickRuleTests
{
    [TestMethod]
    public void From_StartsWithTheSenderAddress_AndACleanSubject()
    {
        var rule = SieveQuickRule.From("\"News Desk\" <News@Example.org>", "Re: Fwd: AW: Weekly digest");
        Assert.IsTrue(rule.UseSender);
        Assert.IsFalse(rule.UseSubject);
        Assert.AreEqual("News@Example.org", rule.Sender);
        Assert.AreEqual("Weekly digest", rule.Subject);
    }

    [TestMethod]
    public void ToRule_SenderAndSubject_MovesAndStops_WithFlagsFirst()
    {
        var quick = SieveQuickRule.From("a@news.example.org", "Digest");
        quick.UseSubject = true;
        quick.MoveTo = "Archive/News";
        quick.MarkRead = true;

        var script = SieveRuleWriter.Write([quick.ToRule()]);

        StringAssert.Contains(script, "require [\"fileinto\", \"imap4flags\"];");
        StringAssert.Contains(script, "# rule:[From a@news.example.org, Subject \"Digest\"]");
        StringAssert.Contains(script, "if allof (address :is \"from\" \"a@news.example.org\", header :contains \"subject\" \"Digest\")");
        Assert.IsTrue(script.IndexOf("addflag", StringComparison.Ordinal) < script.IndexOf("fileinto \"Archive/News\"", StringComparison.Ordinal));
        StringAssert.Contains(script, "    stop;");
    }

    [TestMethod]
    public void ToRule_Domain_MatchesTheDomainPart()
    {
        var quick = SieveQuickRule.From("someone@lists.example.org", "x");
        quick.SenderMatch = SenderMatch.Domain;
        quick.Flag = true;

        var script = SieveRuleWriter.Write([quick.ToRule()]);
        StringAssert.Contains(script, "if address :domain :is \"from\" \"lists.example.org\"");
        Assert.IsFalse(script.Contains("stop;"));
    }

    [TestMethod]
    public void Problem_NeedsAMatchAndAnAction()
    {
        var quick = new SieveQuickRule { MarkRead = true };
        Assert.IsNotNull(quick.Problem());
        quick.UseSubject = true;
        quick.Subject = "  ";
        Assert.IsNotNull(quick.Problem());
        quick.Subject = "invoice";
        Assert.IsNull(quick.Problem());
        quick.MarkRead = false;
        Assert.IsNotNull(quick.Problem());
    }

    [TestMethod]
    public void Append_KeepsExistingRules_AndRoundTrips()
    {
        var first = new SieveQuickRule { UseSubject = true, Subject = "one", MarkRead = true }.ToRule();
        var existing = SieveRuleWriter.Write([first]);
        var second = new SieveQuickRule { UseSender = true, Sender = "b@example.org", MoveTo = "Junk" }.ToRule();

        var result = SieveScriptEdit.Append(existing, second);
        Assert.IsNull(result.Error);
        Assert.IsFalse(result.DropsComments);
        var rules = SieveRuleParser.Parse(result.Script!).Rules!;
        Assert.AreEqual(2, rules.Count);
        Assert.AreEqual("Subject \"one\"", rules[0].Name);
        Assert.AreEqual("From b@example.org", rules[1].Name);
    }

    [TestMethod]
    public void Append_ToNothing_MakesANewScript()
    {
        var rule = new SieveQuickRule { UseSender = true, Sender = "c@example.org", Flag = true }.ToRule();
        var result = SieveScriptEdit.Append(null, rule);
        StringAssert.StartsWith(result.Script!, SieveRuleWriter.Header);
    }

    [TestMethod]
    public void Append_ReportsCommentsThatWouldBeLost()
    {
        var result = SieveScriptEdit.Append("# hello\nif true { keep; }", new SieveQuickRule { UseSubject = true, Subject = "y", Flag = true }.ToRule());
        Assert.IsTrue(result.DropsComments);
        Assert.IsNotNull(result.Script);
    }

    [TestMethod]
    public void Append_RefusesAScriptItCannotRead()
    {
        var result = SieveScriptEdit.Append("if this is not sieve {", new SieveQuickRule { UseSubject = true, Subject = "y", Flag = true }.ToRule());
        Assert.IsNull(result.Script);
        Assert.IsNotNull(result.Error);
    }

    [TestMethod]
    public void EmlFileName_IsSafe()
    {
        Assert.AreEqual("Re Q3 report draft v2.eml", MailFormat.EmlFileName("Re: Q3 report / draft? v2."));
        Assert.AreEqual("message.eml", MailFormat.EmlFileName("  \t "));
        Assert.AreEqual("message.eml", MailFormat.EmlFileName(null));
        Assert.IsTrue(MailFormat.EmlFileName(new string('a', 300)).Length <= 124);
    }
}
