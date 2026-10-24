// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using Nullify.WebMail.Services;

namespace Nullify.WebMail.Tests;

[TestClass]
public class SieveRuleTests
{
    private static List<SieveRule> ParseOk(string script)
    {
        var result = SieveRuleParser.Parse(script);
        Assert.IsNull(result.Error, result.Error);
        return result.Rules!;
    }

    [TestMethod]
    public void RoundTrips_EveryConditionAndAction()
    {
        List<SieveRule> rules =
        [
            new()
            {
                Name = "Newsletters", MatchAll = false, Stop = true,
                Conditions =
                [
                    new() { Field = SieveField.From, Op = SieveOp.EndsWith, Values = ["@news.example.org", "*odd?"] },
                    new() { Field = SieveField.ListId, Op = SieveOp.Exists },
                    new() { Field = SieveField.Subject, Op = SieveOp.Contains, Negate = true, Values = ["Re: \"quoted\" \\ back"] },
                    new() { Field = SieveField.Header, HeaderName = "X-Spam, X-Junk", Op = SieveOp.Regex, Values = ["^yes"] },
                    new() { Field = SieveField.Size, Op = SieveOp.Under, Values = ["10M"] },
                    new() { Field = SieveField.Body, Op = SieveOp.Matches, Values = ["*unsubscribe*"] },
                    new() { Field = SieveField.ToOrCc, Op = SieveOp.StartsWith, Values = ["team"] },
                ],
                Actions =
                [
                    new() { Kind = SieveActionKind.FileInto, Argument = "INBOX.News" },
                    new() { Kind = SieveActionKind.CopyTo, Argument = "Archive" },
                    new() { Kind = SieveActionKind.MarkRead },
                    new() { Kind = SieveActionKind.Flag },
                    new() { Kind = SieveActionKind.AddFlag, Argument = "$Label1" },
                    new() { Kind = SieveActionKind.RedirectCopy, Argument = "me@example.org" },
                ],
            },
            new()
            {
                Name = "Away", Enabled = false,
                Actions = [new() { Kind = SieveActionKind.Vacation, VacationDays = 3, VacationSubject = "Out", Argument = "Back Monday.\nOK then." }],
            },
            new()
            {
                Enabled = false,
                Conditions = [new() { Field = SieveField.To, Op = SieveOp.Is, Values = ["x@example.org"] },
                              new() { Field = SieveField.Cc, Op = SieveOp.Is, Values = ["y@example.org"] }],
                Actions = [new() { Kind = SieveActionKind.Reject, Argument = "No" }, new() { Kind = SieveActionKind.Discard }],
            },
        ];

        var script = SieveRuleWriter.Write(rules);
        StringAssert.Contains(script, "require [\"body\", \"copy\", \"fileinto\", \"imap4flags\", \"regex\", \"reject\", \"vacation\"];");
        var result = SieveRuleParser.Parse(script);
        Assert.IsNull(result.Error, result.Error);
        Assert.IsFalse(result.DropsComments);
        // Writing the parsed rules again must give the identical script.
        Assert.AreEqual(script, SieveRuleWriter.Write(result.Rules!));

        var r = result.Rules!;
        Assert.HasCount(3, r);
        Assert.AreEqual("Newsletters", r[0].Name);
        Assert.IsFalse(r[0].MatchAll);
        Assert.IsTrue(r[0].Stop);
        Assert.AreEqual(SieveOp.EndsWith, r[0].Conditions[0].Op);
        CollectionAssert.AreEqual(new[] { "@news.example.org", "*odd?" }, r[0].Conditions[0].Values);
        Assert.AreEqual("Re: \"quoted\" \\ back", r[0].Conditions[2].Values[0]);
        Assert.IsTrue(r[0].Conditions[2].Negate);
        Assert.AreEqual(SieveOp.StartsWith, r[0].Conditions[6].Op);
        Assert.IsFalse(r[1].Enabled);
        Assert.AreEqual("Back Monday.\nOK then.", r[1].Actions[0].Argument);
        Assert.IsFalse(r[2].Enabled);
        Assert.HasCount(2, r[2].Conditions);
    }

    [TestMethod]
    public void Parses_HandWrittenScript()
    {
        var rules = ParseOk("""
            require ["fileinto", "imap4flags"];
            /* not a rule name */
            if address :comparator "i;ascii-casemap" :domain :is "from" "example.com" {
                fileinto "Example";
            }
            if header :contains "Subject" "[SPAM]" { addflag ["\\Seen", "\\Flagged"]; stop; }
            if true { keep; }
            """);
        Assert.HasCount(3, rules);
        Assert.AreEqual(":domain", rules[0].Conditions[0].AddressPart);
        Assert.AreEqual(SieveField.Subject, rules[1].Conditions[0].Field);
        Assert.AreEqual(SieveActionKind.MarkRead, rules[1].Actions[0].Kind);
        Assert.AreEqual(SieveActionKind.Flag, rules[1].Actions[1].Kind);
        Assert.IsTrue(rules[1].Stop);
        Assert.IsEmpty(rules[2].Conditions);
        Assert.IsTrue(SieveRuleParser.Parse("# hello\nif true { keep; }").DropsComments);
    }

    [TestMethod]
    public void Parses_RoundcubeScript()
    {
        var rules = ParseOk("""
            require ["fileinto","vacation"];
            ## Generated by RoundCube Webmail
            # rule:[Lists]
            if false # anyof (header :contains "list-id" "dev", address :is "to" "dev@example.org")
            {
            	fileinto "Lists";
            }
            # rule:[Holiday]
            if true
            {
            	vacation :days 1 :subject "Away" text:
            Gone fishing.
            ..dot line
            .
            ;
            }
            """);
        Assert.HasCount(2, rules);
        Assert.AreEqual("Lists", rules[0].Name);
        Assert.IsFalse(rules[0].Enabled);
        Assert.IsFalse(rules[0].MatchAll);
        Assert.HasCount(2, rules[0].Conditions);
        Assert.AreEqual(SieveField.ListId, rules[0].Conditions[0].Field);
        Assert.AreEqual("Gone fishing.\n.dot line\n", rules[1].Actions[0].Argument);
        Assert.AreEqual(1, rules[1].Actions[0].VacationDays);
    }

    [TestMethod]
    [DataRow("if envelope :is \"from\" \"x\" { keep; }")]
    [DataRow("if true { keep; } else { discard; }")]
    [DataRow("fileinto \"x\";")]
    [DataRow("if true { if true { keep; } }")]
    [DataRow("if true { stop; keep; }")]
    [DataRow("if header :is :comparator \"i;octet\" \"x\" \"y\" { keep; }")]
    [DataRow("if true { keep; ")]
    [DataRow("if header :is \"x\" \"unterminated { keep; }")]
    public void Rejects_ScriptsTheEditorCannotRepresent(string script)
    {
        var result = SieveRuleParser.Parse(script);
        Assert.IsNull(result.Rules);
        Assert.IsNotNull(result.Error);
    }

    [TestMethod]
    public void Wildcard_MatchesStaysMatches()
    {
        var rules = ParseOk("if header :matches \"subject\" \"a*b\" { keep; }");
        Assert.AreEqual(SieveOp.Matches, rules[0].Conditions[0].Op);
        rules = ParseOk("if header :matches \"subject\" \"lit\\\\*eral*\" { keep; }");
        Assert.AreEqual(SieveOp.StartsWith, rules[0].Conditions[0].Op);
        Assert.AreEqual("lit*eral", rules[0].Conditions[0].Values[0]);
    }
}
