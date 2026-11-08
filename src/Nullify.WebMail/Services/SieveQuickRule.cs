// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using System.Text.RegularExpressions;

namespace Nullify.WebMail.Services;

/// <summary>How a quick rule picks out the sender.</summary>
public enum SenderMatch { Address, Domain }

/// <summary>
/// A filter made from one message ("mail like this"): match its sender and/or subject, then move
/// it, mark it read and/or star it. Turned into a <see cref="SieveRule"/> and added to the end of
/// the user's active Sieve script.
/// </summary>
public sealed class SieveQuickRule
{
    public bool UseSender { get; set; }
    public SenderMatch SenderMatch { get; set; } = SenderMatch.Address;
    public string Sender { get; set; } = "";

    public bool UseSubject { get; set; }
    public string Subject { get; set; } = "";

    /// <summary>Folder to move matching mail to; null leaves it where it lands.</summary>
    public string? MoveTo { get; set; }
    public bool MarkRead { get; set; }
    public bool Flag { get; set; }

    public string Name { get; set; } = "";

    /// <summary>Start from a message: its sender's address and its subject without Re:/Fwd: prefixes.</summary>
    public static SieveQuickRule From(string fromHeader, string subject)
    {
        var sender = MailFormat.ParseAddress(fromHeader).Email;
        var clean = CleanSubject(subject);
        return new SieveQuickRule
        {
            UseSender = sender.Length > 0,
            Sender = sender,
            UseSubject = sender.Length == 0 && clean.Length > 0,
            Subject = clean,
        };
    }

    public static string CleanSubject(string subject) =>
        Regex.Replace(subject ?? "", @"^\s*((re|fwd?|aw|sv|antw)\s*(\[\d+\])?\s*:\s*)+", "", RegexOptions.IgnoreCase).Trim();

    /// <summary>The domain part of an address, or the text as typed when it's already a domain.</summary>
    public static string DomainOf(string sender)
    {
        var at = sender.LastIndexOf('@');
        return (at >= 0 ? sender[(at + 1)..] : sender).Trim();
    }

    private string SenderValue => SenderMatch == SenderMatch.Domain ? DomainOf(Sender) : Sender.Trim();

    /// <summary>Why it can't be saved yet; null when it can.</summary>
    public string? Problem()
    {
        if (!UseSender && !UseSubject) return "Choose the sender, the subject, or both.";
        if (UseSender && SenderValue.Length == 0) return "Enter the sender to match.";
        if (UseSubject && Subject.Trim().Length == 0) return "Enter the subject text to match.";
        if (MoveTo == null && !MarkRead && !Flag) return "Choose at least one thing to do with matching mail.";
        return null;
    }

    public string DefaultName()
    {
        var parts = new List<string>();
        if (UseSender && SenderValue.Length > 0) parts.Add($"From {SenderValue}");
        if (UseSubject && Subject.Trim().Length > 0) parts.Add($"Subject \"{Subject.Trim()}\"");
        return parts.Count > 0 ? string.Join(", ", parts) : "New rule";
    }

    public SieveRule ToRule()
    {
        var rule = new SieveRule
        {
            Name = Name.Trim().Length > 0 ? Name.Trim() : DefaultName(),
            MatchAll = true,
        };
        if (UseSender)
            rule.Conditions.Add(new SieveCondition
            {
                Field = SieveField.From,
                Op = SieveOp.Is,
                AddressPart = SenderMatch == SenderMatch.Domain ? ":domain" : null,
                Values = [SenderValue],
            });
        if (UseSubject)
            rule.Conditions.Add(new SieveCondition { Field = SieveField.Subject, Op = SieveOp.Contains, Values = [Subject.Trim()] });
        // Flags first, so they're set on the copy that gets filed.
        if (MarkRead) rule.Actions.Add(new SieveAction { Kind = SieveActionKind.MarkRead });
        if (Flag) rule.Actions.Add(new SieveAction { Kind = SieveActionKind.Flag });
        if (MoveTo != null)
        {
            rule.Actions.Add(new SieveAction { Kind = SieveActionKind.FileInto, Argument = MoveTo });
            rule.Stop = true; // filed away: later rules shouldn't act on it again
        }
        return rule;
    }
}

/// <summary>Adding a rule to an existing script, keeping the rest as the rule editor would.</summary>
public static class SieveScriptEdit
{
    /// <param name="Script">The new script text; null when it couldn't be made.</param>
    /// <param name="Error">Why the script can't be edited as rules.</param>
    /// <param name="DropsComments">Saving loses comments the user wrote in the script.</param>
    public sealed record AppendResult(string? Script, string? Error, bool DropsComments);

    public static AppendResult Append(string? existing, SieveRule rule)
    {
        var parsed = string.IsNullOrWhiteSpace(existing) ? new SieveParseResult([], null) : SieveRuleParser.Parse(existing);
        if (parsed.Rules == null) return new AppendResult(null, parsed.Error ?? "The script can't be read as rules.", false);
        var rules = parsed.Rules.Append(rule).ToList();
        return new AppendResult(SieveRuleWriter.Write(rules), null, parsed.DropsComments);
    }
}

public enum SieveRuleOutcome { Added, NeedsCommentsDropped, Unreadable }

/// <param name="Script">The script the rule went (or would go) into.</param>
/// <param name="Created">The script was new, and has been made the active one.</param>
public sealed record SieveRuleSaveResult(SieveRuleOutcome Outcome, string Script, string? Error = null, bool Created = false);
