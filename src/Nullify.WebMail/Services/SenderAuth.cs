// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using Nullify.WebMail.Shared;

namespace Nullify.WebMail.Services;

/// <summary>
/// Reads the DKIM/SPF/DMARC results the user's own mail server recorded for a message
/// (Authentication-Results, RFC 8601; Received-SPF, RFC 7208) and decides whether they vouch
/// for the From address the user sees.
///
/// Anyone can write those headers into a message they send, so position is what makes them
/// trustworthy. Each server prepends its headers, so everything above the hop where the
/// message arrived from the internet was written by the user's own servers, and everything
/// below it came from the sender. That hop is the topmost Received header whose client is a
/// public IP address; results are only read from above it. This relies on the server recording
/// the connecting IP in Received, which every mainstream MTA does; if it can't be found there
/// is no indicator at all, never a "verified" one.
///
/// Returns null (show nothing) for local mail, mail submitted by an authenticated user, and
/// servers that record no results, so the absence of headers is never shown as a failure
/// or a pass.
/// </summary>
public static partial class SenderAuth
{
    /// <param name="latin1Source">The raw message as a byte-preserving Latin-1 string.</param>
    /// <param name="trustedAuthServIds">
    /// The authserv-id(s) the user's server writes in Authentication-Results. When given, only
    /// those are trusted; otherwise the id must name one of the server's own Received hops.
    /// </param>
    public static SenderAuthInfo? Analyse(string latin1Source, IReadOnlyCollection<string>? trustedAuthServIds = null)
    {
        var headers = ReadHeaders(latin1Source);

        var ingress = headers.FindIndex(h => IsName(h, "Received") && ParseReceived(h.Value).HasPublicClient);
        if (ingress < 0) return null;
        if (ParseReceived(headers[ingress].Value).Authenticated) return null; // the user's own outgoing mail

        var serverHosts = headers.Take(ingress + 1)
            .Where(h => IsName(h, "Received"))
            .Select(h => ParseReceived(h.Value).By)
            .OfType<string>()
            .ToList();
        bool IsOurs(string id) => trustedAuthServIds is { Count: > 0 }
            ? trustedAuthServIds.Any(t => t.Trim().TrimEnd('.').Equals(id, StringComparison.OrdinalIgnoreCase))
            : serverHosts.Any(host => host == id || (id.Contains('.') && host.EndsWith("." + id, StringComparison.Ordinal)));

        var checks = new List<SenderAuthCheck>();
        var fromDomain = FromDomain(headers, out var fromProblem);
        for (var i = 0; i < ingress; i++)
        {
            if (IsName(headers[i], "Authentication-Results"))
            {
                if (ParseAuthResults(headers[i].Value) is { } ar && IsOurs(ar.Id))
                    checks.AddRange(ar.Results.Select(r => Check(r.Method, r.Result, r.Domain, fromDomain)));
            }
            else if (IsName(headers[i], "Received-SPF") && ParseReceivedSpf(headers[i].Value) is { } spf)
            {
                checks.Add(Check("spf", spf.Result, spf.Domain, fromDomain));
            }
        }
        if (checks.Count == 0) return null; // the server doesn't record results: say nothing either way
        checks = checks.Distinct().ToList();

        var problems = new List<string>();
        if (fromProblem != null) problems.Add(fromProblem);

        // A "pass" in our server's name below the point it received the message was written by
        // the sender. Only flagged when our server demonstrably writes its own results above.
        var forged = headers.Skip(ingress + 1).Any(h => IsName(h, "Authentication-Results")
            && ParseAuthResults(h.Value) is { } ar && IsOurs(ar.Id) && ar.Results.Any(r => r.Result == "pass"));
        if (forged)
            problems.Add("It contains authentication results that claim to come from your mail server but were added before your server received it, which is a sign of forgery.");

        if (fromDomain != null)
        {
            if (checks.Any(c => c.Method == "dmarc" && c.Result == "fail"))
                problems.Add($"It failed the DMARC policy published by {fromDomain}.");
            if (!checks.Any(c => c.Aligned))
            {
                var passedFor = checks.Where(c => c.Result == "pass" && c.Domain != null)
                    .Select(c => c.Domain!).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
                problems.Add(passedFor.Count > 0
                    ? $"It was only verified for {string.Join(", ", passedFor)}, not for {fromDomain}."
                    : $"Neither DKIM nor SPF passed for {fromDomain}.");
            }
        }

        return new SenderAuthInfo(problems.Count == 0 ? SenderAuthVerdict.Verified : SenderAuthVerdict.NotVerified,
            fromDomain, checks, problems);
    }

    private static SenderAuthCheck Check(string method, string result, string? domain, string? fromDomain) =>
        new(method, result, domain, result == "pass" && fromDomain != null && domain != null && Aligned(domain, fromDomain));

    /// <summary>
    /// Relaxed alignment (as DMARC uses): the same domain, or one a subdomain of the other.
    /// Without the Public Suffix List this is approximated by suffix matching, which can only
    /// over-match through a domain whose DNS the sender would have to control anyway.
    /// </summary>
    private static bool Aligned(string domain, string fromDomain) =>
        domain.Contains('.') && (domain == fromDomain
            || fromDomain.EndsWith("." + domain, StringComparison.Ordinal)
            || domain.EndsWith("." + fromDomain, StringComparison.Ordinal));

    /// <summary>The From domain the user is shown, or null with a reason if it can't be pinned down.</summary>
    private static string? FromDomain(List<(string Name, string Value)> headers, out string? problem)
    {
        problem = null;
        var froms = headers.Where(h => IsName(h, "From")).ToList();
        if (froms.Count != 1)
        {
            problem = froms.Count == 0 ? "It has no sender address." : "It has more than one From header, so the sender shown may not be the one that was checked.";
            return null;
        }
        var addresses = MailFormat.ParseAddressList(froms[0].Value);
        var at = addresses.Count == 1 ? addresses[0].Email.LastIndexOf('@') : -1;
        if (addresses.Count != 1 || at < 1)
        {
            problem = addresses.Count > 1 ? "It lists more than one sender address." : "Its sender address couldn't be read.";
            return null;
        }
        return NormaliseDomain(addresses[0].Email[(at + 1)..]);
    }

    // ------------------------------------------------------------------ header parsing

    private static bool IsName((string Name, string Value) h, string name) =>
        h.Name.Equals(name, StringComparison.OrdinalIgnoreCase);

    /// <summary>Top-level headers in order, unfolded, duplicates kept.</summary>
    internal static List<(string Name, string Value)> ReadHeaders(string source)
    {
        var list = new List<(string Name, string Value)>();
        var pos = 0;
        while (pos < source.Length)
        {
            var nl = source.IndexOf('\n', pos);
            var line = source[pos..(nl < 0 ? source.Length : nl)].TrimEnd('\r');
            pos = nl < 0 ? source.Length : nl + 1;
            if (line.Length == 0) break;
            if (line[0] is ' ' or '\t')
            {
                if (list.Count > 0) list[^1] = (list[^1].Name, list[^1].Value + " " + line.Trim());
                continue;
            }
            var colon = line.IndexOf(':');
            if (colon <= 0) continue;
            list.Add((line[..colon].Trim(), line[(colon + 1)..].Trim()));
        }
        return list;
    }

    internal sealed record ReceivedHop(string? By, bool HasPublicClient, bool Authenticated);

    /// <summary>Pull the "by" host, client IPs and protocol out of a Received header.</summary>
    internal static ReceivedHop ParseReceived(string value)
    {
        // Words outside comments, with their positions; stop at the date after ';'.
        var words = new List<(string Word, int Start, int End)>();
        int depth = 0, start = -1;
        for (var i = 0; i <= value.Length; i++)
        {
            var c = i < value.Length ? value[i] : ' ';
            if (depth > 0)
            {
                if (c == '\\') i++;
                else if (c == '(') depth++;
                else if (c == ')') depth--;
                continue;
            }
            if (c is ' ' or '\t' or '(' or ';')
            {
                if (start >= 0) { words.Add((value[start..i], start, i)); start = -1; }
                if (c == '(') depth++;
                if (c == ';') break;
            }
            else if (start < 0) start = i;
        }

        string? Next(string keyword)
        {
            var k = words.FindIndex(w => w.Word.Equals(keyword, StringComparison.OrdinalIgnoreCase));
            return k >= 0 && k + 1 < words.Count ? words[k + 1].Word : null;
        }

        var hasPublic = false;
        if (words.Count > 0 && words[0].Word.Equals("from", StringComparison.OrdinalIgnoreCase))
        {
            // The from clause runs to the next clause keyword and includes its comments,
            // which is where MTAs record the connecting address: "from helo (rdns [1.2.3.4])".
            var end = words.Skip(1).FirstOrDefault(w => ClauseKeywords.Contains(w.Word.ToLowerInvariant())).Start;
            var clause = value[words[0].End..(end > 0 ? end : value.Length)];
            hasPublic = clause.Split([' ', '\t', '(', ')', '[', ']', '=', ',', ';'], StringSplitOptions.RemoveEmptyEntries)
                .Any(t => ParseIp(t) is { } ip && IsPublic(ip));
        }
        var with = Next("with");
        return new ReceivedHop(Next("by") is { } by ? NormaliseDomain(by) : null, hasPublic,
            with != null && AuthenticatedProtocol().IsMatch(with));
    }

    private static readonly HashSet<string> ClauseKeywords = ["by", "via", "with", "id", "for"];

    /// <summary>RFC 3848 / 6531 "with" types that mean the client logged in (ESMTPA, ESMTPSA, LMTPA, ...).</summary>
    [GeneratedRegex(@"^(UTF8)?(E?SMTP|LMTP)S?A$", RegexOptions.IgnoreCase)]
    private static partial Regex AuthenticatedProtocol();

    [GeneratedRegex(@"^\d{1,3}(\.\d{1,3}){3}$")]
    private static partial Regex Ipv4Literal();

    private static IPAddress? ParseIp(string token)
    {
        if (token.StartsWith("IPv6:", StringComparison.OrdinalIgnoreCase)) token = token[5..];
        if (!Ipv4Literal().IsMatch(token) && token.Count(c => c == ':') < 2) return null; // "1" would parse as 0.0.0.1
        return IPAddress.TryParse(token, out var ip) ? ip : null;
    }

    /// <summary>True for addresses on the public internet (not loopback, private, link-local, CGNAT, ...).</summary>
    internal static bool IsPublic(IPAddress ip)
    {
        if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
        if (ip.AddressFamily == AddressFamily.InterNetwork)
        {
            var b = ip.GetAddressBytes();
            return !(b[0] is 0 or 10 or 127 || b[0] >= 224
                     || (b[0] == 169 && b[1] == 254)
                     || (b[0] == 172 && b[1] is >= 16 and <= 31)
                     || (b[0] == 192 && b[1] == 168)
                     || (b[0] == 192 && b[1] == 0 && b[2] == 0)
                     || (b[0] == 100 && b[1] is >= 64 and <= 127)
                     || (b[0] == 198 && b[1] is 18 or 19));
        }
        if (ip.AddressFamily != AddressFamily.InterNetworkV6) return false;
        return !(IPAddress.IsLoopback(ip) || ip.Equals(IPAddress.IPv6None) || ip.IsIPv6LinkLocal || ip.IsIPv6SiteLocal
                 || ip.IsIPv6UniqueLocal || ip.IsIPv6Multicast);
    }

    internal sealed record AuthResult(string Method, string Result, string? Domain);
    internal sealed record AuthResults(string Id, List<AuthResult> Results);

    /// <summary>Parse an Authentication-Results header into its authserv-id and DKIM/SPF/DMARC results.</summary>
    internal static AuthResults? ParseAuthResults(string value)
    {
        var parts = SplitOutsideQuotes(Normalise(value), ';');
        var idWords = parts[0].Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (idWords.Length == 0) return null;
        var results = new List<AuthResult>();
        foreach (var part in parts.Skip(1))
        {
            var tokens = SplitOutsideQuotes(part, ' ').Where(t => t.Length > 0).ToList();
            if (tokens.Count == 0 || !tokens[0].Contains('=')) continue; // "none"
            var method = tokens[0][..tokens[0].IndexOf('=')].Split('/')[0].ToLowerInvariant();
            var result = tokens[0][(tokens[0].IndexOf('=') + 1)..].ToLowerInvariant();
            var props = tokens.Skip(1).Where(t => t.Contains('='))
                .GroupBy(t => t[..t.IndexOf('=')].ToLowerInvariant())
                .ToDictionary(g => g.Key, g => g.First()[(g.First().IndexOf('=') + 1)..].Trim('"'));
            var domain = method switch
            {
                "dkim" => props.GetValueOrDefault("header.d") ?? props.GetValueOrDefault("header.i"),
                "spf" => props.GetValueOrDefault("smtp.mailfrom"),
                "dmarc" => props.GetValueOrDefault("header.from"),
                _ => null,
            };
            if (method is "dkim" or "spf" or "dmarc") results.Add(new AuthResult(method, result, DomainOf(domain)));
        }
        return new AuthResults(NormaliseDomain(idWords[0]), results);
    }

    internal sealed record SpfResult(string Result, string? Domain);

    /// <summary>
    /// Parse Received-SPF. Only the MAIL FROM identity can vouch for the sender, so a HELO
    /// result is kept for display with no domain to align against.
    /// </summary>
    internal static SpfResult? ParseReceivedSpf(string value)
    {
        var text = Normalise(value);
        var first = text.Split(' ', 2, StringSplitOptions.RemoveEmptyEntries);
        if (first.Length == 0) return null;
        var pairs = SplitOutsideQuotes(first.Length > 1 ? first[1] : "", ';')
            .SelectMany(p => SplitOutsideQuotes(p, ' '))
            .Where(t => t.Contains('='))
            .GroupBy(t => t[..t.IndexOf('=')].ToLowerInvariant())
            .ToDictionary(g => g.Key, g => g.First()[(g.First().IndexOf('=') + 1)..].Trim('"'));
        var identity = pairs.GetValueOrDefault("identity")?.ToLowerInvariant();
        var domain = identity is null or "mailfrom" ? DomainOf(pairs.GetValueOrDefault("envelope-from")) : null;
        return new SpfResult(first[0].ToLowerInvariant(), domain);
    }

    /// <summary>Drop comments (nested, with escapes) and the spaces around '='.</summary>
    private static string Normalise(string value)
    {
        var sb = new StringBuilder();
        int depth = 0;
        var quoted = false;
        for (var i = 0; i < value.Length; i++)
        {
            var c = value[i];
            if (c == '\\' && i + 1 < value.Length) { if (depth == 0) sb.Append(c).Append(value[i + 1]); i++; continue; }
            if (!quoted && c == '(') { depth++; continue; }
            if (!quoted && c == ')' && depth > 0) { depth--; if (depth == 0) sb.Append(' '); continue; }
            if (depth > 0) continue;
            if (c == '"') quoted = !quoted;
            sb.Append(c is '\t' or '\r' or '\n' ? ' ' : c);
        }
        return EqualsSpacing().Replace(sb.ToString(), "=").Trim();
    }

    [GeneratedRegex(@"\s*=\s*")]
    private static partial Regex EqualsSpacing();

    private static List<string> SplitOutsideQuotes(string s, char separator)
    {
        var list = new List<string>();
        var sb = new StringBuilder();
        var quoted = false;
        foreach (var c in s)
        {
            if (c == '"') quoted = !quoted;
            if (c == separator && !quoted) { list.Add(sb.ToString().Trim()); sb.Clear(); continue; }
            sb.Append(c);
        }
        list.Add(sb.ToString().Trim());
        return list;
    }

    /// <summary>"user@Example.COM" / "&lt;user@example.com&gt;" / "example.com." → "example.com".</summary>
    private static string? DomainOf(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return null;
        value = value.Trim().Trim('<', '>');
        var at = value.LastIndexOf('@');
        var domain = NormaliseDomain(at >= 0 ? value[(at + 1)..] : value);
        return domain.Length > 0 ? domain : null;
    }

    private static string NormaliseDomain(string domain) => domain.Trim().TrimEnd('.').ToLowerInvariant();
}
