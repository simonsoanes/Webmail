// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using System.Globalization;
using System.Text;

namespace Nullify.WebMail.Services;

/// <summary>
/// Recursive MIME parser. Works on the raw message bytes (held as a Latin-1 string so
/// every byte survives) and decodes each text part with its declared charset. Part IDs
/// follow IMAP BODYSTRUCTURE numbering ("1", "2.1", ...).
/// </summary>
public static class MimeParser
{
    public static MimeParts Parse(byte[] raw) => Parse(Encoding.Latin1.GetString(raw));

    /// <summary>Parse a message held as a byte-preserving Latin-1 string.</summary>
    public static MimeParts Parse(string latin1Source)
    {
        var parts = new MimeParts();
        if (string.IsNullOrEmpty(latin1Source)) return parts;

        var (headers, body) = SplitEntity(latin1Source);
        parts.Headers = headers;
        Walk(parts, headers, body, "", isRoot: true);
        return parts;
    }

    private static void Walk(MimeParts parts, Dictionary<string, string> headers, string body, string partId, bool isRoot)
    {
        var (mediaType, ctParams) = ParseHeaderValue(headers.GetValueOrDefault("Content-Type", "text/plain"));
        mediaType = mediaType.ToLowerInvariant();
        if (mediaType.Length == 0) mediaType = "text/plain";

        if (mediaType.StartsWith("multipart/") && ctParams.TryGetValue("boundary", out var boundary) && boundary.Length > 0)
        {
            var children = SplitMultipart(body, boundary);
            var protocol = ctParams.GetValueOrDefault("protocol")?.ToLowerInvariant();

            // RFC 3156 PGP/MIME. Encrypted: the browser decrypts the second part; nothing to show yet.
            if (mediaType == "multipart/encrypted" && protocol == "application/pgp-encrypted" && children.Count >= 2)
            {
                var (_, encBody) = SplitEntity(children[1]);
                parts.PgpEncrypted ??= encBody; // ASCII armor
                return;
            }
            // Signed: keep the first part's exact bytes (they are what was signed) and the signature.
            if (mediaType == "multipart/signed" && protocol == "application/pgp-signature" && children.Count >= 2)
            {
                parts.PgpSignedEntity ??= children[0];
                var (sigHeaders, sigBody) = SplitEntity(children[1]);
                var sigEncoding = sigHeaders.GetValueOrDefault("Content-Transfer-Encoding", "").Trim().ToLowerInvariant();
                parts.PgpSignature ??= Encoding.ASCII.GetString(DecodeTransfer(sigBody, sigEncoding));
                var (h, b) = SplitEntity(children[0]);
                Walk(parts, h, b, partId.Length == 0 ? "1" : $"{partId}.1", isRoot: false);
                return;
            }
            for (var n = 0; n < children.Count; n++)
            {
                var childId = partId.Length == 0 ? (n + 1).ToString(CultureInfo.InvariantCulture) : $"{partId}.{n + 1}";
                var (h, b) = SplitEntity(children[n]);
                Walk(parts, h, b, childId, isRoot: false);
            }
            return;
        }

        // A single-part message's only part is "1" in IMAP numbering.
        var id = partId.Length == 0 ? "1" : partId;
        var (disposition, dispParams) = ParseHeaderValue(headers.GetValueOrDefault("Content-Disposition", ""));
        var filename = dispParams.GetValueOrDefault("filename") ?? ctParams.GetValueOrDefault("name");
        var encoding = headers.GetValueOrDefault("Content-Transfer-Encoding", "").Trim().ToLowerInvariant();
        var data = DecodeTransfer(body, encoding);
        var contentId = headers.GetValueOrDefault("Content-ID")?.Trim().Trim('<', '>');
        var isAttachment = disposition.Equals("attachment", StringComparison.OrdinalIgnoreCase);
        var isText = mediaType is "text/plain" or "text/html";

        if (isText && !isAttachment && (filename == null || isRoot))
        {
            var text = DecodeCharset(data, ctParams.GetValueOrDefault("charset"));
            if (mediaType == "text/html")
                parts.HtmlBody = parts.HtmlBody == null ? text : parts.HtmlBody + "<hr>" + text;
            else
                parts.TextBody = parts.TextBody == null ? text : parts.TextBody + "\n\n" + text;
            return;
        }

        if (mediaType == "message/rfc822" && filename == null) filename = "message.eml";
        filename ??= contentId != null ? contentId : $"part-{id}";
        var inline = !isAttachment && contentId != null && mediaType.StartsWith("image/");
        parts.Attachments.Add(new MimeAttachment(id, filename, mediaType, data, contentId, inline));
    }

    // ------------------------------------------------------------------ structure

    private static (Dictionary<string, string> Headers, string Body) SplitEntity(string entity)
    {
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var pos = 0;
        string? current = null;
        while (pos < entity.Length)
        {
            var nl = entity.IndexOf('\n', pos);
            var lineEnd = nl < 0 ? entity.Length : nl;
            var line = entity[pos..lineEnd].TrimEnd('\r');
            pos = nl < 0 ? entity.Length : nl + 1;
            if (line.Length == 0) break; // end of headers

            if ((line[0] == ' ' || line[0] == '\t') && current != null)
            {
                headers[current] += " " + line.Trim();
                continue;
            }
            var colon = line.IndexOf(':');
            if (colon <= 0) continue;
            current = line[..colon].Trim();
            var value = line[(colon + 1)..].Trim();
            // First occurrence wins (matches what mail clients display for duplicate headers).
            if (!headers.ContainsKey(current)) headers[current] = value;
            else current = null;
        }

        foreach (var key in headers.Keys.ToList())
            headers[key] = DecodeHeader(headers[key]);
        return (headers, pos < entity.Length ? entity[pos..] : "");
    }

    private static List<string> SplitMultipart(string body, string boundary)
    {
        var delim = "--" + boundary;
        var result = new List<string>();
        var lines = body.Split('\n');
        StringBuilder? current = null;
        foreach (var rawLine in lines)
        {
            var line = rawLine.TrimEnd('\r');
            if (line.StartsWith(delim, StringComparison.Ordinal))
            {
                var rest = line[delim.Length..].TrimEnd();
                if (current != null) result.Add(TrimFinalNewline(current));
                if (rest == "--") return result;
                if (rest.Length == 0) { current = new StringBuilder(); continue; }
            }
            current?.Append(rawLine).Append('\n');
        }
        if (current != null) result.Add(TrimFinalNewline(current));
        return result;
    }

    private static string TrimFinalNewline(StringBuilder sb)
    {
        // The CRLF before a boundary belongs to the boundary, not the part.
        var s = sb.ToString();
        if (s.EndsWith('\n')) s = s[..^1];
        if (s.EndsWith('\r')) s = s[..^1];
        return s;
    }

    // ------------------------------------------------------------------ decoding

    private static byte[] DecodeTransfer(string body, string encoding)
    {
        switch (encoding)
        {
            case "base64":
                var clean = new StringBuilder(body.Length);
                foreach (var c in body)
                    if (char.IsAsciiLetterOrDigit(c) || c is '+' or '/' or '=') clean.Append(c);
                // Tolerate missing padding.
                while (clean.Length % 4 != 0) clean.Append('=');
                try { return Convert.FromBase64String(clean.ToString()); }
                catch { return Encoding.Latin1.GetBytes(body); }
            case "quoted-printable":
                return DecodeQuotedPrintable(body);
            default:
                return Encoding.Latin1.GetBytes(body);
        }
    }

    private static byte[] DecodeQuotedPrintable(string input)
    {
        var ms = new MemoryStream(input.Length);
        for (var i = 0; i < input.Length; i++)
        {
            var c = input[i];
            if (c == '=')
            {
                if (i + 1 < input.Length && input[i + 1] == '\n') { i++; continue; }
                if (i + 2 < input.Length && input[i + 1] == '\r' && input[i + 2] == '\n') { i += 2; continue; }
                if (i + 2 < input.Length &&
                    byte.TryParse(input.AsSpan(i + 1, 2), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var b))
                {
                    ms.WriteByte(b);
                    i += 2;
                    continue;
                }
            }
            ms.WriteByte((byte)c);
        }
        return ms.ToArray();
    }

    public static string DecodeCharset(byte[] data, string? charset)
    {
        var enc = ResolveEncoding(charset);
        var text = enc.GetString(data);
        return text.Replace("\r\n", "\n");
    }

    private static Encoding ResolveEncoding(string? charset)
    {
        if (string.IsNullOrWhiteSpace(charset)) return Encoding.UTF8;
        var name = charset.Trim().Trim('"');
        // us-ascii mail is very often really UTF-8 or Latin-1; UTF-8 is a strict superset of ASCII.
        if (name.Equals("us-ascii", StringComparison.OrdinalIgnoreCase)) return Encoding.UTF8;
        try { return Encoding.GetEncoding(name); }
        catch { return Encoding.UTF8; }
    }

    /// <summary>Header values: raw 8-bit bytes are taken as UTF-8, then RFC 2047 words are decoded.</summary>
    private static string DecodeHeader(string latin1Value)
    {
        var utf8 = latin1Value.Any(c => c > 127)
            ? TryUtf8(Encoding.Latin1.GetBytes(latin1Value)) ?? latin1Value
            : latin1Value;
        return MimeText.Decode(utf8);
    }

    private static string? TryUtf8(byte[] bytes)
    {
        try { return new UTF8Encoding(false, true).GetString(bytes); }
        catch (DecoderFallbackException) { return null; }
    }

    /// <summary>Parse "type/subtype; a=b; c*=utf-8''x" into the value and its parameters (RFC 2045/2231).</summary>
    public static (string Value, Dictionary<string, string> Params) ParseHeaderValue(string header)
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var segments = SplitParams(header);
        var value = segments.Count > 0 ? segments[0].Trim() : "";
        var continuations = new SortedDictionary<string, SortedDictionary<int, (string Text, bool Encoded)>>(StringComparer.OrdinalIgnoreCase);

        foreach (var seg in segments.Skip(1))
        {
            var eq = seg.IndexOf('=');
            if (eq <= 0) continue;
            var key = seg[..eq].Trim();
            var val = seg[(eq + 1)..].Trim();
            if (val.Length >= 2 && val[0] == '"' && val[^1] == '"') val = val[1..^1].Replace("\\\"", "\"");

            var encoded = key.EndsWith('*');
            if (encoded) key = key[..^1];
            var star = key.IndexOf('*');
            if (star > 0 && int.TryParse(key[(star + 1)..], out var index))
            {
                var baseKey = key[..star];
                if (!continuations.TryGetValue(baseKey, out var pieces))
                    continuations[baseKey] = pieces = new SortedDictionary<int, (string, bool)>();
                pieces[index] = (val, encoded);
                continue;
            }
            result[key] = encoded ? DecodeRfc2231(val) : MimeText.Decode(val);
        }

        foreach (var (key, pieces) in continuations)
        {
            if (pieces.Values.Any(p => p.Encoded))
            {
                var joined = string.Concat(pieces.Values.Select(p => p.Text));
                result[key] = DecodeRfc2231(joined);
            }
            else
            {
                result[key] = MimeText.Decode(string.Concat(pieces.Values.Select(p => p.Text)));
            }
        }
        return (value, result);
    }

    private static List<string> SplitParams(string header)
    {
        var list = new List<string>();
        var sb = new StringBuilder();
        var quoted = false;
        for (var i = 0; i < header.Length; i++)
        {
            var c = header[i];
            if (c == '"' && (i == 0 || header[i - 1] != '\\')) quoted = !quoted;
            if (c == ';' && !quoted) { list.Add(sb.ToString()); sb.Clear(); continue; }
            sb.Append(c);
        }
        list.Add(sb.ToString());
        return list;
    }

    private static string DecodeRfc2231(string value)
    {
        // charset'language'percent-encoded
        var first = value.IndexOf('\'');
        var second = first >= 0 ? value.IndexOf('\'', first + 1) : -1;
        var charset = second > 0 ? value[..first] : "utf-8";
        var payload = second > 0 ? value[(second + 1)..] : value;
        var bytes = new List<byte>(payload.Length);
        for (var i = 0; i < payload.Length; i++)
        {
            if (payload[i] == '%' && i + 2 < payload.Length &&
                byte.TryParse(payload.AsSpan(i + 1, 2), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var b))
            {
                bytes.Add(b);
                i += 2;
            }
            else bytes.Add((byte)payload[i]);
        }
        return ResolveEncoding(charset).GetString(bytes.ToArray());
    }
}

public sealed class MimeParts
{
    public Dictionary<string, string> Headers { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    public string? TextBody { get; set; }
    public string? HtmlBody { get; set; }
    public List<MimeAttachment> Attachments { get; set; } = new();
    /// <summary>Armored body of a PGP/MIME multipart/encrypted message.</summary>
    public string? PgpEncrypted { get; set; }
    /// <summary>The signed part of a PGP/MIME multipart/signed message, byte-exact (Latin-1 string).</summary>
    public string? PgpSignedEntity { get; set; }
    public string? PgpSignature { get; set; }
}

public sealed record MimeAttachment(string PartId, string Filename, string ContentType, byte[] Data, string? ContentId, bool IsInline);
