// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using System.Globalization;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Text;
using System.Text.RegularExpressions;
using Nullify.WebMail.Shared;

namespace Nullify.WebMail.Services;

public sealed record ImapEndpoint(string Host, int Port, MailSecurity Security, bool AllowInvalidCertificates);

public enum ImapResult { Success, InvalidCredentials, Unavailable }

public sealed class ImapProtocolException(string message) : Exception(message);
public sealed class TlsException(string message) : Exception(message);

public sealed class ImapClient(ILogger<ImapClient> logger)
{
    public static readonly TimeSpan DefaultTimeout = TimeSpan.FromSeconds(30);

    public async Task<ImapSession> ConnectAndLoginAsync(
        ImapEndpoint endpoint, string login, string password, CancellationToken ct = default)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(DefaultTimeout);
        var session = await ImapSession.ConnectAsync(endpoint, logger, cts.Token);
        try
        {
            var result = await session.LoginAsync(login, password);
            if (result != ImapResult.Success)
            {
                await session.DisposeAsync();
                throw new ImapProtocolException("Login failed: " + result);
            }
            return session;
        }
        catch
        {
            await session.DisposeAsync();
            throw;
        }
    }

    public async Task<ImapResult> AuthenticateAsync(
        ImapEndpoint endpoint, string login, string password, CancellationToken ct = default)
    {
        try
        {
            await using var session = await ImapSession.ConnectAsync(endpoint, logger, ct);
            var result = await session.LoginAsync(login, password);
            await session.LogoutAsync();
            return result;
        }
        catch (Exception ex) when (ex is IOException or SocketException or TlsException
            or TimeoutException or OperationCanceledException or ImapProtocolException
            or AuthenticationException)
        {
            logger.LogWarning("IMAP auth {Host}:{Port} failed: {Msg}", endpoint.Host, endpoint.Port, ex.Message);
            return ImapResult.Unavailable;
        }
    }
}

public sealed partial class ImapSession : IAsyncDisposable
{
    private readonly TcpClient _tcp;
    private Stream _stream;
    private readonly CancellationTokenSource _cts;
    private readonly ILogger _logger;
    private int _tag;
    private readonly byte[] _buffer = new byte[16384];
    private int _bufferPos, _bufferLen;

    public HashSet<string> Capabilities { get; private set; } = new(StringComparer.OrdinalIgnoreCase);

    private ImapSession(TcpClient tcp, Stream stream, CancellationTokenSource cts, ILogger logger)
    {
        _tcp = tcp;
        _stream = stream;
        _cts = cts;
        _logger = logger;
    }

    public CancellationToken Ct => _cts.Token;

    public static async Task<ImapSession> ConnectAsync(ImapEndpoint ep, ILogger logger, CancellationToken ct = default)
    {
        using var connectCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        connectCts.CancelAfter(ImapClient.DefaultTimeout);
        var tcp = new TcpClient { NoDelay = true };
        var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        try
        {
            await tcp.ConnectAsync(ep.Host, ep.Port, connectCts.Token);
            Stream stream = tcp.GetStream();
            if (ep.Security == MailSecurity.Tls)
                stream = await UpgradeTlsAsync(stream, ep, connectCts.Token);

            var session = new ImapSession(tcp, stream, cts, logger);
            var greeting = await session.ReadLineAsync();
            if (greeting.StartsWith("* BYE", StringComparison.OrdinalIgnoreCase))
                throw new ImapProtocolException("Server refused connection: " + greeting);
            if (!greeting.StartsWith("* OK", StringComparison.OrdinalIgnoreCase)
                && !greeting.StartsWith("* PREAUTH", StringComparison.OrdinalIgnoreCase))
                throw new ImapProtocolException("Unexpected greeting: " + greeting);

            await session.RefreshCapabilitiesAsync();

            if (ep.Security == MailSecurity.StartTls)
            {
                if (!session.Capabilities.Contains("STARTTLS"))
                    throw new ImapProtocolException("STARTTLS not offered by server");
                var tlsResult = await session.RunAsync("STARTTLS");
                if (tlsResult.Status != "OK") throw new ImapProtocolException("STARTTLS failed: " + tlsResult.Text);
                session._stream = await UpgradeTlsAsync(session._stream, ep, connectCts.Token);
                session._bufferPos = session._bufferLen = 0;
                await session.RefreshCapabilitiesAsync();
            }
            return session;
        }
        catch
        {
            tcp.Dispose();
            cts.Dispose();
            throw;
        }
    }

    private static async Task<Stream> UpgradeTlsAsync(Stream inner, ImapEndpoint ep, CancellationToken ct)
    {
        var ssl = new SslStream(inner, leaveInnerStreamOpen: false,
            (_, _, _, errors) => errors == SslPolicyErrors.None || ep.AllowInvalidCertificates);
        try
        {
            await ssl.AuthenticateAsClientAsync(
                new SslClientAuthenticationOptions { TargetHost = ep.Host }, ct);
        }
        catch (System.Security.Authentication.AuthenticationException ex)
        {
            throw new TlsException("TLS handshake failed: " + ex.Message);
        }
        return ssl;
    }

    private async Task RefreshCapabilitiesAsync()
    {
        try
        {
            var result = await RunAsync("CAPABILITY");
            if (result.Status != "OK") return;
            var caps = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var line in result.Untagged)
            {
                if (line.StartsWith("* CAPABILITY", StringComparison.OrdinalIgnoreCase))
                    foreach (var c in line[12..].Split(' ', StringSplitOptions.RemoveEmptyEntries))
                        caps.Add(c);
            }
            Capabilities = caps;
        }
        catch (Exception ex)
        {
            _logger.LogDebug("CAPABILITY failed: {Msg}", ex.Message);
        }
    }

    // ------------------------------------------------------------------ auth

    public async Task<ImapResult> LoginAsync(string login, string password)
    {
        string status;
        if (Capabilities.Contains("AUTH=PLAIN"))
        {
            var tag = NextTag();
            await WriteAsync($"{tag} AUTHENTICATE PLAIN\r\n");
            var cont = await ReadLineAsync();
            if (!cont.StartsWith('+')) return Classify(ParseTagged(cont, tag).Status);
            var sasl = Convert.ToBase64String(Encoding.UTF8.GetBytes("\0" + login + "\0" + password));
            await WriteAsync(sasl + "\r\n");
            status = (await ReadTaggedAsync(tag)).Status;
        }
        else if (Capabilities.Contains("LOGINDISABLED"))
        {
            throw new ImapProtocolException("LOGIN is disabled — use TLS or STARTTLS");
        }
        else
        {
            var tag = NextTag();
            await WriteAsync($"{tag} LOGIN ");
            await WriteAStringAsync(login);
            await WriteAsync(" ");
            await WriteAStringAsync(password);
            await WriteAsync("\r\n");
            status = (await ReadTaggedAsync(tag)).Status;
        }
        return Classify(status);
    }

    public async Task LogoutAsync()
    {
        try { await RunAsync("LOGOUT"); } catch { /* best effort */ }
    }

    // ------------------------------------------------------------------ folders

    public Task<IReadOnlyList<FolderEntry>> ListFoldersAsync() => ListAsync("LIST");

    /// <summary>The folders the user is subscribed to (LSUB), by name.</summary>
    public async Task<HashSet<string>> ListSubscribedAsync() =>
        (await ListAsync("LSUB")).Select(f => f.Name).ToHashSet(StringComparer.Ordinal);

    private async Task<IReadOnlyList<FolderEntry>> ListAsync(string command)
    {
        var folders = new List<FolderEntry>();
        var result = await RunAsync($"{command} \"\" \"*\"");
        if (result.Status != "OK") throw new ImapProtocolException($"{command} failed: " + result.Text);

        foreach (var line in result.Untagged)
        {
            var m = ListRx().Match(line);
            if (!m.Success) continue;

            var attrs = m.Groups["attrs"].Value
                .Split(' ', StringSplitOptions.RemoveEmptyEntries)
                .Select(a => a.TrimStart('\\'))
                .ToHashSet(StringComparer.OrdinalIgnoreCase);

            var name = m.Groups["name"].Value.Trim();
            if (name.Length >= 2 && name[0] == '"' && name[^1] == '"') name = name[1..^1];
            name = ImapUtf7.Decode(name);

            var delim = m.Groups["qdelim"].Success ? m.Groups["qdelim"].Value
                : m.Groups["delim"].Value == "NIL" ? "" : m.Groups["delim"].Value;

            folders.Add(new FolderEntry(name, attrs, delim));
        }
        return folders;
    }

    [GeneratedRegex(@"^\* (?:LIST|LSUB) \((?<attrs>.*?)\) (?:""(?<qdelim>.)""|(?<delim>NIL|\S)) (?<name>.+)$", RegexOptions.IgnoreCase)]
    private static partial Regex ListRx();

    public async Task<SelectResult> SelectFolderAsync(string folderName)
    {
        int total = 0, recent = 0, unseen = 0;
        IReadOnlyList<string> defined = [], permanent = [];
        var result = await RunAsync($"SELECT \"{Mailbox(folderName)}\"", line =>
        {
            if (line.StartsWith("* FLAGS (", StringComparison.OrdinalIgnoreCase)) defined = FlagList(line, "* FLAGS (");
            if (line.Contains("[PERMANENTFLAGS (", StringComparison.OrdinalIgnoreCase)) permanent = FlagList(line, "[PERMANENTFLAGS (");
            var m = CountRx().Match(line);
            if (m.Success) total = int.Parse(m.Groups[1].Value);
            m = RecentRx().Match(line);
            if (m.Success) recent = int.Parse(m.Groups[1].Value);
            m = UnseenRx().Match(line);
            if (m.Success) unseen = int.Parse(m.Groups[1].Value);
        });
        if (result.Status != "OK") throw new ImapProtocolException($"SELECT {folderName} failed: {result.Status} {result.Text}");
        // "\*" in PERMANENTFLAGS: the client may create new keywords (tags) here.
        var keywords = defined.Concat(permanent).Where(f => !f.StartsWith('\\'))
            .Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        return new SelectResult(total, recent, unseen, keywords, permanent.Contains("\\*"));
    }

    /// <summary>The space-separated flags inside the parentheses that follow <paramref name="marker"/>.</summary>
    public static IReadOnlyList<string> FlagList(string line, string marker)
    {
        var start = line.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
        if (start < 0) return [];
        start += marker.Length;
        var end = line.IndexOf(')', start);
        if (end < 0) return [];
        return line[start..end].Split(' ', StringSplitOptions.RemoveEmptyEntries);
    }

    [GeneratedRegex(@"^\* (\d+) EXISTS", RegexOptions.IgnoreCase)]
    private static partial Regex CountRx();
    [GeneratedRegex(@"^\* (\d+) RECENT", RegexOptions.IgnoreCase)]
    private static partial Regex RecentRx();
    [GeneratedRegex(@"\[UNSEEN (\d+)\]", RegexOptions.IgnoreCase)]
    private static partial Regex UnseenRx();

    public async Task<(int Messages, int Unseen)> StatusAsync(string folderName)
    {
        var result = await RunAsync($"STATUS \"{Mailbox(folderName)}\" (MESSAGES UNSEEN)");
        foreach (var line in result.Untagged)
        {
            if (!line.StartsWith("* STATUS", StringComparison.OrdinalIgnoreCase)) continue;
            var mm = Regex.Match(line, @"MESSAGES\s+(\d+)", RegexOptions.IgnoreCase);
            var um = Regex.Match(line, @"UNSEEN\s+(\d+)", RegexOptions.IgnoreCase);
            return (mm.Success ? int.Parse(mm.Groups[1].Value) : 0,
                    um.Success ? int.Parse(um.Groups[1].Value) : 0);
        }
        return (0, 0);
    }

    public async Task CreateFolderAsync(string folderName)
    {
        var r = await RunAsync($"CREATE \"{Mailbox(folderName)}\"");
        if (r.Status != "OK") throw new ImapProtocolException($"CREATE failed: {r.Status} {r.Text}");
    }

    public async Task DeleteFolderAsync(string folderName)
    {
        var r = await RunAsync($"DELETE \"{Mailbox(folderName)}\"");
        if (r.Status != "OK") throw new ImapProtocolException($"DELETE failed: {r.Status} {r.Text}");
    }

    public async Task RenameFolderAsync(string oldName, string newName)
    {
        var r = await RunAsync($"RENAME \"{Mailbox(oldName)}\" \"{Mailbox(newName)}\"");
        if (r.Status != "OK") throw new ImapProtocolException($"RENAME failed: {r.Status} {r.Text}");
    }

    public async Task SubscribeAsync(string folderName, bool subscribe)
    {
        var command = subscribe ? "SUBSCRIBE" : "UNSUBSCRIBE";
        var r = await RunAsync($"{command} \"{Mailbox(folderName)}\"");
        if (r.Status != "OK") throw new ImapProtocolException($"{command} failed: {r.Status} {r.Text}");
    }

    /// <summary>Mark every message in the selected folder as read.</summary>
    public async Task MarkAllSeenAsync()
    {
        var r = await RunAsync("STORE 1:* +FLAGS.SILENT (\\Seen)");
        if (r.Status != "OK") throw new ImapProtocolException("STORE failed: " + r.Status + " " + r.Text);
    }

    // ------------------------------------------------------------------ messages

    private const string EnvelopeItems =
        "UID FLAGS INTERNALDATE RFC822.SIZE BODYSTRUCTURE BODY.PEEK[HEADER.FIELDS (FROM TO CC SUBJECT DATE MESSAGE-ID)]";

    /// <summary>Fetch envelopes for a page of a selected folder (newest first).</summary>
    public async Task<IReadOnlyList<MessageEnvelope>> FetchEnvelopesAsync(int totalMessages, int page, int pageSize)
    {
        if (totalMessages == 0) return Array.Empty<MessageEnvelope>();

        int end = totalMessages - page * pageSize;
        int start = end - pageSize + 1;
        if (end < 1) return Array.Empty<MessageEnvelope>();
        if (start < 1) start = 1;

        var result = await RunAsync($"FETCH {start}:{end} ({EnvelopeItems})");
        if (result.Status != "OK") throw new ImapProtocolException("FETCH failed: " + result.Status);

        var messages = ParseEnvelopes(result.Untagged);
        messages.Sort((a, b) => b.Uid.CompareTo(a.Uid)); // UI wants newest first
        return messages;
    }

    /// <summary>Fetch envelopes for specific UIDs of the selected folder (newest first).</summary>
    public async Task<IReadOnlyList<MessageEnvelope>> FetchEnvelopesByUidAsync(IReadOnlyCollection<long> uids)
    {
        if (uids.Count == 0) return Array.Empty<MessageEnvelope>();
        var result = await RunAsync($"UID FETCH {UidSet(uids)} ({EnvelopeItems})");
        if (result.Status != "OK") throw new ImapProtocolException("FETCH failed: " + result.Status);
        var messages = ParseEnvelopes(result.Untagged);
        messages.Sort((a, b) => b.Uid.CompareTo(a.Uid));
        return messages;
    }

    private static readonly string[] EnvelopeHeaders = ["From", "To", "Cc", "Subject", "Date", "Message-ID"];

    private static List<MessageEnvelope> ParseEnvelopes(IReadOnlyList<string> untagged)
    {
        var messages = new List<MessageEnvelope>();
        Dictionary<string, string>? current = null;
        string? lastKey = null;
        var inHeaders = false;

        foreach (var line in untagged)
        {
            if (FetchStartRx().IsMatch(line))
            {
                if (current != null) messages.Add(ParseEnvelope(current));
                current = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                lastKey = null;
                ScanFetchItems(line, current);
                inHeaders = line.TrimEnd().EndsWith('}');
                continue;
            }

            if (current == null) continue;

            if (!inHeaders)
            {
                // Items after the header literal, e.g. " BODYSTRUCTURE (...))" or " UID 12)".
                ScanFetchItems(line, current);
                continue;
            }

            // HEADER.FIELDS literals always end with an empty line.
            if (line.Length == 0) { inHeaders = false; continue; }
            if ((line[0] == ' ' || line[0] == '\t') && lastKey != null)
            {
                current[lastKey] += " " + line.Trim();
                continue;
            }
            var colon = line.IndexOf(':');
            if (colon > 0 && colon < 30)
            {
                var key = line[..colon].Trim();
                lastKey = EnvelopeHeaders.FirstOrDefault(h => h.Equals(key, StringComparison.OrdinalIgnoreCase));
                if (lastKey != null) current[lastKey] = line[(colon + 1)..].Trim();
            }
            else if (line.StartsWith(')')) inHeaders = false;
        }
        if (current != null) messages.Add(ParseEnvelope(current));
        return messages;
    }

    private static void ScanFetchItems(string line, Dictionary<string, string> current)
    {
        var fm = FlagsRx().Match(line);
        if (fm.Success && !current.ContainsKey("flags")) current["flags"] = fm.Groups[1].Value;
        var um = UidRx().Match(line);
        if (um.Success && !current.ContainsKey("uid")) current["uid"] = um.Groups[1].Value;
        var sm = SizeRx().Match(line);
        if (sm.Success && !current.ContainsKey("size")) current["size"] = sm.Groups[1].Value;
        // A PGP/MIME signature part is usually marked as an attachment; it isn't one to the reader.
        if (CountOf(line, "\"attachment\"") > (line.Contains("\"pgp-signature\"", StringComparison.OrdinalIgnoreCase) ? 1 : 0)) current["attach"] = "1";
    }

    private static int CountOf(string haystack, string needle)
    {
        var n = 0;
        for (var i = haystack.IndexOf(needle, StringComparison.OrdinalIgnoreCase); i >= 0; i = haystack.IndexOf(needle, i + needle.Length, StringComparison.OrdinalIgnoreCase)) n++;
        return n;
    }

    /// <summary>Compact IMAP UID set ("3:7,9,12").</summary>
    public static string UidSet(IEnumerable<long> uids)
    {
        var sorted = uids.Distinct().Order().ToList();
        var sb = new StringBuilder();
        for (var i = 0; i < sorted.Count; i++)
        {
            var runStart = sorted[i];
            while (i + 1 < sorted.Count && sorted[i + 1] == sorted[i] + 1) i++;
            if (sb.Length > 0) sb.Append(',');
            sb.Append(runStart.ToString(CultureInfo.InvariantCulture));
            if (sorted[i] != runStart) sb.Append(':').Append(sorted[i].ToString(CultureInfo.InvariantCulture));
        }
        return sb.ToString();
    }

    [GeneratedRegex(@"^\* \d+ (FETCH|EXPUNGE)")]
    private static partial Regex FetchStartRx();
    [GeneratedRegex(@"FLAGS \(([^)]*)\)")]
    private static partial Regex FlagsRx();
    [GeneratedRegex(@"UID (\d+)")]
    private static partial Regex UidRx();
    [GeneratedRegex(@"RFC822\.SIZE (\d+)")]
    private static partial Regex SizeRx();

    private static MessageEnvelope ParseEnvelope(Dictionary<string, string> f)
    {
        var flags = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var keywords = new List<string>();
        if (f.TryGetValue("flags", out var raw))
            foreach (var flag in raw.Split(' ', StringSplitOptions.RemoveEmptyEntries))
            {
                flags.Add(flag.TrimStart('\\'));
                if (!flag.StartsWith('\\')) keywords.Add(flag);
            }

        long.TryParse(f.GetValueOrDefault("uid", "0"), out var uid);
        long.TryParse(f.GetValueOrDefault("size", "0"), out var size);

        return new MessageEnvelope
        {
            Uid = uid,
            Subject = MimeText.Decode(f.GetValueOrDefault("Subject", "")),
            From = MimeText.Decode(f.GetValueOrDefault("From", "")),
            To = MimeText.Decode(f.GetValueOrDefault("To", "")),
            Date = f.GetValueOrDefault("Date", ""),
            Size = size,
            IsSeen = flags.Contains("Seen"),
            IsFlagged = flags.Contains("Flagged"),
            IsAnswered = flags.Contains("Answered"),
            IsDeleted = flags.Contains("Deleted"),
            IsDraft = flags.Contains("Draft"),
            HasAttachments = f.ContainsKey("attach"),
            Cc = MimeText.Decode(f.GetValueOrDefault("Cc", "")),
            MessageId = f.GetValueOrDefault("Message-ID", ""),
            Flags = flags,
            Keywords = keywords,
        };
    }

    /// <summary>Full RFC822 source of a message in the selected folder.</summary>
    public async Task<string> FetchMessageSourceAsync(long uid)
    {
        var bytes = await FetchLiteralAsync($"UID FETCH {uid} (BODY.PEEK[])");
        return Encoding.UTF8.GetString(bytes);
    }

    /// <summary>Raw bytes of a MIME body part (attachment-safe) in the selected folder.</summary>
    public Task<byte[]> FetchBodyPartAsync(long uid, string part) =>
        FetchLiteralAsync($"UID FETCH {uid} (BODY.PEEK[{part}])");

    /// <summary>
    /// Run a FETCH that returns a single literal and read exactly {N} bytes — immune to
    /// message bodies containing lines like ")" or non-UTF8 binary data.
    /// </summary>
    public async Task<byte[]> FetchLiteralAsync(string command)
    {
        var tag = NextTag();
        await WriteAsync($"{tag} {command}\r\n");
        while (true)
        {
            var line = await ReadLineAsync();
            if (line.StartsWith(tag + " ", StringComparison.Ordinal))
            {
                var parsed = ParseTagged(line, tag);
                if (parsed.Status != "OK")
                    throw new ImapProtocolException($"{command.Split(' ')[0]} failed: {parsed.Status} {parsed.Text}");
                return Array.Empty<byte>(); // e.g. UID not found
            }
            var m = LiteralRx().Match(line);
            if (m.Success)
            {
                var data = await ReadExactAsync(int.Parse(m.Groups[1].Value));
                await ReadUntilTagAsync(tag); // consume ")" and the tagged completion
                return data;
            }
        }
    }

    [GeneratedRegex(@"\{(\d+)\}\s*$")]
    private static partial Regex LiteralRx();

    private async Task ReadUntilTagAsync(string tag)
    {
        while (true)
        {
            var line = await ReadLineAsync();
            if (line.StartsWith(tag + " ", StringComparison.Ordinal)) return;
        }
    }

    public Task SetFlagsAsync(long uid, string addFlags, string removeFlags) =>
        SetFlagsAsync(uid.ToString(CultureInfo.InvariantCulture), addFlags, removeFlags);

    public async Task SetFlagsAsync(string uidSet, string addFlags, string removeFlags)
    {
        // Two STOREs: a single command carries only one flag operation.
        if (!string.IsNullOrEmpty(addFlags))
        {
            var r = await RunAsync($"UID STORE {uidSet} +FLAGS.SILENT ({addFlags})");
            if (r.Status != "OK") throw new ImapProtocolException("STORE failed: " + r.Status + " " + r.Text);
        }
        if (!string.IsNullOrEmpty(removeFlags))
        {
            var r = await RunAsync($"UID STORE {uidSet} -FLAGS.SILENT ({removeFlags})");
            if (r.Status != "OK") throw new ImapProtocolException("STORE failed: " + r.Status + " " + r.Text);
        }
    }

    public Task CopyMessageAsync(long uid, string destination) =>
        CopyMessagesAsync(uid.ToString(CultureInfo.InvariantCulture), destination);

    public async Task CopyMessagesAsync(string uidSet, string destination)
    {
        var r = await RunAsync($"UID COPY {uidSet} \"{Mailbox(destination)}\"");
        if (r.Status != "OK") throw new ImapProtocolException("COPY failed: " + r.Status + " " + r.Text);
    }

    public Task MoveMessageAsync(long uid, string destination) =>
        MoveMessagesAsync(uid.ToString(CultureInfo.InvariantCulture), destination);

    public async Task MoveMessagesAsync(string uidSet, string destination)
    {
        // Prefer MOVE (RFC 6851); fall back to COPY + flag-delete + expunge.
        if (Capabilities.Contains("MOVE"))
        {
            var r = await RunAsync($"UID MOVE {uidSet} \"{Mailbox(destination)}\"");
            if (r.Status == "OK") return;
            if (r.Status == "BAD") throw new ImapProtocolException("MOVE failed: " + r.Text);
            // NO → fall through to copy/delete
        }
        await CopyMessagesAsync(uidSet, destination);
        await ExpungeUidsAsync(uidSet);
    }

    /// <summary>Permanently remove a message. User deletes should move to Trash instead.</summary>
    public Task DeleteMessageAsync(long uid) => ExpungeUidsAsync(uid.ToString(CultureInfo.InvariantCulture));

    public async Task ExpungeUidsAsync(string uidSet)
    {
        await SetFlagsAsync(uidSet, "\\Deleted", "");
        // UID EXPUNGE (UIDPLUS) removes only these messages; a bare EXPUNGE also purges
        // anything another client already flagged \Deleted.
        var r = await RunAsync(Capabilities.Contains("UIDPLUS") ? $"UID EXPUNGE {uidSet}" : "EXPUNGE");
        if (r.Status != "OK") throw new ImapProtocolException("EXPUNGE failed: " + r.Status);
    }

    public async Task AppendMessageAsync(string folderName, string message, string flags = "\\Seen")
    {
        var bytes = Encoding.UTF8.GetBytes(message);
        var tag = NextTag();
        await WriteAsync($"{tag} APPEND \"{Mailbox(folderName)}\" ({flags}) {{{bytes.Length}}}\r\n");

        var cont = await ReadLineAsync();
        if (!cont.StartsWith('+'))
        {
            // Server refused the literal; recover the tagged response for the real error.
            CommandResult final;
            if (cont.StartsWith(tag + " ", StringComparison.Ordinal))
            {
                var parsed = ParseTagged(cont, tag);
                final = new CommandResult(parsed.Status, parsed.Text, Array.Empty<string>());
            }
            else
            {
                final = await ReadTaggedAsync(tag);
            }
            throw new ImapProtocolException($"APPEND refused: {final.Status} {final.Text}");
        }

        await _stream.WriteAsync(bytes, Ct);
        await WriteAsync("\r\n");
        var result = await ReadTaggedAsync(tag);
        if (result.Status != "OK") throw new ImapProtocolException($"APPEND failed: {result.Status} {result.Text}");
    }

    public async Task<IReadOnlyList<long>> SearchAsync(string criteria)
    {
        var r = await RunAsync($"UID SEARCH {criteria}");
        if (r.Status != "OK") throw new ImapProtocolException("SEARCH failed: " + r.Status);
        var uids = new List<long>();
        foreach (var line in r.Untagged)
        {
            if (!line.StartsWith("* SEARCH", StringComparison.OrdinalIgnoreCase)) continue;
            foreach (var token in line[8..].Split(' ', StringSplitOptions.RemoveEmptyEntries))
                if (long.TryParse(token, out var uid)) uids.Add(uid);
        }
        return uids;
    }

    // ------------------------------------------------------------------ IDLE

    /// <summary>
    /// Enter IDLE on the selected folder and wait for the first mailbox update.
    /// Returns null on timeout/cancellation; the caller should re-enter.
    /// </summary>
    public async Task<string?> IdleAsync(TimeSpan timeout, CancellationToken ct)
    {
        var tag = NextTag();
        await WriteAsync($"{tag} IDLE\r\n");
        var cont = await ReadLineAsync();
        if (!cont.StartsWith('+'))
            throw new ImapProtocolException("IDLE rejected: " + cont);

        try
        {
            using var idleCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            idleCts.CancelAfter(timeout);
            while (true)
            {
                string line;
                try { line = await ReadLineAsync(idleCts.Token); }
                catch (OperationCanceledException) when (!ct.IsCancellationRequested)
                {
                    return null; // keepalive timeout — caller re-enters IDLE
                }
                if (line.StartsWith("* ", StringComparison.Ordinal))
                    return line; // EXISTS / EXPUNGE / FETCH — something changed
            }
        }
        finally
        {
            try
            {
                await WriteAsync("DONE\r\n");
                await ReadTaggedAsync(tag);
            }
            catch (Exception ex)
            {
                _logger.LogDebug("IDLE DONE failed: {Msg}", ex.Message);
                if (!ct.IsCancellationRequested)
                    throw new IOException("IDLE connection lost", ex);
            }
        }
    }

    public async Task NoopAsync()
    {
        var r = await RunAsync("NOOP");
        if (r.Status != "OK") throw new ImapProtocolException("NOOP failed: " + r.Status);
    }

    // ------------------------------------------------------------------ protocol plumbing

    private string NextTag() => "N" + Interlocked.Increment(ref _tag).ToString("D4", CultureInfo.InvariantCulture);

    internal async Task<CommandResult> RunAsync(string command, Action<string>? onUntagged = null)
    {
        var tag = NextTag();
        await WriteAsync($"{tag} {command}\r\n");
        return await ReadTaggedAsync(tag, onUntagged);
    }

    private async Task<CommandResult> ReadTaggedAsync(string tag, Action<string>? onUntagged = null)
    {
        var lines = new List<string>();
        while (true)
        {
            var line = await ReadLineAsync();
            if (line.StartsWith(tag + " ", StringComparison.Ordinal))
            {
                var parsed = ParseTagged(line, tag);
                return new CommandResult(parsed.Status, parsed.Text, lines);
            }
            lines.Add(line);
            onUntagged?.Invoke(line);
        }
    }

    private static (string Status, string Text) ParseTagged(string line, string tag)
    {
        var rest = line[(tag.Length + 1)..];
        var space = rest.IndexOf(' ');
        return space < 0
            ? (rest.ToUpperInvariant(), "")
            : (rest[..space].ToUpperInvariant(), rest[(space + 1)..]);
    }

    private static ImapResult Classify(string status) => status switch
    {
        "OK" => ImapResult.Success,
        "NO" => ImapResult.InvalidCredentials,
        "BAD" => throw new ImapProtocolException("Auth command rejected: BAD"),
        "PREAUTH" => ImapResult.Success,
        _ => throw new ImapProtocolException("Unexpected auth status: " + status),
    };

    private async Task WriteAStringAsync(string value)
    {
        // Non-ASCII or control characters require a literal; otherwise quote.
        if (value.All(c => c >= 32 && c <= 126) && !value.Contains('"') && !value.Contains('\\'))
        {
            await WriteAsync("\"" + value + "\"");
            return;
        }
        var bytes = Encoding.UTF8.GetBytes(value);
        await WriteAsync("{" + bytes.Length + "}\r\n");
        var cont = await ReadLineAsync();
        if (!cont.StartsWith('+')) throw new ImapProtocolException("Literal rejected: " + cont);
        await _stream.WriteAsync(bytes, Ct);
        await _stream.FlushAsync(Ct);
    }

    private async Task WriteAsync(string text)
    {
        await _stream.WriteAsync(Encoding.UTF8.GetBytes(text), Ct);
        await _stream.FlushAsync(Ct);
    }

    private async Task<string> ReadLineAsync(CancellationToken? ct = null)
    {
        var token = ct ?? Ct;
        var line = new List<byte>(128);
        while (true)
        {
            if (_bufferPos >= _bufferLen)
            {
                _bufferLen = await _stream.ReadAsync(_buffer, token);
                _bufferPos = 0;
                if (_bufferLen == 0) throw new IOException("IMAP connection closed by server");
            }
            var b = _buffer[_bufferPos++];
            if (b == '\n')
            {
                if (line.Count > 0 && line[^1] == '\r') line.RemoveAt(line.Count - 1);
                return Encoding.UTF8.GetString(line.ToArray());
            }
            line.Add(b);
            if (line.Count > 65536) throw new ImapProtocolException("Protocol line too long");
        }
    }

    private async Task<byte[]> ReadExactAsync(int count)
    {
        var data = new byte[count];
        var copied = 0;
        if (_bufferPos < _bufferLen)
        {
            var take = Math.Min(count, _bufferLen - _bufferPos);
            Array.Copy(_buffer, _bufferPos, data, 0, take);
            _bufferPos += take;
            copied = take;
        }
        while (copied < count)
        {
            var read = await _stream.ReadAsync(data.AsMemory(copied, count - copied), Ct);
            if (read == 0) throw new IOException("IMAP connection closed during literal read");
            copied += read;
        }
        return data;
    }

    private static string Mailbox(string name) => Escape(ImapUtf7.Encode(name));

    private static string Escape(string s) => s.Replace("\\", "\\\\").Replace("\"", "\\\"");

    public async ValueTask DisposeAsync()
    {
        try { _cts.Cancel(); } catch { }
        try { await _stream.DisposeAsync(); } catch { }
        _tcp.Dispose();
        _cts.Dispose();
    }
}

// ------------------------------------------------------------------ shared types

public sealed record CommandResult(string Status, string Text, IReadOnlyList<string> Untagged);

public sealed record FolderEntry(string Name, HashSet<string> Attributes, string Delimiter);

/// <param name="Keywords">Keywords (tags) the server lists for this folder.</param>
/// <param name="CanCreateKeywords">The server accepts new keywords here (PERMANENTFLAGS includes "\*").</param>
public sealed record SelectResult(int Total, int Recent, int Unseen,
    IReadOnlyList<string>? Keywords = null, bool CanCreateKeywords = false);

public sealed record MessageEnvelope
{
    public long Uid { get; init; }
    public string Subject { get; init; } = "";
    public string From { get; init; } = "";
    public string To { get; init; } = "";
    public string Date { get; init; } = "";
    public long Size { get; init; }
    public bool IsSeen { get; init; }
    public bool IsFlagged { get; init; }
    public bool IsAnswered { get; init; }
    public bool IsDeleted { get; init; }
    public bool IsDraft { get; init; }
    public bool HasAttachments { get; init; }
    public string Cc { get; init; } = "";
    public string MessageId { get; init; } = "";
    public HashSet<string> Flags { get; init; } = new();
    /// <summary>Non-system flags as stored (IMAP keywords: tags set by this or another client).</summary>
    public IReadOnlyList<string> Keywords { get; init; } = [];
}

/// <summary>RFC 2047 encoded-word decoding and IMAP modified UTF-7 (RFC 3501 §5.1.3).</summary>
public static partial class MimeText
{
    public static string Decode(string raw)
    {
        if (string.IsNullOrEmpty(raw) || !raw.Contains("=?")) return raw;
        // RFC 2047 6.2: whitespace between adjacent encoded words is not displayed.
        raw = AdjacentWordsRx().Replace(raw, "?==?");
        return EncodedWordRx().Replace(raw, m =>
        {
            try
            {
                var charset = m.Groups[1].Value;
                var encoding = m.Groups[2].Value;
                var payload = m.Groups[3].Value;
                var bytes = encoding.Equals("B", StringComparison.OrdinalIgnoreCase)
                    ? Convert.FromBase64String(payload)
                    : QDecode(payload);
                var enc = charset.Equals("utf-8", StringComparison.OrdinalIgnoreCase)
                    ? Encoding.UTF8
                    : Encoding.GetEncoding(charset);
                return enc.GetString(bytes);
            }
            catch
            {
                return m.Value;
            }
        });
    }

    [System.Text.RegularExpressions.GeneratedRegex(@"=\?([^?]+)\?([BbQq])\?([^?]*)\?=")]
    private static partial System.Text.RegularExpressions.Regex EncodedWordRx();

    [System.Text.RegularExpressions.GeneratedRegex(@"\?=\s+=\?")]
    private static partial System.Text.RegularExpressions.Regex AdjacentWordsRx();

    private static byte[] QDecode(string input)
    {
        var ms = new MemoryStream();
        for (var i = 0; i < input.Length; i++)
        {
            if (input[i] == '_') ms.WriteByte((byte)' ');
            else if (input[i] == '=' && i + 2 < input.Length
                     && byte.TryParse(input.AsSpan(i + 1, 2), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var b))
            {
                ms.WriteByte(b);
                i += 2;
            }
            else ms.WriteByte((byte)input[i]);
        }
        return ms.ToArray();
    }
}

public static class ImapUtf7
{
    public static string Encode(string input)
    {
        if (input.All(c => c >= 0x20 && c <= 0x7e && c != '&')) return input;
        var sb = new StringBuilder();
        var pending = new StringBuilder();
        void Flush()
        {
            if (pending.Length == 0) return;
            var b64 = Convert.ToBase64String(Encoding.BigEndianUnicode.GetBytes(pending.ToString()))
                .TrimEnd('=').Replace('/', ',');
            sb.Append('&').Append(b64).Append('-');
            pending.Clear();
        }
        foreach (var c in input)
        {
            if (c >= 0x20 && c <= 0x7e)
            {
                Flush();
                sb.Append(c == '&' ? "&-" : c.ToString());
            }
            else pending.Append(c);
        }
        Flush();
        return sb.ToString();
    }

    public static string Decode(string input)
    {
        if (!input.Contains('&')) return input;
        var sb = new StringBuilder();
        for (var i = 0; i < input.Length; i++)
        {
            if (input[i] != '&') { sb.Append(input[i]); continue; }
            var end = input.IndexOf('-', i + 1);
            if (end < 0) { sb.Append(input[i]); continue; }
            var b64 = input[(i + 1)..end];
            if (b64.Length == 0) { sb.Append('&'); i = end; continue; }
            try
            {
                var modified = b64.Replace(',', '/');
                switch (modified.Length % 4)
                {
                    case 2: modified += "=="; break;
                    case 3: modified += "="; break;
                }
                var bytes = Convert.FromBase64String(modified);
                // Modified UTF-7 is UTF-16BE
                sb.Append(Encoding.BigEndianUnicode.GetString(bytes));
            }
            catch
            {
                sb.Append(input[i..(end + 1)]);
            }
            i = end;
        }
        return sb.ToString();
    }
}