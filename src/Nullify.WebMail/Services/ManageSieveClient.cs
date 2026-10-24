// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Text;
using Nullify.WebMail.Shared;

namespace Nullify.WebMail.Services;

public sealed class ManageSieveClient(ILogger<ManageSieveClient> logger)
{
    public static readonly TimeSpan DefaultTimeout = TimeSpan.FromSeconds(20);

    public async Task<ManageSieveSession> ConnectAndLoginAsync(
        SieveEndpoint endpoint, string login, string password, CancellationToken ct = default)
    {
        // connectCts bounds the handshake only; the session lives on the caller's
        // token (a disposed CTS token would poison every later read).
        using var connectCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        connectCts.CancelAfter(DefaultTimeout);
        var tcp = new TcpClient { NoDelay = true };
        try
        {
            await tcp.ConnectAsync(endpoint.Host, endpoint.Port, connectCts.Token);
            Stream stream = tcp.GetStream();
            if (endpoint.Security == MailSecurity.Tls)
                stream = await UpgradeTlsAsync(stream, endpoint, connectCts.Token);

            var session = new ManageSieveSession(tcp, stream, ct);

            // Greeting is a capability block: quoted strings ending with OK (or NO on STARTTLS-first servers).
            var greeting = await session.ReadResponseAsync();
            if (greeting.StartsWith("NO", StringComparison.OrdinalIgnoreCase))
                throw new SieveException("Server refused: " + greeting);

            if (endpoint.Security == MailSecurity.StartTls)
            {
                await session.SendCommandAsync("STARTTLS");
                var resp = await session.ReadResponseAsync();
                if (!resp.StartsWith("OK", StringComparison.OrdinalIgnoreCase))
                    throw new SieveException("STARTTLS failed: " + resp);
                var ssl = await UpgradeTlsAsync(session.Stream, endpoint, connectCts.Token);
                session.ReplaceStream(ssl);
                await session.ReadResponseAsync(); // re-read capability block
            }

            var sasl = Convert.ToBase64String(Encoding.UTF8.GetBytes("\0" + login + "\0" + password));
            await session.SendCommandAsync($"AUTHENTICATE \"PLAIN\" \"{sasl}\"");
            var authResp = await session.ReadResponseAsync();
            if (!authResp.StartsWith("OK", StringComparison.OrdinalIgnoreCase))
                throw new SieveException("Sieve authentication failed: " + authResp);

            return session;
        }
        catch (Exception ex)
        {
            logger.LogWarning("ManageSieve {Host}:{Port} failed: {Msg}", endpoint.Host, endpoint.Port, ex.Message);
            tcp.Dispose();
            throw;
        }
    }

    private static async Task<SslStream> UpgradeTlsAsync(Stream inner, SieveEndpoint ep, CancellationToken ct)
    {
        var ssl = new SslStream(inner, leaveInnerStreamOpen: false,
            (_, _, _, errors) => errors == SslPolicyErrors.None || ep.AllowInvalidCertificates);
        try
        {
            await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions { TargetHost = ep.Host }, ct);
        }
        catch (AuthenticationException ex)
        {
            throw new SieveException("Sieve TLS handshake failed: " + ex.Message, ex);
        }
        return ssl;
    }
}

public sealed class ManageSieveSession : IAsyncDisposable
{
    private readonly TcpClient _tcp;
    private readonly CancellationToken _ct;
    private readonly byte[] _buffer = new byte[8192];
    private int _bufferPos, _bufferLen;

    public Stream Stream { get; private set; }

    internal ManageSieveSession(TcpClient tcp, Stream stream, CancellationToken ct)
    {
        _tcp = tcp;
        Stream = stream;
        _ct = ct;
    }

    internal void ReplaceStream(Stream newStream)
    {
        Stream = newStream;
        _bufferPos = _bufferLen = 0;
    }

    public async Task<IReadOnlyList<SieveScriptInfo>> ListScriptsAsync()
    {
        await SendCommandAsync("LISTSCRIPTS");
        var lines = await ReadLinesUntilOkAsync();
        var scripts = new List<SieveScriptInfo>();
        foreach (var line in lines)
        {
            // Format: "name" [ACTIVE]
            if (!line.StartsWith('"')) continue;
            var end = line.IndexOf('"', 1);
            if (end < 0) continue;
            var name = line[1..end];
            var isActive = line[end..].Contains("ACTIVE", StringComparison.OrdinalIgnoreCase);
            scripts.Add(new SieveScriptInfo(name, isActive));
        }
        return scripts;
    }

    public async Task<string> GetScriptAsync(string name)
    {
        await SendCommandAsync($"GETSCRIPT \"{Escape(name)}\"");
        // Response: {N} literal, exactly N bytes of script, CRLF, then OK.
        var marker = await ReadLineAsync();
        if (marker.StartsWith("NO", StringComparison.OrdinalIgnoreCase))
            throw new SieveException("GETSCRIPT failed: " + marker);
        var m = System.Text.RegularExpressions.Regex.Match(marker, @"^\{(\d+)\+?\}$");
        if (!m.Success || !int.TryParse(m.Groups[1].Value, out var size) || size > 16 * 1024 * 1024)
            throw new SieveException("GETSCRIPT: unexpected response: " + marker);
        var content = Encoding.UTF8.GetString(await ReadBytesAsync(size));
        await ReadResponseAsync(); // trailing CRLF, then OK
        return content;
    }

    public async Task PutScriptAsync(string name, string content)
    {
        var bytes = Encoding.UTF8.GetBytes(content);
        // RFC 5804 client literals are non-synchronising ({N+}): the script follows at once.
        await Stream.WriteAsync(Encoding.UTF8.GetBytes($"PUTSCRIPT \"{Escape(name)}\" {{{bytes.Length}+}}\r\n"), _ct);
        await Stream.WriteAsync(bytes, _ct);
        await Stream.WriteAsync("\r\n"u8.ToArray(), _ct);
        await Stream.FlushAsync(_ct);
        var resp = await ReadResponseAsync();
        if (!resp.StartsWith("OK", StringComparison.OrdinalIgnoreCase))
            throw new SieveException("PUTSCRIPT failed: " + resp);
    }

    public async Task DeleteScriptAsync(string name)
    {
        await SendCommandAsync($"DELETESCRIPT \"{Escape(name)}\"");
        var resp = await ReadResponseAsync();
        if (!resp.StartsWith("OK", StringComparison.OrdinalIgnoreCase))
            throw new SieveException("DELETESCRIPT failed: " + resp);
    }

    public async Task SetActiveAsync(string name)
    {
        await SendCommandAsync($"SETACTIVE \"{Escape(name)}\"");
        var resp = await ReadResponseAsync();
        if (!resp.StartsWith("OK", StringComparison.OrdinalIgnoreCase))
            throw new SieveException("SETACTIVE failed: " + resp);
    }

    public async Task LogoutAsync()
    {
        try
        {
            await SendCommandAsync("LOGOUT");
            await ReadResponseAsync();
        }
        catch { /* best effort */ }
    }

    internal async Task SendCommandAsync(string command)
    {
        await Stream.WriteAsync(Encoding.UTF8.GetBytes(command + "\r\n"), _ct);
        await Stream.FlushAsync(_ct);
    }

    /// <summary>Read lines until an OK/NO/BYE terminator; returns the non-terminator lines.</summary>
    internal async Task<List<string>> ReadLinesUntilOkAsync()
    {
        var lines = new List<string>();
        while (true)
        {
            var line = await ReadLineAsync();
            if (line.StartsWith("OK", StringComparison.OrdinalIgnoreCase)) return lines;
            if (line.StartsWith("NO", StringComparison.OrdinalIgnoreCase)
                || line.StartsWith("BYE", StringComparison.OrdinalIgnoreCase))
                throw new SieveException("Sieve command failed: " + line);
            lines.Add(line);
        }
    }

    internal async Task<string> ReadResponseAsync()
    {
        var lines = await ReadLinesUntilOkAsync();
        return "OK";
    }

    internal async Task<string> ReadLineAsync()
    {
        var line = new List<byte>(128);
        while (true)
        {
            if (_bufferPos >= _bufferLen)
            {
                _bufferLen = await Stream.ReadAsync(_buffer, _ct);
                _bufferPos = 0;
                if (_bufferLen == 0) throw new IOException("Sieve connection closed by server");
            }
            var b = _buffer[_bufferPos++];
            if (b == '\n')
            {
                if (line.Count > 0 && line[^1] == '\r') line.RemoveAt(line.Count - 1);
                return Encoding.UTF8.GetString(line.ToArray());
            }
            line.Add(b);
            if (line.Count > 65536) throw new SieveException("Sieve protocol line too long");
        }
    }

    private async Task<byte[]> ReadBytesAsync(int count)
    {
        var result = new byte[count];
        var filled = 0;
        while (filled < count)
        {
            if (_bufferPos >= _bufferLen)
            {
                _bufferLen = await Stream.ReadAsync(_buffer, _ct);
                _bufferPos = 0;
                if (_bufferLen == 0) throw new IOException("Sieve connection closed by server");
            }
            var n = Math.Min(count - filled, _bufferLen - _bufferPos);
            Array.Copy(_buffer, _bufferPos, result, filled, n);
            _bufferPos += n;
            filled += n;
        }
        return result;
    }

    private static string Escape(string s) => s.Replace("\\", "\\\\").Replace("\"", "\\\"");

    public async ValueTask DisposeAsync()
    {
        try { await Stream.DisposeAsync(); } catch { }
        _tcp.Dispose();
    }
}

public sealed record SieveEndpoint(string Host, int Port, MailSecurity Security, bool AllowInvalidCertificates)
{
    // RFC 5804 defines no implicit-TLS port: ManageSieve (4190) greets in plaintext and upgrades via STARTTLS.
    public static SieveEndpoint For(string host, int port) => new(host, port, MailSecurity.StartTls, false);
}

public sealed record SieveScriptInfo(string Name, bool IsActive);

public sealed class SieveException(string message, Exception? inner = null) : Exception(message, inner);