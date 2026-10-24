// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Text;
using Nullify.WebMail.Shared;

namespace Nullify.WebMail.Services;

public sealed class SmtpClient(ILogger<SmtpClient> logger)
{
    public static readonly TimeSpan DefaultTimeout = TimeSpan.FromSeconds(60);

    public async Task SendAsync(SmtpEndpoint endpoint, string login, string password,
        string from, IReadOnlyList<string> to, string message, CancellationToken ct = default)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(DefaultTimeout);
        using var tcp = new TcpClient { NoDelay = true };
        try
        {
            await tcp.ConnectAsync(endpoint.Host, endpoint.Port, cts.Token);
            Stream stream = tcp.GetStream();
            if (endpoint.Security == MailSecurity.Tls)
                stream = await UpgradeTlsAsync(stream, endpoint, cts.Token);

            // Readers and writers leave the stream open: STARTTLS replaces them while the socket must survive.
            var reader = new StreamReader(stream, Encoding.ASCII, leaveOpen: true);
            var writer = NewWriter(stream);

            try
            {
                var greeting = await ReadResponseAsync(reader, cts.Token);
                if (!greeting.StartsWith("220"))
                    throw new SmtpException("Unexpected greeting: " + FirstLine(greeting));

                await SendCommandAsync(writer, reader, $"EHLO {Dns.GetHostName()}", cts.Token, "250");

                if (endpoint.Security == MailSecurity.StartTls)
                {
                    await SendCommandAsync(writer, reader, "STARTTLS", cts.Token, "220");
                    var ssl = await UpgradeTlsAsync(stream, endpoint, cts.Token);
                    reader.Dispose();
                    await writer.DisposeAsync();
                    stream = ssl;
                    reader = new StreamReader(stream, Encoding.ASCII, leaveOpen: true);
                    writer = NewWriter(stream);
                    await SendCommandAsync(writer, reader, $"EHLO {Dns.GetHostName()}", cts.Token, "250");
                }

                var authPlain = Convert.ToBase64String(Encoding.UTF8.GetBytes("\0" + login + "\0" + password));
                await SendCommandAsync(writer, reader, "AUTH PLAIN " + authPlain, cts.Token, "235");

                await SendCommandAsync(writer, reader, $"MAIL FROM:<{ExtractAddress(from)}>", cts.Token, "250");
                foreach (var rcpt in to)
                    await SendCommandAsync(writer, reader, $"RCPT TO:<{ExtractAddress(rcpt)}>", cts.Token, "250", "251");

                await SendCommandAsync(writer, reader, "DATA", cts.Token, "354");

                // Dot-stuffing: a line beginning with "." terminates the message early.
                var payload = message.Replace("\r\n.", "\r\n..");
                if (!payload.EndsWith("\r\n")) payload += "\r\n";
                await writer.WriteAsync(payload);
                await writer.WriteAsync(".\r\n");
                await writer.FlushAsync(cts.Token);

                var dataResp = await ReadResponseAsync(reader, cts.Token);
                if (!dataResp.StartsWith("250"))
                    throw new SmtpException("Message not accepted: " + FirstLine(dataResp));

                try { await SendCommandAsync(writer, reader, "QUIT", cts.Token, "221"); }
                catch { /* server may close immediately */ }
            }
            finally
            {
                reader.Dispose();
                await writer.DisposeAsync();
                await stream.DisposeAsync();
            }
        }
        catch (SmtpException)
        {
            throw;
        }
        catch (Exception ex)
        {
            logger.LogWarning("SMTP send {Host}:{Port} failed: {Msg}", endpoint.Host, endpoint.Port, ex.Message);
            throw new SmtpException("SMTP error: " + ex.Message, ex);
        }
    }

    public static string ExtractAddress(string value)
    {
        var lt = value.IndexOf('<');
        var gt = value.IndexOf('>');
        if (lt >= 0 && gt > lt) return value[(lt + 1)..gt].Trim();
        return value.Trim();
    }

    private static StreamWriter NewWriter(Stream stream) =>
        new(stream, new UTF8Encoding(false), bufferSize: -1, leaveOpen: true) { NewLine = "\r\n", AutoFlush = true };

    private static string FirstLine(string response) =>
        response.Split('\n')[0].Trim();

    private static async Task<string> ReadResponseAsync(StreamReader reader, CancellationToken ct)
    {
        var response = new StringBuilder();
        while (true)
        {
            ct.ThrowIfCancellationRequested();
            var line = await reader.ReadLineAsync(ct);
            if (line == null) throw new SmtpException("SMTP connection closed unexpectedly");
            response.Append(line).Append('\n');
            // Multi-line responses use "xxx-"; the final line uses "xxx " or is bare code.
            if (line.Length >= 4 && line[3] == '-') continue;
            return response.ToString();
        }
    }

    private static async Task SendCommandAsync(StreamWriter writer, StreamReader reader,
        string command, CancellationToken ct, params string[] expectedCodes)
    {
        // Never log credentials embedded in AUTH commands.
        await writer.WriteLineAsync(command.AsMemory(), ct);
        var response = await ReadResponseAsync(reader, ct);
        var code = response.Length >= 3 ? response[..3] : "";
        if (!expectedCodes.Contains(code))
        {
            var name = command.Split(' ')[0];
            throw new SmtpException($"SMTP {name} failed ({code.Trim()}): {FirstLine(response)}");
        }
    }

    private static async Task<SslStream> UpgradeTlsAsync(Stream inner, SmtpEndpoint ep, CancellationToken ct)
    {
        var ssl = new SslStream(inner, leaveInnerStreamOpen: true,
            (_, _, _, errors) => errors == SslPolicyErrors.None || ep.AllowInvalidCertificates);
        try
        {
            await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions { TargetHost = ep.Host }, ct);
        }
        catch (System.Security.Authentication.AuthenticationException ex)
        {
            throw new SmtpException("SMTP TLS handshake failed: " + ex.Message, ex);
        }
        return ssl;
    }
}

public sealed record SmtpEndpoint(string Host, int Port, MailSecurity Security, bool AllowInvalidCertificates);

public sealed class SmtpException(string message, Exception? inner = null) : Exception(message, inner);