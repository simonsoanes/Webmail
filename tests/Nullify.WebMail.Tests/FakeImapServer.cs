// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Nullify.WebMail.Tests;

/// <summary>Just enough IMAP for a login check: CAPABILITY, LOGIN and LOGOUT.</summary>
internal sealed class FakeImapServer : IDisposable
{
    private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
    private readonly string _user;
    private int _loginAttempts;

    /// <summary>The password LOGIN accepts; change it to simulate a password change.</summary>
    public string Password { get; set; }

    public int Port => ((IPEndPoint)_listener.LocalEndpoint).Port;
    public int LoginAttempts => Volatile.Read(ref _loginAttempts);

    public FakeImapServer(string user, string password)
    {
        _user = user;
        Password = password;
        _listener.Start();
        _ = AcceptLoop();
    }

    private async Task AcceptLoop()
    {
        while (true)
        {
            TcpClient client;
            try { client = await _listener.AcceptTcpClientAsync(); } catch { return; }
            _ = Serve(client);
        }
    }

    private async Task Serve(TcpClient client)
    {
        using var _ = client;
        var stream = client.GetStream();
        var reader = new StreamReader(stream, Encoding.ASCII);
        var writer = new StreamWriter(stream, Encoding.ASCII) { NewLine = "\r\n", AutoFlush = true };
        try
        {
            await writer.WriteLineAsync("* OK fake IMAP ready");
            while (await reader.ReadLineAsync() is { } line)
            {
                var parts = line.Split(' ', 3);
                var tag = parts[0];
                var command = parts.Length > 1 ? parts[1].ToUpperInvariant() : "";
                switch (command)
                {
                    case "CAPABILITY":
                        await writer.WriteLineAsync("* CAPABILITY IMAP4rev1");
                        await writer.WriteLineAsync($"{tag} OK done");
                        break;
                    case "LOGIN":
                        Interlocked.Increment(ref _loginAttempts);
                        var args = parts.Length > 2 ? parts[2].Split(' ').Select(t => t.Trim('"')).ToArray() : [];
                        var ok = args.Length == 2 && args[0] == _user && args[1] == Password;
                        await writer.WriteLineAsync(ok ? $"{tag} OK logged in" : $"{tag} NO [AUTHENTICATIONFAILED] bad");
                        break;
                    case "LOGOUT":
                        await writer.WriteLineAsync("* BYE");
                        await writer.WriteLineAsync($"{tag} OK bye");
                        return;
                    default:
                        await writer.WriteLineAsync($"{tag} BAD unsupported");
                        break;
                }
            }
        }
        catch (IOException) { }
    }

    public void Dispose() => _listener.Stop();
}
