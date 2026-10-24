// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using System.Collections.Concurrent;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Authentication;

namespace Nullify.WebMail.Services;

public enum QrLoginState { Waiting, Scanned, Confirmed, Approved, Redeemed, Failed, Expired, Cancelled }

/// <summary>What the phone is shown before it approves: enough to tell whether this is the user's desktop.</summary>
public sealed record QrDescription(string Desktop, string? DesktopIp, string? PhoneIp, DateTimeOffset StartedUtc, int[] Codes);

/// <summary>A desktop session a phone approved, as the phone sees it.</summary>
public sealed record QrSessionStatus(string Login, string Desktop, string? DesktopIp, DateTimeOffset SignedInUtc, DateTimeOffset ExpiresUtc, bool Active);

/// <summary>
/// Signing in a desktop from a phone, so the mail password is typed on the phone and never
/// reaches the desktop. The desktop starts a request and shows its id as a QR code; the phone
/// checks a match code, sends the password, and the server hands the resulting ticket to the
/// desktop browser that started the request (proven by an HttpOnly cookie).
/// Everything is held in memory, like <see cref="MemoryTicketStore"/>.
/// </summary>
public sealed class QrLoginService : IDisposable
{
    public static readonly TimeSpan ScanWindow = TimeSpan.FromSeconds(120);
    public static readonly TimeSpan ApproveWindow = TimeSpan.FromMinutes(5);
    public static readonly TimeSpan RedeemWindow = TimeSpan.FromSeconds(60);
    public const int MaxPasswordAttempts = 3;

    private readonly MemoryTicketStore _tickets;
    private readonly TimeProvider _time;
    private readonly ConcurrentDictionary<string, Pending> _pending = new();
    private readonly ConcurrentDictionary<string, ApprovedSession> _sessions = new(); // by app session id
    private readonly ITimer _sweeper;

    public TimeSpan SessionLifetime { get; }

    /// <summary>A pending request changed state (id, new state). Raised outside any lock.</summary>
    public event Action<string, QrLoginState>? Changed;

    public QrLoginService(MemoryTicketStore tickets, IConfiguration config, TimeProvider? time = null)
    {
        _tickets = tickets;
        _time = time ?? TimeProvider.System;
        var hours = config.GetValue("QrLogin:SessionHours", 8.0);
        SessionLifetime = TimeSpan.FromHours(Math.Clamp(hours, 0.25, 24));
        _sweeper = _time.CreateTimer(_ => Sweep(), null, TimeSpan.FromSeconds(15), TimeSpan.FromSeconds(15));
    }

    private sealed class Pending
    {
        public required byte[] BindHash;
        public required int Code;
        public required int[] Codes;
        public required string Desktop;
        public required string? DesktopIp;
        public required DateTimeOffset StartedUtc;
        public DateTimeOffset ExpiresUtc;
        public QrLoginState State = QrLoginState.Waiting;
        public byte[]? PhoneHash;
        public int PasswordAttempts;
        public ClaimsPrincipal? Principal;
        public AuthenticationProperties? Properties;
        public byte[]? RevokeHash;
    }

    private sealed record ApprovedSession(byte[] RevokeHash, string Login, string Desktop, string? DesktopIp, DateTimeOffset SignedInUtc, DateTimeOffset ExpiresUtc)
    {
        public bool Ended;
    }

    private DateTimeOffset Now => _time.GetUtcNow();

    // ------------------------------------------------------------------ desktop

    /// <summary>Start a request. The bind token goes into the desktop's HttpOnly cookie; the id goes into the QR code.</summary>
    public (string Id, string BindToken, int Code, DateTimeOffset ExpiresUtc) Start(string? userAgent, string? ip)
    {
        var id = Token(16);
        var bind = Token(32);
        var code = RandomNumberGenerator.GetInt32(10, 100);
        var codes = new HashSet<int> { code };
        while (codes.Count < 3) codes.Add(RandomNumberGenerator.GetInt32(10, 100));
        var shuffled = codes.ToArray();
        RandomNumberGenerator.Shuffle<int>(shuffled);

        var pending = new Pending
        {
            BindHash = Hash(bind),
            Code = code,
            Codes = shuffled,
            Desktop = DescribeUserAgent(userAgent),
            DesktopIp = ip,
            StartedUtc = Now,
            ExpiresUtc = Now + ScanWindow,
        };
        _pending[id] = pending;
        return (id, bind, code, pending.ExpiresUtc);
    }

    public QrLoginState? GetState(string id) => _pending.TryGetValue(id, out var p) ? p.State : null;

    /// <summary>The desktop gave up on this request (closed the panel or showed a new code).</summary>
    public void Cancel(string id)
    {
        if (_pending.TryRemove(id, out var p))
        {
            lock (p) if (p.State is QrLoginState.Redeemed) return;
            Changed?.Invoke(id, QrLoginState.Cancelled);
        }
    }

    /// <summary>Hand the approved ticket to the desktop that started the request. Single use.</summary>
    public (ClaimsPrincipal Principal, AuthenticationProperties Properties)? Redeem(string id, string? bindToken)
    {
        if (bindToken == null || !_pending.TryGetValue(id, out var p)) return null;
        ClaimsPrincipal principal;
        AuthenticationProperties properties;
        lock (p)
        {
            if (p.State != QrLoginState.Approved || Now > p.ExpiresUtc) return null;
            if (!CryptographicOperations.FixedTimeEquals(p.BindHash, Hash(bindToken))) return null;
            principal = p.Principal!;
            properties = p.Properties!;
            p.State = QrLoginState.Redeemed;
            p.Principal = null;
            p.Properties = null;
        }
        _pending.TryRemove(id, out _);

        var sessionId = principal.FindFirst(AuthService.SessionIdClaim)!.Value;
        _sessions[sessionId] = new ApprovedSession(
            p.RevokeHash!, principal.Identity?.Name ?? "", p.Desktop, p.DesktopIp, Now, properties.ExpiresUtc ?? Now + SessionLifetime);
        Changed?.Invoke(id, QrLoginState.Redeemed);
        return (principal, properties);
    }

    // ------------------------------------------------------------------ phone

    /// <summary>What the phone shows before the user approves. Null once the request is gone or used.</summary>
    public QrDescription? Describe(string id, string? phoneIp)
    {
        if (!_pending.TryGetValue(id, out var p)) return null;
        var notify = false;
        lock (p)
        {
            if (Now > p.ExpiresUtc || p.State is not (QrLoginState.Waiting or QrLoginState.Scanned)) return null;
            if (p.State == QrLoginState.Waiting) { p.State = QrLoginState.Scanned; notify = true; }
        }
        if (notify) Changed?.Invoke(id, QrLoginState.Scanned);
        return new QrDescription(p.Desktop, p.DesktopIp, phoneIp, p.StartedUtc, p.Codes);
    }

    /// <summary>
    /// The phone picked the code it sees on the desktop. One chance: a wrong pick ends the request,
    /// so a phone tricked into scanning someone else's code can't simply try all three.
    /// Returns a phone token that the approval must carry, or null.
    /// </summary>
    public string? Confirm(string id, int code)
    {
        if (!_pending.TryGetValue(id, out var p)) return null;
        string? phone = null;
        QrLoginState state;
        lock (p)
        {
            if (Now > p.ExpiresUtc || p.State != QrLoginState.Scanned) return null;
            if (code == p.Code)
            {
                phone = Token(32);
                p.PhoneHash = Hash(phone);
                p.State = QrLoginState.Confirmed;
                p.ExpiresUtc = Now + ApproveWindow;
            }
            else
            {
                p.State = QrLoginState.Failed;
            }
            state = p.State;
        }
        if (state == QrLoginState.Failed) _pending.TryRemove(id, out _);
        Changed?.Invoke(id, state);
        return phone;
    }

    /// <summary>Whether the phone token is valid for a request waiting for its password.</summary>
    public bool CanApprove(string id, string? phoneToken)
    {
        if (phoneToken == null || !_pending.TryGetValue(id, out var p)) return false;
        lock (p)
            return p.State == QrLoginState.Confirmed && Now <= p.ExpiresUtc
                && CryptographicOperations.FixedTimeEquals(p.PhoneHash!, Hash(phoneToken));
    }

    /// <summary>A wrong password from the phone. Returns false once the request has used up its attempts.</summary>
    public bool RecordFailedPassword(string id)
    {
        if (!_pending.TryGetValue(id, out var p)) return false;
        bool failed;
        lock (p)
        {
            p.PasswordAttempts++;
            failed = p.PasswordAttempts >= MaxPasswordAttempts;
            if (failed) p.State = QrLoginState.Failed;
        }
        if (failed)
        {
            _pending.TryRemove(id, out _);
            Changed?.Invoke(id, QrLoginState.Failed);
        }
        return !failed;
    }

    /// <summary>
    /// Store the verified sign-in for the desktop to collect. Returns a revoke token for the phone,
    /// which is the only way to end the desktop session from the phone.
    /// </summary>
    public string? Approve(string id, string phoneToken, ClaimsPrincipal principal, AuthenticationProperties properties)
    {
        if (!_pending.TryGetValue(id, out var p)) return null;
        var revoke = Token(32);
        lock (p)
        {
            if (p.State != QrLoginState.Confirmed || Now > p.ExpiresUtc) return null;
            if (!CryptographicOperations.FixedTimeEquals(p.PhoneHash!, Hash(phoneToken))) return null;
            p.Principal = principal;
            p.Properties = properties;
            p.RevokeHash = Hash(revoke);
            p.State = QrLoginState.Approved;
            p.ExpiresUtc = Now + RedeemWindow;
        }
        Changed?.Invoke(id, QrLoginState.Approved);
        return revoke;
    }

    /// <summary>Status of the desktop sessions this phone approved, by revoke token. Unknown tokens are skipped.</summary>
    public IReadOnlyList<(string Token, QrSessionStatus Status)> Status(IEnumerable<string> revokeTokens)
    {
        var result = new List<(string, QrSessionStatus)>();
        foreach (var token in revokeTokens.Distinct().Take(20))
        {
            var (sessionId, s) = FindByRevokeToken(token);
            if (s == null) continue;
            var active = !s.Ended && _tickets.HasSession(sessionId!) && Now < s.ExpiresUtc;
            result.Add((token, new QrSessionStatus(s.Login, s.Desktop, s.DesktopIp, s.SignedInUtc, s.ExpiresUtc, active)));
        }
        return result;
    }

    /// <summary>End a desktop session from the phone. True if the token named a session.</summary>
    public async Task<bool> RevokeAsync(string revokeToken)
    {
        var (sessionId, s) = FindByRevokeToken(revokeToken);
        if (s == null) return false;
        await EndSessionAsync(sessionId!);
        return true;
    }

    private (string?, ApprovedSession?) FindByRevokeToken(string token)
    {
        var hash = Hash(token);
        foreach (var (sessionId, s) in _sessions)
            if (CryptographicOperations.FixedTimeEquals(s.RevokeHash, hash)) return (sessionId, s);
        return (null, null);
    }

    private async Task EndSessionAsync(string sessionId)
    {
        if (_sessions.TryGetValue(sessionId, out var s)) s.Ended = true;
        await _tickets.RemoveSessionAsync(sessionId); // raises MemoryTicketStore.SessionEnded
    }

    // ------------------------------------------------------------------ housekeeping

    /// <summary>Expire old requests and end sessions past their time limit. Runs on a timer.</summary>
    public void Sweep()
    {
        var now = Now;
        foreach (var (id, p) in _pending)
        {
            bool expired;
            lock (p) expired = now > p.ExpiresUtc;
            if (expired && _pending.TryRemove(id, out _)) Changed?.Invoke(id, QrLoginState.Expired);
        }

        foreach (var (sessionId, s) in _sessions)
        {
            if (now >= s.ExpiresUtc && !s.Ended)
            {
                // The ticket expires by itself; this also closes any circuit still showing mail.
                _ = EndSessionAsync(sessionId);
            }
            // Keep ended sessions listed on the phone for a day, then forget them.
            if (now >= s.ExpiresUtc + TimeSpan.FromDays(1)) _sessions.TryRemove(sessionId, out _);
        }
    }

    public void Dispose() => _sweeper.Dispose();

    // ------------------------------------------------------------------ helpers

    private static string Token(int bytes) =>
        Convert.ToBase64String(RandomNumberGenerator.GetBytes(bytes)).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static byte[] Hash(string token) => SHA256.HashData(Encoding.UTF8.GetBytes(token));

    /// <summary>"Edge on Windows" style summary of a user agent, for the phone to recognise its desktop.</summary>
    public static string DescribeUserAgent(string? ua)
    {
        if (string.IsNullOrWhiteSpace(ua)) return "Unknown browser";
        var browser =
            ua.Contains("Edg/") ? "Edge" :
            ua.Contains("OPR/") ? "Opera" :
            ua.Contains("Firefox/") ? "Firefox" :
            ua.Contains("Chrome/") ? "Chrome" :
            ua.Contains("Safari/") ? "Safari" : "Browser";
        var os =
            ua.Contains("Windows") ? "Windows" :
            ua.Contains("CrOS") ? "ChromeOS" :
            ua.Contains("iPhone") || ua.Contains("iPad") ? "iOS" :
            ua.Contains("Mac OS X") ? "macOS" :
            ua.Contains("Android") ? "Android" :
            ua.Contains("Linux") ? "Linux" : "an unknown system";
        return $"{browser} on {os}";
    }
}
