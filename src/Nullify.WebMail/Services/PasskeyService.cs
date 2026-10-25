// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using System.Buffers.Text;
using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Nullify.WebMail.Data;

namespace Nullify.WebMail.Services;

public sealed record PasskeyInfo(int Id, string Name, DateTime CreatedUtc, DateTime? LastUsedUtc, bool Stale);

public sealed record PasskeyCredentialDescriptor(string Id, string[]? Transports);
/// <summary>PRF salts for one passkey. The browser hashes them with a label before use, never passing them to PRF as they are.</summary>
public sealed record PasskeySalts(string First, string? Second);

public sealed record PasskeyRegisterOptions(
    string Handle, string Challenge, string RpId, string RpName,
    string UserId, string UserName, int[] Algorithms,
    PasskeyCredentialDescriptor[] Exclude, string Salt);

public sealed record PasskeyAssertionOptions(
    string Handle, string Challenge, string RpId,
    PasskeyCredentialDescriptor[] Allow, Dictionary<string, PasskeySalts> Salts);

public sealed record PasskeySignInOptionsRequest(string? Username, string[]? CredentialIds);

public sealed record PasskeyRegisterRequest(
    string Handle, string ClientDataJson, string AttestationObject, string[]? Transports, string Kek);

/// <summary>An assertion plus the keys the browser derived from the PRF outputs (never the outputs themselves).</summary>
public sealed record PasskeyAssertionRequest(
    string Handle, string CredentialId, string ClientDataJson, string AuthenticatorData, string Signature,
    string? UserHandle, string Kek, string? NextKek);

public sealed record PasskeyResponse(bool Success, string? Error, string? CredentialId = null);

/// <summary>What passkey.js hands back to .NET: whether it worked, and nothing secret.</summary>
public sealed record PasskeyOutcome(bool Ok, string? Error);

/// <summary>passkey.js approving a QR sign-in: the phone's revoke token for the computer's session, and who signed in.</summary>
public sealed record QrPasskeyOutcome(bool Ok, string? Error, string? RevokeToken, string? Login);

/// <summary>WebAuthn ceremonies in progress: in memory only, single use, a few minutes long.</summary>
public sealed class PasskeyCeremonies
{
    public enum Kind { Register, SignIn, Update }

    public sealed class Pending
    {
        public required Kind Kind { get; init; }
        public required byte[] Challenge { get; init; }
        public DateTime ExpiresUtc { get; init; } = DateTime.UtcNow + Lifetime;
        /// <summary>Register and update: the signed-in user.</summary>
        public string? Login { get; init; }
        /// <summary>Register: the WebAuthn user handle and the PRF salt for the first wrap.</summary>
        public string? UserHandle { get; init; }
        public byte[]? Salt { get; init; }
        /// <summary>Sign-in and update: the passkeys that may answer, each with the salt its next wrap will use.</summary>
        public Dictionary<string, byte[]> NextSalts { get; } = [];
    }

    public static readonly TimeSpan Lifetime = TimeSpan.FromMinutes(3);
    private const int MaxPending = 10_000;

    private readonly ConcurrentDictionary<string, Pending> _pending = new();
    // Gives addresses without passkeys a stable made-up credential, so sign-in options don't reveal which addresses have them.
    private readonly byte[] _decoyKey = RandomNumberGenerator.GetBytes(32);

    public string Add(Pending pending)
    {
        var now = DateTime.UtcNow;
        foreach (var (key, p) in _pending)
            if (p.ExpiresUtc < now) _pending.TryRemove(key, out _);
        if (_pending.Count >= MaxPending)
            throw new WebAuthnException("Too many passkey requests are in progress. Try again in a few minutes.");

        var handle = Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(16));
        _pending[handle] = pending;
        return handle;
    }

    /// <summary>The ceremony for a handle, removed so it can't be answered twice.</summary>
    public Pending? Take(string? handle, Kind kind) =>
        handle != null && _pending.TryRemove(handle, out var p) && p.Kind == kind && p.ExpiresUtc > DateTime.UtcNow ? p : null;

    public string DecoyCredentialId(string username) => Decoy("id", username);

    /// <summary>Stable like a real passkey's current salt, which only changes when it's used.</summary>
    public string DecoySalt(string username) => Decoy("salt", username);

    private string Decoy(string purpose, string username) =>
        Base64Url.EncodeToString(HMACSHA256.HashData(_decoyKey, Encoding.UTF8.GetBytes(purpose + "|" + username.ToLowerInvariant())));
}

/// <summary>
/// Passkeys that sign in to the webmail. A passkey can't sign in to IMAP, so each one also keeps
/// the mail login, wrapped twice: inside with the server's Data Protection key ring, and outside
/// with AES-256-GCM under a key the browser derives from the passkey's PRF output. Between
/// sign-ins neither the database nor the key ring can recover the password without the
/// authenticator. The PRF salt changes on every use, so a key captured once stops working after
/// the next sign-in. See docs/qr-passkey-signin.md, Part 2.
/// </summary>
public sealed class PasskeyService(
    AuthService auth,
    PasskeyCeremonies ceremonies,
    IDataProtectionProvider protection,
    IDbContextFactory<AppDbContext> dbFactory,
    MemoryTicketStore tickets,
    SettingsService settings,
    ILogger<PasskeyService> logger)
{
    public const int MaxPerUser = 20;
    private const int SaltSize = 32, KeySize = 32, NonceSize = 12, TagSize = 16;

    private readonly IDataProtector _protector = protection.CreateProtector("Nullify.WebMail.Passkey.v1");

    private sealed record WrappedLogin(string Login, string Password);

    // ------------------------------------------------------------------ registration (signed in)

    public async Task<PasskeyRegisterOptions> BeginRegisterAsync(HttpContext ctx, CredentialInfo cred, CancellationToken ct = default)
    {
        await using var db = await dbFactory.CreateDbContextAsync(ct);
        var existing = await db.Passkeys.Where(p => p.User!.Username == cred.Login).ToListAsync(ct);
        if (existing.Count >= MaxPerUser)
            throw new WebAuthnException($"You already have {MaxPerUser} passkeys. Remove one first.");

        var pending = new PasskeyCeremonies.Pending
        {
            Kind = PasskeyCeremonies.Kind.Register,
            Challenge = RandomNumberGenerator.GetBytes(32),
            Login = cred.Login,
            // One handle per user, so adding a passkey again on the same authenticator replaces the old one there.
            UserHandle = existing.FirstOrDefault()?.UserHandle ?? Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(32)),
            Salt = RandomNumberGenerator.GetBytes(SaltSize),
        };
        var handle = ceremonies.Add(pending);
        return new PasskeyRegisterOptions(
            handle, Base64Url.EncodeToString(pending.Challenge), RpId(ctx), "Nullify WebMail",
            pending.UserHandle, cred.Login, WebAuthn.Algorithms,
            existing.Select(Descriptor).ToArray(), Base64Url.EncodeToString(pending.Salt));
    }

    public async Task FinishRegisterAsync(HttpContext ctx, CredentialInfo cred, PasskeyRegisterRequest r, CancellationToken ct = default)
    {
        var pending = ceremonies.Take(r.Handle, PasskeyCeremonies.Kind.Register);
        if (pending == null || pending.Login != cred.Login)
            throw new WebAuthnException("This request has expired. Try again.");

        var clientData = Bytes(r.ClientDataJson);
        WebAuthn.VerifyClientData(clientData, "webauthn.create", pending.Challenge, Origins(ctx));
        var data = WebAuthn.ParseAuthenticatorData(WebAuthn.AuthenticatorDataFromAttestation(Bytes(r.AttestationObject)));
        WebAuthn.VerifyRpAndUser(data, RpId(ctx));
        if (data.CredentialId == null || data.CosePublicKey == null)
            throw new WebAuthnException("The passkey's registration has no credential in it.");
        WebAuthn.ValidatePublicKey(data.CosePublicKey);
        var kek = Key(r.Kek);

        await using var db = await dbFactory.CreateDbContextAsync(ct);
        var credentialId = Base64Url.EncodeToString(data.CredentialId);
        if (await db.Passkeys.AnyAsync(p => p.CredentialId == credentialId, ct))
            throw new WebAuthnException("That passkey is already set up.");
        var user = await db.Users.FirstAsync(u => u.Username == cred.Login, ct);

        var passkey = new Passkey
        {
            UserId = user.Id,
            Name = QrLoginService.DescribeUserAgent(ctx.Request.Headers.UserAgent.ToString()),
            CredentialId = credentialId,
            PublicKey = data.CosePublicKey,
            SignCount = data.SignCount,
            Transports = r.Transports is { Length: > 0 } t ? string.Join(',', t.Where(IsTransport)) : null,
            UserHandle = pending.UserHandle!,
            PrfSalt = pending.Salt!,
            WrapVersion = 1,
        };
        passkey.WrappedCredential = Wrap(kek, passkey, cred.Login, cred.Password);
        db.Passkeys.Add(passkey);
        await db.SaveChangesAsync(ct);
        logger.LogInformation("Passkey {Id} added for {Login}", passkey.Id, cred.Login);
    }

    // ------------------------------------------------------------------ sign-in (anonymous)

    /// <summary>
    /// Sign-in options for the passkeys of an address the user typed, and those this browser has
    /// used before. PRF can only be given per-credential salts for credentials named up front, so
    /// one of those is needed: a passkey on its own can't be picked without saying whose it is.
    /// </summary>
    public async Task<PasskeyAssertionOptions> BeginSignInAsync(string? username, string[]? credentialIds, HttpContext ctx, CancellationToken ct = default)
    {
        username = username?.Trim();
        var ids = (credentialIds ?? []).Where(id => id is { Length: > 0 and <= 1400 }).Distinct().Take(10).ToArray();
        if (string.IsNullOrEmpty(username) && ids.Length == 0)
            throw new WebAuthnException("Type your email address first, then use your passkey.");

        await using var db = await dbFactory.CreateDbContextAsync(ct);
        var lower = username?.ToLowerInvariant();
        var passkeys = await db.Passkeys
            .Where(p => ids.Contains(p.CredentialId) || (lower != null && p.User!.Username.ToLower() == lower))
            .ToListAsync(ct);

        var pending = new PasskeyCeremonies.Pending { Kind = PasskeyCeremonies.Kind.SignIn, Challenge = RandomNumberGenerator.GetBytes(32) };
        var salts = new Dictionary<string, PasskeySalts>();
        foreach (var p in passkeys)
        {
            var next = RandomNumberGenerator.GetBytes(SaltSize);
            pending.NextSalts[p.CredentialId] = next;
            salts[p.CredentialId] = new PasskeySalts(Base64Url.EncodeToString(p.PrfSalt), Base64Url.EncodeToString(next));
        }
        var allow = passkeys.Select(Descriptor).ToList();
        if (allow.Count == 0 && !string.IsNullOrEmpty(username))
        {
            // Looks like any other address's options; the browser just won't find the passkey.
            var decoy = ceremonies.DecoyCredentialId(username);
            allow.Add(new PasskeyCredentialDescriptor(decoy, null));
            salts[decoy] = new PasskeySalts(ceremonies.DecoySalt(username), Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(SaltSize)));
        }
        if (allow.Count == 0)
            throw new WebAuthnException("Type your email address first, then use your passkey.");

        var handle = ceremonies.Add(pending);
        return new PasskeyAssertionOptions(handle, Base64Url.EncodeToString(pending.Challenge), RpId(ctx), allow.ToArray(), salts);
    }

    /// <summary>Sign this browser in with a passkey.</summary>
    public async Task FinishSignInAsync(HttpContext ctx, PasskeyAssertionRequest r, CancellationToken ct = default)
    {
        var (cred, passkeyId) = await VerifySignInAsync(ctx, r, ct);
        await auth.SignInAsync(ctx, cred, passkeyId: passkeyId);
    }

    /// <summary>
    /// Check the assertion, unwrap the login with the browser's key, check it with IMAP and wrap it
    /// again under the next salt. Returns the credential to sign in with and the passkey's id for the
    /// session's claim, without signing anyone in: a phone can use its passkey to sign in a computer.
    /// </summary>
    public async Task<(CredentialInfo Credential, string PasskeyId)> VerifySignInAsync(HttpContext ctx, PasskeyAssertionRequest r, CancellationToken ct = default)
    {
        var pending = ceremonies.Take(r.Handle, PasskeyCeremonies.Kind.SignIn)
            ?? throw new WebAuthnException("The passkey request has expired. Try again.");

        await using var db = await dbFactory.CreateDbContextAsync(ct);
        var passkey = await VerifyAssertionAsync(db, ctx, pending, r, ct);
        // The keys are only looked at once the assertion has checked out.
        var kek = Key(r.Kek);
        var nextKek = Key(r.NextKek);

        var login = Unwrap(kek, passkey);
        if (login == null || login.Login != passkey.User!.Username)
            throw new WebAuthnException("This passkey couldn't unlock your saved password. Sign in with your password, then add the passkey again in Settings.");

        var servers = await auth.ResolveServersAsync(login.Login, ct)
            ?? throw new WebAuthnException("No mail server is configured for this account.");
        var result = await auth.VerifyAsync(servers.Imap, login.Login, login.Password, ct);
        if (result == ImapResult.InvalidCredentials)
        {
            passkey.Stale = true;
            await db.SaveChangesAsync(ct);
            throw new WebAuthnException("Your mail password has changed since this passkey was set up. Sign in with your password, then update the passkey in Settings.");
        }
        // If IMAP can't be reached the user is signed in anyway: the passkey proved who they are, and the mail view reports the outage.

        passkey.PrfSalt = pending.NextSalts[passkey.CredentialId];
        passkey.WrapVersion++;
        passkey.WrappedCredential = Wrap(nextKek, passkey, login.Login, login.Password);
        passkey.Stale = false;
        passkey.LastUsedUtc = DateTime.UtcNow;
        await SaveRewrapAsync(db, ct);

        await auth.UpsertUserAsync(login.Login, ct);
        return (AuthService.BuildCredential(login.Login, login.Password, servers), passkey.Id.ToString());
    }

    // ------------------------------------------------------------------ updating the saved password (signed in)

    /// <summary>After the mail password changes: wrap this session's password under the passkey again.</summary>
    public async Task<PasskeyAssertionOptions> BeginUpdateAsync(HttpContext ctx, CredentialInfo cred, int passkeyId, CancellationToken ct = default)
    {
        await using var db = await dbFactory.CreateDbContextAsync(ct);
        var passkey = await db.Passkeys.FirstOrDefaultAsync(p => p.Id == passkeyId && p.User!.Username == cred.Login, ct)
            ?? throw new WebAuthnException("That passkey isn't set up any more.");

        var next = RandomNumberGenerator.GetBytes(SaltSize);
        var pending = new PasskeyCeremonies.Pending { Kind = PasskeyCeremonies.Kind.Update, Challenge = RandomNumberGenerator.GetBytes(32), Login = cred.Login };
        pending.NextSalts[passkey.CredentialId] = next;
        var handle = ceremonies.Add(pending);
        return new PasskeyAssertionOptions(handle, Base64Url.EncodeToString(pending.Challenge), RpId(ctx),
            [Descriptor(passkey)],
            new() { [passkey.CredentialId] = new PasskeySalts(Base64Url.EncodeToString(next), null) });
    }

    public async Task FinishUpdateAsync(HttpContext ctx, CredentialInfo cred, PasskeyAssertionRequest r, CancellationToken ct = default)
    {
        var pending = ceremonies.Take(r.Handle, PasskeyCeremonies.Kind.Update);
        if (pending == null || pending.Login != cred.Login)
            throw new WebAuthnException("This request has expired. Try again.");

        await using var db = await dbFactory.CreateDbContextAsync(ct);
        var passkey = await VerifyAssertionAsync(db, ctx, pending, r, ct);
        if (passkey.User!.Username != cred.Login)
            throw new WebAuthnException("That passkey belongs to a different account.");
        var kek = Key(r.Kek);

        passkey.PrfSalt = pending.NextSalts[passkey.CredentialId];
        passkey.WrapVersion++;
        passkey.WrappedCredential = Wrap(kek, passkey, cred.Login, cred.Password);
        passkey.Stale = false;
        await SaveRewrapAsync(db, ct);
    }

    // ------------------------------------------------------------------ settings

    public async Task<List<PasskeyInfo>> ListAsync(string login, CancellationToken ct = default)
    {
        await using var db = await dbFactory.CreateDbContextAsync(ct);
        return await db.Passkeys
            .Where(p => p.User!.Username == login)
            .OrderByDescending(p => p.CreatedUtc)
            .Select(p => new PasskeyInfo(p.Id, p.Name, p.CreatedUtc, p.LastUsedUtc, p.Stale))
            .ToListAsync(ct);
    }

    /// <summary>Remove a passkey, and end any session it signed in.</summary>
    public async Task RemoveAsync(string login, int passkeyId, CancellationToken ct = default)
    {
        await using (var db = await dbFactory.CreateDbContextAsync(ct))
            await db.Passkeys.Where(p => p.Id == passkeyId && p.User!.Username == login).ExecuteDeleteAsync(ct);
        var id = passkeyId.ToString();
        await tickets.RemoveSessionsAsync(p => p.FindFirst(AuthService.PasskeyClaim)?.Value == id);
    }

    // ------------------------------------------------------------------ helpers

    private async Task<Passkey> VerifyAssertionAsync(AppDbContext db, HttpContext ctx, PasskeyCeremonies.Pending pending, PasskeyAssertionRequest r, CancellationToken ct)
    {
        if (r.CredentialId == null || !pending.NextSalts.ContainsKey(r.CredentialId))
            throw new WebAuthnException("That passkey isn't set up for this account.");
        var passkey = await db.Passkeys.Include(p => p.User).FirstOrDefaultAsync(p => p.CredentialId == r.CredentialId, ct)
            ?? throw new WebAuthnException("That passkey isn't set up any more.");

        var clientData = Bytes(r.ClientDataJson);
        WebAuthn.VerifyClientData(clientData, "webauthn.get", pending.Challenge, Origins(ctx));
        var authData = Bytes(r.AuthenticatorData);
        var data = WebAuthn.ParseAuthenticatorData(authData);
        WebAuthn.VerifyRpAndUser(data, RpId(ctx));
        if (!WebAuthn.VerifySignature(passkey.PublicKey, authData, clientData, Bytes(r.Signature)))
            throw new WebAuthnException("The passkey's signature didn't check out.");
        if (!string.IsNullOrEmpty(r.UserHandle) && r.UserHandle != passkey.UserHandle)
            throw new WebAuthnException("That passkey belongs to a different account.");
        // Synced passkeys always report 0; a counter that goes backwards means a cloned authenticator.
        if ((data.SignCount != 0 || passkey.SignCount != 0) && data.SignCount <= passkey.SignCount)
            throw new WebAuthnException("This passkey's counter went backwards, which can mean it was copied. Remove it in Settings and add it again.");
        passkey.SignCount = data.SignCount;
        return passkey;
    }

    private static async Task SaveRewrapAsync(AppDbContext db, CancellationToken ct)
    {
        try
        {
            await db.SaveChangesAsync(ct);
        }
        catch (DbUpdateConcurrencyException)
        {
            // Another sign-in with the same passkey wrapped the login again first; this one's keys are for the old salt.
            throw new WebAuthnException("The passkey was used somewhere else at the same moment. Try again.");
        }
    }

    private byte[] Wrap(byte[] kek, Passkey passkey, string login, string password)
    {
        var inner = _protector.Protect(JsonSerializer.SerializeToUtf8Bytes(new WrappedLogin(login, password)));
        var blob = new byte[NonceSize + TagSize + inner.Length];
        RandomNumberGenerator.Fill(blob.AsSpan(0, NonceSize));
        using (var aes = new AesGcm(kek, TagSize))
            aes.Encrypt(blob.AsSpan(0, NonceSize), inner, blob.AsSpan(NonceSize + TagSize), blob.AsSpan(NonceSize, TagSize), Aad(passkey));
        CryptographicOperations.ZeroMemory(inner);
        CryptographicOperations.ZeroMemory(kek);
        return blob;
    }

    private WrappedLogin? Unwrap(byte[] kek, Passkey passkey)
    {
        var blob = passkey.WrappedCredential;
        if (blob.Length <= NonceSize + TagSize) return null;
        var inner = new byte[blob.Length - NonceSize - TagSize];
        try
        {
            using (var aes = new AesGcm(kek, TagSize))
                aes.Decrypt(blob.AsSpan(0, NonceSize), blob.AsSpan(NonceSize + TagSize), blob.AsSpan(NonceSize, TagSize), inner, Aad(passkey));
            return JsonSerializer.Deserialize<WrappedLogin>(_protector.Unprotect(inner));
        }
        catch (Exception ex) when (ex is CryptographicException or JsonException)
        {
            return null; // the wrong key (an old salt), or a key ring we no longer have
        }
        finally
        {
            CryptographicOperations.ZeroMemory(inner);
            CryptographicOperations.ZeroMemory(kek);
        }
    }

    /// <summary>Binds a wrap to its owner, its passkey and its version, so a blob can't be moved or rolled back.</summary>
    private static byte[] Aad(Passkey p) => Encoding.UTF8.GetBytes($"{p.UserId}|{p.CredentialId}|{p.WrapVersion}");

    private static PasskeyCredentialDescriptor Descriptor(Passkey p) =>
        new(p.CredentialId, string.IsNullOrEmpty(p.Transports) ? null : p.Transports.Split(','));

    private static bool IsTransport(string t) => t is "usb" or "nfc" or "ble" or "internal" or "hybrid" or "smart-card";

    private static string RpId(HttpContext ctx) => ctx.Request.Host.Host;

    private string[] Origins(HttpContext ctx)
    {
        var origins = new List<string> { $"{ctx.Request.Scheme}://{ctx.Request.Host}" };
        if (settings.Current.PublicUrl is { } url && Uri.TryCreate(url, UriKind.Absolute, out var u))
            origins.Add(u.GetLeftPart(UriPartial.Authority));
        return origins.ToArray();
    }

    private static byte[] Bytes(string? base64Url)
    {
        try
        {
            return string.IsNullOrEmpty(base64Url) ? throw new WebAuthnException("The passkey's response is incomplete.") : Base64Url.DecodeFromChars(base64Url);
        }
        catch (FormatException)
        {
            throw new WebAuthnException("The passkey's response couldn't be read.");
        }
    }

    private static byte[] Key(string? base64Url)
    {
        var key = Bytes(base64Url);
        if (key.Length != KeySize)
            throw new WebAuthnException("This passkey or browser doesn't support the PRF extension, so it can't unlock your mail password.");
        return key;
    }
}
