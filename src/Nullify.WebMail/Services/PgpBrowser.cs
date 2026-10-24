// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using System.Text;
using Microsoft.AspNetCore.Components;
using Microsoft.JSInterop;
using Nullify.WebMail.Shared;

namespace Nullify.WebMail.Services;

/// <summary>Summary of an OpenPGP key, computed in the browser.</summary>
public sealed record PgpKeyInfo(
    string Fingerprint, string KeyId, string Algorithm, string[] UserIds, string? PrimaryUserId,
    DateTime Created, DateTime? Expires, bool Expired, bool Revoked, bool Valid,
    bool CanEncrypt, bool CanSign, bool HasSecret, bool SecretOnCard, bool IsSecret,
    string[] KeyIds, string[] Emails);

/// <summary>
/// A secret key as the browser protected it, and how. Deliberately has no passphrase: those never
/// leave the browser (see wwwroot/js/pgp-bridge.js).
/// </summary>
public sealed record PgpProtectedKey(PgpKeyInfo Summary, string PublicKey, string SecretKey, bool SecurityKey, string? CredentialId, string? Salt)
{
    public PgpProtection Protection => SecurityKey ? PgpProtection.SecurityKey : PgpProtection.Passphrase;
}

/// <summary>A stored key re-protected in the browser.</summary>
public sealed record PgpReprotectedKey(string SecretKey, bool SecurityKey, string? CredentialId, string? Salt)
{
    public PgpProtection Protection => SecurityKey ? PgpProtection.SecurityKey : PgpProtection.Passphrase;
}

public sealed record PgpSignatureResult(string? KeyId, string? Fingerprint, string? Created, bool Valid, string Status, string? Signer);

public sealed record PgpDecrypted(byte[] Data, string? Filename, string Format, PgpSignatureResult[] Signatures);

public sealed record PgpCleartext(string Text, PgpSignatureResult[] Signatures);

/// <summary>A failure reported by the browser-side OpenPGP engine, with a user-facing message.</summary>
public sealed class PgpException(string message, bool locked = false) : Exception(message)
{
    /// <summary>The operation needs a key the user hasn't unlocked yet.</summary>
    public bool Locked { get; } = locked;
}

/// <summary>
/// Circuit-scoped handle on wwwroot/js/pgp-bridge.js. All OpenPGP work, and every unlocked
/// secret key, stays in the browser; this only passes data across.
/// Passphrases must never pass through here: anything .NET holds is on the server. Methods that
/// need one take the input elements instead, and the browser reads and clears them itself.
/// </summary>
public sealed class PgpBrowser(IJSRuntime js) : IAsyncDisposable
{
    private const long MaxBytes = 256L * 1024 * 1024;
    private IJSObjectReference? _module;

    private async Task<IJSObjectReference> Module() =>
        _module ??= await js.InvokeAsync<IJSObjectReference>("import", "./js/pgp-bridge.js");

    private async Task<T> Call<T>(string fn, params object?[] args)
    {
        try { return await (await Module()).InvokeAsync<T>(fn, args); }
        catch (JSException ex) { throw Wrap(ex); }
    }

    private async Task Call(string fn, params object?[] args)
    {
        try { await (await Module()).InvokeVoidAsync(fn, args); }
        catch (JSException ex) { throw Wrap(ex); }
    }

    private static PgpException Wrap(JSException ex)
    {
        // JSException messages carry the JS stack after the first line.
        var message = ex.Message.Split('\n')[0].Trim();
        var locked = message.StartsWith("LOCKED:", StringComparison.Ordinal);
        return new PgpException(locked ? message["LOCKED:".Length..].Trim() : message, locked);
    }

    private async Task<byte[]> Take(int id)
    {
        var stream = await Call<IJSStreamReference>("take", id);
        await using var s = await stream.OpenReadStreamAsync(MaxBytes);
        using var ms = new MemoryStream();
        await s.CopyToAsync(ms);
        return ms.ToArray();
    }

    private static DotNetStreamReference Stream(byte[] data) => new(new MemoryStream(data), leaveOpen: false);

    // ---- keys

    public Task<PgpKeyInfo[]> InspectAsync(string armored) => Call<PgpKeyInfo[]>("inspect", armored);

    // Element arguments are ElementReference?; null where the form doesn't show that field.
    // "protection" is the ProtectionChooser option name: Keep, Passphrase or SecurityKey.

    private static object Current(PgpKeyRecord k) =>
        new { securityKey = k.Protection == PgpProtection.SecurityKey, credentialId = k.CredentialId, salt = k.PrfSalt };

    /// <summary>Generate a key protected as chosen; it stays unlocked in the browser.</summary>
    public Task<PgpProtectedKey> GenerateAsync(IReadOnlyList<string> userIds, string kind, int expiresInDays, string protection,
        ElementReference? passphrase, ElementReference? confirm) =>
        Call<PgpProtectedKey>("generate", new { userIds, kind, expiresInDays, protection }, passphrase, confirm);

    /// <summary>Import the secret key typed or pasted into <paramref name="keyText"/>; it stays unlocked in the browser.</summary>
    public Task<PgpProtectedKey> ImportAsync(IReadOnlyList<string> existingFingerprints, string protection,
        ElementReference keyText, ElementReference currentPassphrase, ElementReference? passphrase, ElementReference? confirm) =>
        Call<PgpProtectedKey>("importKey", new { existing = existingFingerprints, protection }, keyText, currentPassphrase, passphrase, confirm);

    /// <summary>Let a file input fill the import box in the browser, so the key file never reaches the server.</summary>
    public Task AttachKeyFileAsync(ElementReference fileInput, ElementReference keyText) => Call("attachKeyFile", fileInput, keyText);

    public Task<PgpReprotectedKey> ChangeProtectionAsync(PgpKeyRecord key, string protection,
        ElementReference? currentPassphrase, ElementReference? passphrase, ElementReference? confirm) =>
        Call<PgpReprotectedKey>("changeProtection", new { secretArmored = key.SecretKey, current = Current(key), protection, label = key.UserId },
            currentPassphrase, passphrase, confirm);

    /// <summary>Download a copy of the key protected with a new backup passphrase.</summary>
    public Task BackupAsync(PgpKeyRecord key, string filename,
        ElementReference? currentPassphrase, ElementReference? passphrase, ElementReference? confirm) =>
        Call("backup", new { secretArmored = key.SecretKey, current = Current(key), filename }, currentPassphrase, passphrase, confirm);

    public Task<PgpKeyInfo> UnlockAsync(PgpKeyRecord key, ElementReference passphrase) =>
        Call<PgpKeyInfo>("unlockFromInput", key.Fingerprint, key.SecretKey, passphrase);

    public Task<PgpKeyInfo> UnlockWithSecurityKeyAsync(string fingerprint, string secretKey, string credentialId, string salt) =>
        Call<PgpKeyInfo>("unlockWithSecurityKey", fingerprint, secretKey, credentialId, salt);

    public Task<bool> IsUnlockedAsync(string fingerprint) => Call<bool>("isUnlocked", fingerprint);
    public Task LockAsync(string fingerprint) => Call("lock", fingerprint);
    public Task LockAllAsync() => Call("lockAll");

    public Task<string> PublicOfAsync(string armored) => Call<string>("publicOf", armored);

    public Task<bool> SecurityKeySupportedAsync() => Call<bool>("securityKeySupported");

    // ---- messages

    /// <summary>Encrypt to the recipients' public keys (include your own to read it in Sent), optionally signing.</summary>
    public async Task<string> EncryptAsync(byte[] data, IReadOnlyList<string> recipientKeys, string? signerFingerprint)
    {
        var id = await Call<int>("encrypt", Stream(data), recipientKeys, signerFingerprint);
        return Encoding.ASCII.GetString(await Take(id));
    }

    public Task<string> SignDetachedAsync(byte[] data, string signerFingerprint) =>
        Call<string>("signDetached", Stream(data), signerFingerprint);

    public Task<string[]> RecipientsAsync(string armored) => Call<string[]>("recipients", armored);

    private sealed record DecryptMeta(int Id, string? Filename, string Format, PgpSignatureResult[] Signatures);

    public async Task<PgpDecrypted> DecryptAsync(string armored, IReadOnlyList<string> verificationKeys)
    {
        var meta = await Call<DecryptMeta>("decrypt", armored, verificationKeys);
        return new PgpDecrypted(await Take(meta.Id), meta.Filename, meta.Format, meta.Signatures);
    }

    public Task<PgpSignatureResult[]> VerifyDetachedAsync(byte[] data, string signature, IReadOnlyList<string> keys) =>
        Call<PgpSignatureResult[]>("verifyDetached", Stream(data), signature, keys);

    public Task<PgpCleartext> VerifyCleartextAsync(string text, IReadOnlyList<string> keys) =>
        Call<PgpCleartext>("verifyCleartext", text, keys);

    public Task DownloadAsync(string filename, byte[] data, string mime) => Call("download", filename, Stream(data), mime);

    public async ValueTask DisposeAsync()
    {
        if (_module == null) return;
        try { await _module.DisposeAsync(); } catch (JSDisconnectedException) { }
    }
}
