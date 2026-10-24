// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Nullify.WebMail.Data;
using Nullify.WebMail.Shared;

namespace Nullify.WebMail.Services;

/// <summary>
/// Storage for the user's OpenPGP keys. All cryptography happens in the browser
/// (wwwroot/js/pgp); this only keeps the already-protected key blobs and preferences.
/// </summary>
public sealed class PgpService(UserSession session, ApiService api, IDbContextFactory<AppDbContext> dbFactory, WriteGate gate)
{
    private const string DefaultKey = "pgp.default", SignKey = "pgp.signByDefault", EncryptKey = "pgp.encryptWhenPossible";
    private static string MetaKey(string fpr) => $"pgp.key.{fpr}";

    private sealed record Meta(PgpProtection Protection, string? CredentialId, string? PrfSalt);

    private string Login => session.Credential?.Login ?? throw new InvalidOperationException("Not authenticated.");

    public async Task<IReadOnlyList<PgpKeyRecord>> ListAsync()
    {
        await using var db = await dbFactory.CreateDbContextAsync();
        var userId = await UserIdAsync(db);
        if (userId == null) return [];
        var rows = await db.PgpKeys.Where(k => k.UserId == userId).OrderBy(k => k.CreatedUtc).ToListAsync();
        var prefs = (await api.GetPreferencesAsync()).ToDictionary(p => p.Key, p => p.Value);
        var defaultFpr = prefs.GetValueOrDefault(DefaultKey);
        return rows.Where(r => !string.IsNullOrEmpty(r.ArmoredPrivateKey)).Select(r =>
        {
            var meta = prefs.GetValueOrDefault(MetaKey(r.KeyId)) is { } json ? JsonSerializer.Deserialize<Meta>(json) : null;
            return new PgpKeyRecord(r.KeyId, r.UserIds ?? "", r.ArmoredPublicKey, r.ArmoredPrivateKey, r.CreatedUtc, r.ExpiresUtc,
                meta?.Protection ?? PgpProtection.Passphrase, meta?.CredentialId, meta?.PrfSalt,
                defaultFpr == r.KeyId || (defaultFpr == null && r == rows[0]));
        }).ToList();
    }

    /// <summary>Add or replace a key (e.g. after changing its protection).</summary>
    public async Task SaveAsync(PgpKeyRecord key)
    {
        if (!key.SecretKey.Contains("BEGIN PGP PRIVATE KEY BLOCK"))
            throw new InvalidOperationException("Only protected secret keys are stored here.");
        await using var db = await dbFactory.CreateDbContextAsync();
        var userId = await UserIdAsync(db) ?? throw new InvalidOperationException("Unknown user.");
        using (await gate.EnterAsync())
        {
            var row = await db.PgpKeys.FirstOrDefaultAsync(k => k.UserId == userId && k.KeyId == key.Fingerprint);
            if (row == null)
            {
                row = new PgpKey { UserId = userId, KeyId = key.Fingerprint };
                db.PgpKeys.Add(row);
            }
            row.UserIds = key.UserId.Length > 512 ? key.UserId[..512] : key.UserId;
            row.ArmoredPublicKey = key.PublicKey;
            row.ArmoredPrivateKey = key.SecretKey;
            row.CreatedUtc = key.CreatedUtc;
            row.ExpiresUtc = key.ExpiresUtc;
            await db.SaveChangesAsync();
        }
        await api.SetPreferenceAsync(MetaKey(key.Fingerprint),
            JsonSerializer.Serialize(new Meta(key.Protection, key.CredentialId, key.PrfSalt)));
        if (key.IsDefault) await api.SetPreferenceAsync(DefaultKey, key.Fingerprint);
    }

    public async Task DeleteAsync(string fingerprint)
    {
        await using var db = await dbFactory.CreateDbContextAsync();
        var userId = await UserIdAsync(db);
        using (await gate.EnterAsync())
        {
            var row = await db.PgpKeys.FirstOrDefaultAsync(k => k.UserId == userId && k.KeyId == fingerprint);
            if (row != null) { db.PgpKeys.Remove(row); await db.SaveChangesAsync(); }
        }
        await api.SetPreferenceAsync(MetaKey(fingerprint), null);
        var prefs = await api.GetPreferencesAsync();
        if (prefs.FirstOrDefault(p => p.Key == DefaultKey)?.Value == fingerprint) await api.SetPreferenceAsync(DefaultKey, null);
    }

    public Task SetDefaultAsync(string fingerprint) => api.SetPreferenceAsync(DefaultKey, fingerprint);

    public async Task<PgpSettingsDto> GetSettingsAsync()
    {
        var prefs = (await api.GetPreferencesAsync()).ToDictionary(p => p.Key, p => p.Value);
        return new PgpSettingsDto(prefs.GetValueOrDefault(SignKey) == "true", prefs.GetValueOrDefault(EncryptKey) != "false");
    }

    public async Task SaveSettingsAsync(PgpSettingsDto s)
    {
        await api.SetPreferenceAsync(SignKey, s.SignByDefault ? "true" : "false");
        await api.SetPreferenceAsync(EncryptKey, s.EncryptWhenPossible ? "true" : "false");
    }

    private async Task<int?> UserIdAsync(AppDbContext db) =>
        await db.Users.Where(u => u.Username == Login).Select(u => (int?)u.Id).FirstOrDefaultAsync();
}
