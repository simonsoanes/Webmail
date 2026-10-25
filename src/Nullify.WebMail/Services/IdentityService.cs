// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Nullify.WebMail.Data;
using Nullify.WebMail.Shared;

namespace Nullify.WebMail.Services;

/// <summary>
/// Who a user can send as: their sign-in address with their display name, plus aliases they
/// add themselves at domains the administrator has opened for aliases. Every send and draft is
/// checked here, so a From address can't be set to anything else by editing the request.
/// </summary>
public sealed class IdentityService(IDbContextFactory<AppDbContext> dbFactory, WriteGate gate)
{
    public const string AliasesKey = "identity.aliases";
    public const int MaxAliases = 50;
    public const int MaxNameLength = 128;

    public static string DomainAliasesKey(string domain) => $"send.domain.{domain.Trim().ToLowerInvariant()}.aliases";

    public async Task<IdentitySettingsDto> GetAsync(string login)
    {
        await using var db = await dbFactory.CreateDbContextAsync();
        var user = await db.Users.FirstOrDefaultAsync(u => u.Username == login);
        var aliases = user == null ? [] : await LoadAliases(db, user.Id);
        return new IdentitySettingsDto(user?.DisplayName, login, aliases, await AliasDomainsAsync(db));
    }

    /// <summary>Every address the user may send as, the sign-in address first.</summary>
    public async Task<IReadOnlyList<SenderIdentity>> SendersAsync(string login)
    {
        var settings = await GetAsync(login);
        var list = new List<SenderIdentity> { new(settings.DisplayName ?? "", login) };
        list.AddRange(settings.Aliases.Where(a => DomainAllowed(a.Email, settings.AliasDomains)));
        return list;
    }

    public async Task SetDisplayNameAsync(string login, string? name)
    {
        name = CleanName(name);
        await using var db = await dbFactory.CreateDbContextAsync();
        using (await gate.EnterAsync())
        {
            var user = await db.Users.FirstOrDefaultAsync(u => u.Username == login)
                ?? throw new InvalidOperationException("Your account could not be found.");
            user.DisplayName = name.Length == 0 ? null : name;
            await db.SaveChangesAsync();
        }
    }

    /// <summary>Add an alias, or rename one that already exists.</summary>
    /// <exception cref="InvalidOperationException">Not an address, or not at an allowed domain.</exception>
    public async Task SaveAliasAsync(string login, string name, string email)
    {
        email = email.Trim();
        if (!LooksLikeAddress(email)) throw new InvalidOperationException($"\"{email}\" isn't an email address.");
        if (email.Equals(login, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("That's your sign-in address; set its name under Display name.");
        await using var db = await dbFactory.CreateDbContextAsync();
        if (!DomainAllowed(email, await AliasDomainsAsync(db)))
            throw new InvalidOperationException($"Your administrator doesn't allow aliases at {DomainOf(email)}.");
        await UpdateAliases(db, login, list =>
        {
            var existing = list.FindIndex(a => a.Email.Equals(email, StringComparison.OrdinalIgnoreCase));
            var alias = new SenderIdentity(CleanName(name), email);
            if (existing >= 0) list[existing] = alias;
            else if (list.Count >= MaxAliases) throw new InvalidOperationException($"You can have up to {MaxAliases} aliases.");
            else list.Add(alias);
        });
    }

    public async Task RemoveAliasAsync(string login, string email)
    {
        await using var db = await dbFactory.CreateDbContextAsync();
        await UpdateAliases(db, login, list =>
            list.RemoveAll(a => a.Email.Equals(email.Trim(), StringComparison.OrdinalIgnoreCase)));
    }

    /// <summary>
    /// The From header to send with: <paramref name="from"/> when its address is one the user
    /// may send as (their name for it is used), else an exception.
    /// </summary>
    public async Task<string> ResolveFromAsync(string login, string? from)
    {
        var senders = await SendersAsync(login);
        var address = string.IsNullOrWhiteSpace(from) ? login : MailService.ExtractAddress(from);
        var match = senders.FirstOrDefault(s => s.Email.Equals(address, StringComparison.OrdinalIgnoreCase))
            ?? throw new UnauthorizedAccessException($"You can't send as {address}. Add it as an alias in Settings first.");
        return match.ToString();
    }

    // ---- admin ----

    public async Task<bool> DomainAllowsAliasesAsync(string domain)
    {
        await using var db = await dbFactory.CreateDbContextAsync();
        var key = DomainAliasesKey(domain);
        return await db.AdminSettings.AnyAsync(s => s.Key == key && s.Value == "true");
    }

    public async Task SetDomainAllowsAliasesAsync(string domain, bool allowed)
    {
        await using var db = await dbFactory.CreateDbContextAsync();
        var key = DomainAliasesKey(domain);
        using (await gate.EnterAsync())
        {
            var setting = await db.AdminSettings.FirstOrDefaultAsync(s => s.Key == key);
            if (setting == null) db.AdminSettings.Add(new AdminSetting { Key = key, Value = allowed ? "true" : "false" });
            else setting.Value = allowed ? "true" : "false";
            await db.SaveChangesAsync();
        }
    }

    // ---- helpers ----

    /// <summary>Configured domains whose aliases the administrator has turned on.</summary>
    private static async Task<IReadOnlyList<string>> AliasDomainsAsync(AppDbContext db)
    {
        var domains = await db.Domains.Select(d => d.Name).ToListAsync();
        var on = await db.AdminSettings.Where(s => s.Key.StartsWith("send.domain.") && s.Value == "true")
            .Select(s => s.Key).ToListAsync();
        return domains.Where(d => on.Contains(DomainAliasesKey(d))).Order(StringComparer.Ordinal).ToList();
    }

    public static bool DomainAllowed(string email, IReadOnlyCollection<string> domains) =>
        domains.Contains(DomainOf(email), StringComparer.OrdinalIgnoreCase);

    public static string DomainOf(string email)
    {
        var at = email.LastIndexOf('@');
        return at < 0 ? "" : email[(at + 1)..].Trim().ToLowerInvariant();
    }

    public static bool LooksLikeAddress(string email)
    {
        var at = email.IndexOf('@');
        return at > 0 && at == email.LastIndexOf('@') && at < email.Length - 3 && email.Length <= 254
            && email[(at + 1)..].Contains('.') && !email.Any(c => char.IsWhiteSpace(c) || c is '<' or '>' or '"' or ',' or ';' or '(' or ')' || char.IsControl(c));
    }

    /// <summary>A display name safe to put in a header: one line, no quotes or brackets that would confuse parsers.</summary>
    public static string CleanName(string? name)
    {
        var cleaned = new string((name ?? "").Where(c => !char.IsControl(c) && c is not ('<' or '>' or '"')).ToArray()).Trim();
        return cleaned.Length > MaxNameLength ? cleaned[..MaxNameLength].Trim() : cleaned;
    }

    private static async Task<List<SenderIdentity>> LoadAliases(AppDbContext db, int userId)
    {
        var json = await db.UserPreferences.Where(p => p.UserId == userId && p.Key == AliasesKey)
            .Select(p => p.Value).FirstOrDefaultAsync();
        if (string.IsNullOrEmpty(json)) return [];
        try { return JsonSerializer.Deserialize<List<SenderIdentity>>(json) ?? []; }
        catch (JsonException) { return []; }
    }

    private async Task UpdateAliases(AppDbContext db, string login, Action<List<SenderIdentity>> change)
    {
        using (await gate.EnterAsync())
        {
            var user = await db.Users.FirstOrDefaultAsync(u => u.Username == login)
                ?? throw new InvalidOperationException("Your account could not be found.");
            var list = await LoadAliases(db, user.Id);
            change(list);
            var json = JsonSerializer.Serialize(list.OrderBy(a => a.Email, StringComparer.OrdinalIgnoreCase));
            var pref = await db.UserPreferences.FirstOrDefaultAsync(p => p.UserId == user.Id && p.Key == AliasesKey);
            if (pref == null) db.UserPreferences.Add(new UserPreference { UserId = user.Id, Key = AliasesKey, Value = json });
            else pref.Value = json;
            await db.SaveChangesAsync();
        }
    }
}
