// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

namespace Nullify.WebMail.Services;

/// <summary>
/// The name shown where the UI says "Nullify" (sidebar, sign-in page, browser tab). An admin can
/// set it for the whole instance and override it per mail domain; the domain's title wins, then
/// the instance's, then <see cref="DefaultTitle"/>. Stored as admin settings, like the Documents
/// domain settings, and kept in <see cref="BrandingCache"/> since nearly every page shows it.
/// </summary>
public sealed class BrandingService(ApiService api, UserSession session, BrandingCache cache)
{
    public const string DefaultTitle = "Nullify";
    public const int MaxLength = 64;

    public const string KeyPrefix = "branding.";
    public const string InstanceKey = KeyPrefix + "title";
    public static string DomainKey(string domain) => $"{KeyPrefix}domain.{domain.ToLowerInvariant()}.title";

    /// <summary>Pick the title to show: the domain's, else the instance's, else the default.</summary>
    public static string Resolve(string? domainTitle, string? instanceTitle) =>
        Clean(domainTitle) ?? Clean(instanceTitle) ?? DefaultTitle;

    /// <summary>Trimmed and capped, or null when blank (meaning "not set").</summary>
    public static string? Clean(string? title)
    {
        if (string.IsNullOrWhiteSpace(title)) return null;
        title = title.Trim();
        return title.Length > MaxLength ? title[..MaxLength] : title;
    }

    /// <summary>
    /// The title for <paramref name="domain"/>, or for the signed-in user's domain when omitted.
    /// Before sign-in there is no domain, so the instance title applies.
    /// </summary>
    public async Task<string> TitleAsync(string? domain = null)
    {
        domain ??= session.Credential == null ? null : AuthService.ExtractDomain(session.Credential.Login);
        var domainTitle = string.IsNullOrEmpty(domain) ? null : await Setting(DomainKey(domain));
        return Resolve(domainTitle, await Setting(InstanceKey));
    }

    /// <summary>The instance-wide title as set by an admin, or null when not set.</summary>
    public async Task<string?> InstanceTitleAsync() => Clean(await Setting(InstanceKey));

    /// <summary>The domain's own title as set by an admin, or null when it falls back to the instance's.</summary>
    public async Task<string?> DomainTitleAsync(string domain) => Clean(await Setting(DomainKey(domain)));

    public async Task SetInstanceTitleAsync(string? title)
    {
        RequireAdmin();
        await api.SetAdminSettingAsync(InstanceKey, Clean(title));
    }

    public async Task SetDomainTitleAsync(string domain, string? title)
    {
        RequireAdmin();
        await api.SetAdminSettingAsync(DomainKey(domain), Clean(title));
    }

    private Task<string?> Setting(string key) => cache.GetAsync(key, api.GetAdminSettingAsync);

    private void RequireAdmin()
    {
        if (!session.IsAdmin) throw new UnauthorizedAccessException("Only administrators can change the title.");
    }
}

/// <summary>
/// Branding admin settings held in memory for the life of the process. Every write to
/// AdminSettings calls <see cref="Invalidate"/>, so a changed title shows on the next page load.
/// </summary>
public sealed class BrandingCache
{
    private readonly Dictionary<string, string?> values = new();
    private long version;

    public async Task<string?> GetAsync(string key, Func<string, Task<string?>> load)
    {
        long before;
        lock (values)
        {
            if (values.TryGetValue(key, out var cached)) return cached;
            before = version;
        }
        var value = await load(key);
        // A write that landed while this was loading may not be in value; don't keep it then.
        lock (values)
        {
            if (version == before) values[key] = value;
        }
        return value;
    }

    /// <summary>Call after an admin setting is saved. Keys outside branding are ignored.</summary>
    public void Invalidate(string key)
    {
        if (!key.StartsWith(BrandingService.KeyPrefix, StringComparison.Ordinal)) return;
        lock (values)
        {
            version++;
            values.Remove(key);
        }
    }
}
