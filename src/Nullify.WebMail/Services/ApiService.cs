// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using Microsoft.EntityFrameworkCore;
using Nullify.WebMail.Data;
using Nullify.WebMail.Shared;

namespace Nullify.WebMail.Services;

/// <summary>
/// In-process data facade consumed by Blazor components. Everything runs directly
/// against services and the DB — no HTTP loopback (a server-side HttpClient can
/// never carry or set the browser's auth cookie).
/// </summary>
public class ApiService(
    UserSession session,
    MailService mail,
    IDbContextFactory<AppDbContext> dbFactory,
    ManageSieveClient sieve,
    WriteGate gate,
    BrandingCache brandingCache)
{
    private CredentialInfo Cred =>
        session.Credential ?? throw new InvalidOperationException("Not authenticated.");

    // ---- Session ----

    public Task<SessionInfo?> GetSessionAsync() => Task.FromResult(
        session.Credential == null
            ? null
            : new SessionInfo(session.Credential.Login, session.Credential.Login, session.Credential.Login));

    public Task<bool> IsAdminAsync() => Task.FromResult(session.IsAdmin);

    public async Task<bool> HasUsersAsync()
    {
        await using var db = await dbFactory.CreateDbContextAsync();
        return await db.Users.AnyAsync();
    }

    // ---- Mail ----

    public Task<IReadOnlyList<FolderInfo>> GetFoldersAsync() => mail.GetFoldersAsync(Cred);

    public async Task<MessagePage?> GetMessagesAsync(string folderName, int page = 0, int pageSize = 50) =>
        await mail.GetMessagesAsync(Cred, folderName, page, pageSize);

    public async Task<MessageContent?> GetMessageAsync(string folderName, long uid) =>
        await mail.GetMessageAsync(Cred, folderName, uid);

    public Task SetFlagsAsync(string folderName, long uid, string? addFlags, string? removeFlags) =>
        mail.SetFlagsAsync(Cred, folderName, uid, addFlags ?? "", removeFlags ?? "");

    public Task MoveAsync(string folderName, long uid, string destination) =>
        mail.MoveAsync(Cred, folderName, uid, destination);

    public Task SetFlagsAsync(string folderName, IReadOnlyCollection<long> uids, string? addFlags, string? removeFlags) =>
        mail.SetFlagsAsync(Cred, folderName, uids, addFlags ?? "", removeFlags ?? "");

    public Task MoveAsync(string folderName, IReadOnlyCollection<long> uids, string destination) =>
        mail.MoveAsync(Cred, folderName, uids, destination);

    /// <summary>Moves to Trash (or purges when already there). Returns true when permanent.</summary>
    public Task<bool> DeleteAsync(string folderName, IReadOnlyCollection<long> uids) =>
        mail.DeleteAsync(Cred, folderName, uids);

    public Task<bool> DeleteAsync(string folderName, long uid) =>
        mail.DeleteAsync(Cred, folderName, [uid]);

    public Task<string?> SaveDraftAsync(SendRequest request) => mail.SaveDraftAsync(Cred, request);

    public Task<MimeAttachment?> GetAttachmentAsync(string folderName, long uid, string partId) =>
        mail.GetAttachmentAsync(Cred, folderName, uid, partId);

    public Task SendAsync(SendRequest request, string? bodyEntity = null) => mail.SendAsync(Cred, request, bodyEntity);

    public Task<IReadOnlyList<MessageSummary>> SearchAsync(string folderName, string query, int limit = 50) =>
        mail.SearchAsync(Cred, folderName, query, limit);

    public Task CreateFolderAsync(string name) => mail.CreateFolderAsync(Cred, name);

    public Task DeleteFolderAsync(string name) => mail.DeleteFolderAsync(Cred, name);

    public Task RenameFolderAsync(string oldName, string newName) => mail.RenameFolderAsync(Cred, oldName, newName);

    // ---- Preferences ----

    public async Task<IReadOnlyList<PreferenceDto>> GetPreferencesAsync()
    {
        await using var db = await dbFactory.CreateDbContextAsync();
        var userId = await FindUserId(db);
        if (userId == null) return Array.Empty<PreferenceDto>();
        var prefs = await db.UserPreferences.Where(p => p.UserId == userId.Value).ToListAsync();
        return prefs.Select(p => new PreferenceDto(p.Key, p.Value)).ToList();
    }

    public async Task SetPreferenceAsync(string key, string? value)
    {
        await using var db = await dbFactory.CreateDbContextAsync();
        var userId = await FindUserId(db);
        if (userId == null) return;

        using (await gate.EnterAsync())
        {
            var pref = await db.UserPreferences
                .FirstOrDefaultAsync(p => p.UserId == userId.Value && p.Key == key);
            if (pref == null)
            {
                db.UserPreferences.Add(new UserPreference { UserId = userId.Value, Key = key, Value = value });
            }
            else
            {
                pref.Value = value;
            }
            await db.SaveChangesAsync();
        }
    }

    private async Task<int?> FindUserId(AppDbContext db)
    {
        var username = session.Credential?.Login;
        if (username == null) return null;
        return await db.Users.Where(u => u.Username == username).Select(u => (int?)u.Id).FirstOrDefaultAsync();
    }

    // ---- Sieve ----

    public async Task<IReadOnlyList<SieveScriptDto>> GetSieveScriptsAsync()
    {
        try
        {
            await using var s = await ConnectSieveAsync();
            var scripts = await s.ListScriptsAsync();
            return scripts.Select(x => new SieveScriptDto(x.Name, x.IsActive, "")).ToList();
        }
        catch
        {
            return Array.Empty<SieveScriptDto>();
        }
    }

    public async Task<SieveScriptDto?> GetSieveScriptAsync(string name)
    {
        await using var s = await ConnectSieveAsync();
        var content = await s.GetScriptAsync(name);
        var scripts = await s.ListScriptsAsync();
        var isActive = scripts.FirstOrDefault(x => x.Name == name)?.IsActive ?? false;
        return new SieveScriptDto(name, isActive, content);
    }

    public async Task PutSieveScriptAsync(string name, string content)
    {
        await using var s = await ConnectSieveAsync();
        await s.PutScriptAsync(name, content);
    }

    public async Task DeleteSieveScriptAsync(string name)
    {
        await using var s = await ConnectSieveAsync();
        await s.DeleteScriptAsync(name);
    }

    public async Task ActivateSieveScriptAsync(string name)
    {
        await using var s = await ConnectSieveAsync();
        await s.SetActiveAsync(name);
    }

    private async Task<ManageSieveSession> ConnectSieveAsync()
    {
        var endpoint = SieveEndpoint.For(Cred.SieveHost, Cred.SievePort);
        var s = await sieve.ConnectAndLoginAsync(endpoint, Cred.Login, Cred.Password);
        return s;
    }

    // ---- Admin: domains ----

    public async Task<IReadOnlyList<DomainDto>> GetDomainsAsync()
    {
        await using var db = await dbFactory.CreateDbContextAsync();
        var domains = await db.Domains.OrderBy(d => d.Name).ToListAsync();
        return domains.Select(d => new DomainDto(
            d.Name, d.ImapHost, d.ImapPort, d.ImapSecurity, d.ImapAllowInvalidCertificates,
            d.SmtpHost, d.SmtpPort, d.SmtpSecurity, d.SieveHost, d.SievePort,
            d.CalDavUrl, d.CardDavUrl, d.CreatedUtc)).ToList();
    }

    public async Task CreateDomainAsync(DomainDto dto)
    {
        await using var db = await dbFactory.CreateDbContextAsync();
        using (await gate.EnterAsync())
        {
            var name = dto.Name.Trim().ToLowerInvariant();
            if (await db.Domains.AnyAsync(d => d.Name == name))
                throw new InvalidOperationException($"Domain '{name}' already exists.");
            db.Domains.Add(new Domain
            {
                Name = name,
                ImapHost = dto.ImapHost, ImapPort = dto.ImapPort, ImapSecurity = dto.ImapSecurity,
                ImapAllowInvalidCertificates = dto.ImapAllowInvalidCertificates,
                SmtpHost = dto.SmtpHost, SmtpPort = dto.SmtpPort, SmtpSecurity = dto.SmtpSecurity,
                SieveHost = dto.SieveHost, SievePort = dto.SievePort,
                CalDavUrl = dto.CalDavUrl, CardDavUrl = dto.CardDavUrl,
            });
            await db.SaveChangesAsync();
        }
    }

    public async Task UpdateDomainAsync(string name, DomainDto dto)
    {
        name = name.Trim().ToLowerInvariant();
        await using var db = await dbFactory.CreateDbContextAsync();
        using (await gate.EnterAsync())
        {
            var domain = await db.Domains.FirstOrDefaultAsync(d => d.Name == name)
                ?? throw new InvalidOperationException($"Domain '{name}' not found.");
            domain.ImapHost = dto.ImapHost; domain.ImapPort = dto.ImapPort; domain.ImapSecurity = dto.ImapSecurity;
            domain.ImapAllowInvalidCertificates = dto.ImapAllowInvalidCertificates;
            domain.SmtpHost = dto.SmtpHost; domain.SmtpPort = dto.SmtpPort; domain.SmtpSecurity = dto.SmtpSecurity;
            domain.SieveHost = dto.SieveHost; domain.SievePort = dto.SievePort;
            domain.CalDavUrl = dto.CalDavUrl; domain.CardDavUrl = dto.CardDavUrl;
            await db.SaveChangesAsync();
        }
    }

    public async Task DeleteDomainAsync(string name)
    {
        name = name.Trim().ToLowerInvariant();
        await using var db = await dbFactory.CreateDbContextAsync();
        using (await gate.EnterAsync())
        {
            var domain = await db.Domains.FirstOrDefaultAsync(d => d.Name == name);
            if (domain == null) return;
            db.Domains.Remove(domain);
            await db.SaveChangesAsync();
        }
    }

    // ---- Admin: settings ----

    public async Task<IReadOnlyList<AdminSettingDto>> GetAdminSettingsAsync()
    {
        await using var db = await dbFactory.CreateDbContextAsync();
        var settings = await db.AdminSettings.OrderBy(s => s.Key).ToListAsync();
        return settings.Select(s => new AdminSettingDto(s.Key, s.Value)).ToList();
    }

    public async Task<string?> GetAdminSettingAsync(string key)
    {
        await using var db = await dbFactory.CreateDbContextAsync();
        return (await db.AdminSettings.FirstOrDefaultAsync(s => s.Key == key))?.Value;
    }

    public async Task SetAdminSettingAsync(string key, string? value)
    {
        await using var db = await dbFactory.CreateDbContextAsync();
        using (await gate.EnterAsync())
        {
            var setting = await db.AdminSettings.FirstOrDefaultAsync(s => s.Key == key);
            if (setting == null)
            {
                db.AdminSettings.Add(new AdminSetting { Key = key, Value = value });
            }
            else
            {
                setting.Value = value;
            }
            await db.SaveChangesAsync();
        }
        brandingCache.Invalidate(key);
    }

    // ---- Admin: users ----

    public async Task<IReadOnlyList<UserDto>> GetUsersAsync()
    {
        await using var db = await dbFactory.CreateDbContextAsync();
        var users = await db.Users.OrderBy(u => u.Username).ToListAsync();
        return users.Select(u => new UserDto(u.Username, u.Email, u.IsAdmin, u.CreatedUtc, u.LastLoginUtc)).ToList();
    }

    public async Task SetUserAdminAsync(string username, bool isAdmin)
    {
        await using var db = await dbFactory.CreateDbContextAsync();
        using (await gate.EnterAsync())
        {
            var user = await db.Users.FirstOrDefaultAsync(u => u.Username == username)
                ?? throw new InvalidOperationException($"User '{username}' not found.");
            user.IsAdmin = isAdmin;
            await db.SaveChangesAsync();
        }
    }
}

public enum ComposeMode { New, Reply, ReplyAll, Forward }

public sealed record Toast(int Id, string Message, bool IsError);

public class AppState
{
    public bool IsAuthenticated { get; set; }
    public bool IsAdmin { get; set; }
    /// <summary>Show the Documents menu (WebDAV enabled for this user or their domain).</summary>
    public bool DocumentsAvailable { get; set; }
    /// <summary>Shown where the UI says "Nullify" (see <see cref="BrandingService"/>).</summary>
    public string BrandTitle { get; set; } = BrandingService.DefaultTitle;
    public SessionInfo? Session { get; set; }
    public string? SelectedFolder { get; set; } = "INBOX";
    public long? SelectedMessageUid { get; set; }
    public bool ShowCompose { get; set; }
    public ComposeMode ComposeMode { get; set; }
    /// <summary>Message being replied to / forwarded (folder + UID), when <see cref="ComposeMode"/> isn't New.</summary>
    public string? ComposeSourceFolder { get; set; }
    public long? ComposeSourceUid { get; set; }
    /// <summary>Recipient to prefill in a new message (e.g. from Contacts); consumed by the form.</summary>
    public string? ComposeTo { get; set; }
    public IReadOnlyList<FolderInfo> Folders { get; set; } = Array.Empty<FolderInfo>();

    /// <summary>The message rows currently shown (one page or search results).</summary>
    public IReadOnlyList<MessageSummary> CurrentMessages { get; set; } = Array.Empty<MessageSummary>();
    public int CurrentTotal { get; set; }
    public int CurrentPage { get; set; }
    public bool IsSearching { get; set; }

    /// <summary>Messages ticked for bulk actions in the list.</summary>
    public HashSet<long> CheckedUids { get; } = new();

    /// <summary>Messages being dragged onto a folder.</summary>
    public IReadOnlyCollection<long> DraggingUids { get; set; } = Array.Empty<long>();

    /// <summary>Set by the open compose form so Ctrl+Enter can send from anywhere.</summary>
    public Func<Task>? SendHandler { get; set; }

    /// <summary>Raised when a new compose session starts (so the form re-initialises).</summary>
    public event Action? ComposeOpened;
    public string ActiveTab { get; set; } = "mail";

    /// <summary>The browser's time zone (resolved on circuit start); server local until then.</summary>
    public TimeZoneInfo TimeZone { get; set; } = TimeZoneInfo.Local;

    // Cached compose preferences.
    public string Signature { get; set; } = "";
    public string ComposeFont { get; set; } = "sans-serif";

    /// <summary>Bump to force the message list to refetch (e.g. after delete/move).</summary>
    public int ListVersion { get; set; }

    /// <summary>Bump to make the folder list refetch counts.</summary>
    public int FoldersVersion { get; set; }

    public event Action? StateChanged;
    public void NotifyStateChanged() => StateChanged?.Invoke();

    public void StartCompose(ComposeMode mode, string? folder = null, long? uid = null, string? to = null)
    {
        ComposeTo = mode == ComposeMode.New ? to : null;
        ShowCompose = true;
        ComposeMode = mode;
        ComposeSourceFolder = mode == ComposeMode.New ? null : folder;
        ComposeSourceUid = mode == ComposeMode.New ? null : uid;
        ComposeOpened?.Invoke();
        NotifyStateChanged();
    }

    /// <summary>Optimistically adjust a folder's unread badge without a server round-trip.</summary>
    public void AdjustUnread(string folder, int delta)
    {
        Folders = Folders.Select(f => f.Name == folder
            ? f with { UnreadMessages = Math.Max(0, f.UnreadMessages + delta) }
            : f).ToList();
    }

    public FolderInfo? FindSpecialFolder(string use) => Folders.FirstOrDefault(f => f.SpecialUse == use);

    // ---- toasts ----

    private int _toastId;
    private readonly List<Toast> _toasts = new();
    public IReadOnlyList<Toast> Toasts => _toasts;

    public void ShowToast(string message, bool isError = false)
    {
        var toast = new Toast(Interlocked.Increment(ref _toastId), message, isError);
        lock (_toasts) _toasts.Add(toast);
        NotifyStateChanged();
        _ = Task.Delay(isError ? 7000 : 3500).ContinueWith(_ => DismissToast(toast.Id));
    }

    public void DismissToast(int id)
    {
        lock (_toasts) _toasts.RemoveAll(t => t.Id == id);
        NotifyStateChanged();
    }
}
