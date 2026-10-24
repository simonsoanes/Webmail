// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Xml.Linq;
using Nullify.WebMail.Shared;

namespace Nullify.WebMail.Services;

/// <summary>
/// Documents: a WebDAV storage account (Nextcloud, ownCloud, Apache mod_dav, IIS, SharePoint...).
/// URL: the user's own, else the one the administrator set for their domain, else the server-wide
/// default. Credentials: the user's own, else their CalDAV/CardDAV ones (which themselves default
/// to the mail login and password). A separate password is sealed under the mail password.
/// </summary>
public sealed class WebDavService(
    ApiService api,
    UserSession session,
    CalDavAccountService calDav,
    IConfiguration configuration,
    IHttpClientFactory httpFactory)
{
    public const string HttpClientName = "webdav";
    private const string EnabledKey = "webdav.enabled", UrlKey = "webdav.url", UserKey = "webdav.username", SecretKey = "webdav.password";
    private static readonly XNamespace Dav = "DAV:";
    private static readonly TimeSpan MetadataTimeout = TimeSpan.FromSeconds(30);

    private sealed record Account(Uri Root, string Username, string Password);

    private CredentialInfo Cred =>
        session.Credential ?? throw new InvalidOperationException("Not authenticated.");

    private string SealContext => "nullify.webdav.v1|" + Cred.Login.ToLowerInvariant();

    // ------------------------------------------------------------------ settings

    public static string DomainEnabledKey(string domain) => $"webdav.domain.{domain.ToLowerInvariant()}.enabled";
    public static string DomainUrlKey(string domain) => $"webdav.domain.{domain.ToLowerInvariant()}.url";

    public async Task<DocumentsSettingsDto> GetSettingsAsync()
    {
        var prefs = await LoadPrefsAsync();
        var (domainEnabled, domainUrl) = await DomainSettingsAsync();
        string defaultUser;
        bool calDavSeparate;
        try { (defaultUser, _, calDavSeparate) = await calDav.ResolveCredentialsAsync(); }
        catch (InvalidOperationException) { (defaultUser, calDavSeparate) = (Cred.Login, true); }
        var template = domainUrl ?? GlobalUrl;
        var defaultUrl = template == null ? null
            : ExpandPlaceholders(new Uri(CalDavAccountService.NormalizeUrl(template)),
                prefs.GetValueOrDefault(UserKey) ?? defaultUser, Cred.Login).AbsoluteUri;
        return new DocumentsSettingsDto(
            domainEnabled || prefs.GetValueOrDefault(EnabledKey) == "true", domainEnabled,
            prefs.GetValueOrDefault(UrlKey), prefs.GetValueOrDefault(UserKey),
            PasswordSource(prefs.GetValueOrDefault(SecretKey)),
            defaultUrl, defaultUser, calDavSeparate);
    }

    /// <summary>Show the Documents menu: switched on (by the user or for their domain) and a URL is known.</summary>
    public async Task<bool> IsAvailableAsync()
    {
        var s = await GetSettingsAsync();
        return s.Enabled && !string.IsNullOrWhiteSpace(s.Url ?? s.DefaultUrl);
    }

    /// <param name="newPassword">Null/empty keeps a working saved password; a value replaces it.</param>
    /// <param name="useDefaultPassword">Discard any saved password and use the CalDAV/mail one.</param>
    public async Task SaveAsync(bool enabled, string? url, string? username, string? newPassword, bool useDefaultPassword)
    {
        url = string.IsNullOrWhiteSpace(url) ? null : CalDavAccountService.NormalizeUrl(url);
        await api.SetPreferenceAsync(EnabledKey, enabled ? "true" : "false");
        await api.SetPreferenceAsync(UrlKey, url);
        await api.SetPreferenceAsync(UserKey, string.IsNullOrWhiteSpace(username) ? null : username.Trim());
        if (useDefaultPassword)
            await api.SetPreferenceAsync(SecretKey, null);
        else if (!string.IsNullOrEmpty(newPassword))
            await api.SetPreferenceAsync(SecretKey, SecretBox.Seal(newPassword, Cred.Password, SealContext));
        else if (PasswordSource((await LoadPrefsAsync()).GetValueOrDefault(SecretKey)) == DavPasswordSource.NeedsReentry)
            await api.SetPreferenceAsync(SecretKey, null); // can never open again; fall back instead
    }

    public async Task ResetAsync()
    {
        foreach (var key in new[] { UrlKey, UserKey, SecretKey }) await api.SetPreferenceAsync(key, null);
    }

    /// <summary>Check settings without saving; blank fields fall back as they would when saved.</summary>
    public async Task<CalDavTestResult> TestAsync(string? url, string? username, string? password)
    {
        Account account;
        try { account = await ResolveAccountAsync(url, username, password); }
        catch (Exception ex) when (ex is CalDavException or InvalidOperationException or FormatException)
        {
            return new(false, ex.Message, []);
        }
        try
        {
            var listing = await ListAsync(account, "/");
            var space = listing.QuotaAvailable is { } free
                ? $" {MailFormat.Size(listing.QuotaUsed ?? 0)} used, {MailFormat.Size(free)} free."
                : "";
            return new(true, $"Connected — {listing.Items.Count} item{(listing.Items.Count == 1 ? "" : "s")} in the top folder.{space}", []);
        }
        catch (Exception ex) when (ex is CalDavException or HttpRequestException or TaskCanceledException)
        {
            return new(false, ex is TaskCanceledException ? "The server did not respond in time." : ex.Message, []);
        }
    }

    // ------------------------------------------------------------------ domain (admin)

    public async Task<(bool Enabled, string? Url)> DomainSettingsAsync(string? domain = null)
    {
        domain ??= AuthService.ExtractDomain(Cred.Login);
        if (string.IsNullOrEmpty(domain)) return (false, null);
        var enabled = await api.GetAdminSettingAsync(DomainEnabledKey(domain)) == "true";
        var url = await api.GetAdminSettingAsync(DomainUrlKey(domain));
        return (enabled, string.IsNullOrWhiteSpace(url) ? null : url);
    }

    public async Task SetDomainSettingsAsync(string domain, bool enabled, string? url)
    {
        if (!session.IsAdmin) throw new UnauthorizedAccessException("Only administrators can change domain settings.");
        await api.SetAdminSettingAsync(DomainEnabledKey(domain), enabled ? "true" : "false");
        await api.SetAdminSettingAsync(DomainUrlKey(domain),
            string.IsNullOrWhiteSpace(url) ? null : CalDavAccountService.NormalizeUrl(url));
    }

    private string? GlobalUrl => string.IsNullOrWhiteSpace(configuration["WebDav:Url"]) ? null : configuration["WebDav:Url"];

    // ------------------------------------------------------------------ files

    /// <exception cref="CalDavException">Not configured, or the server refused.</exception>
    public async Task<DavListing> ListAsync(string path) => await ListAsync(await ResolveAccountAsync(), path);

    public async Task CreateFolderAsync(string parentPath, string name)
    {
        var account = await ResolveAccountAsync();
        var path = Combine(parentPath, ValidName(name));
        using var resp = await SendAsync(account, new HttpMethod("MKCOL"), ToUri(account, path, folder: true), null, []);
        if (resp.StatusCode == HttpStatusCode.MethodNotAllowed) throw new CalDavException($"\"{name}\" already exists.");
        EnsureSuccess(resp, "create the folder");
    }

    public async Task DeleteAsync(DavItem item)
    {
        var account = await ResolveAccountAsync();
        using var resp = await SendAsync(account, HttpMethod.Delete, ToUri(account, item.Path, item.IsFolder), null, []);
        if (resp.StatusCode != HttpStatusCode.NotFound) EnsureSuccess(resp, "delete it");
    }

    public async Task RenameAsync(DavItem item, string newName)
    {
        var account = await ResolveAccountAsync();
        var parent = item.Path[..item.Path.TrimEnd('/').LastIndexOf('/')];
        var target = ToUri(account, Combine(parent, ValidName(newName)), item.IsFolder);
        using var resp = await SendAsync(account, new HttpMethod("MOVE"), ToUri(account, item.Path, item.IsFolder), null,
            new() { ["Destination"] = target.AbsoluteUri, ["Overwrite"] = "F" });
        if (resp.StatusCode == HttpStatusCode.PreconditionFailed) throw new CalDavException($"\"{newName}\" already exists here.");
        EnsureSuccess(resp, "rename it");
    }

    /// <summary>Stream a file up. Without <paramref name="overwrite"/>, an existing file of that name is an error.</summary>
    public async Task UploadAsync(string folderPath, string fileName, Stream content, long length, string? contentType,
        bool overwrite, CancellationToken ct)
    {
        var account = await ResolveAccountAsync();
        var uri = ToUri(account, Combine(folderPath, ValidName(fileName)), folder: false);
        var body = new StreamContent(content);
        body.Headers.ContentType = MediaTypeHeaderValue.TryParse(contentType, out var mt) ? mt : new MediaTypeHeaderValue("application/octet-stream");
        body.Headers.ContentLength = length;
        using var resp = await SendAsync(account, HttpMethod.Put, uri, body,
            overwrite ? [] : new() { ["If-None-Match"] = "*" }, ct, metadata: false);
        if (resp.StatusCode == HttpStatusCode.PreconditionFailed) throw new FileExistsException(fileName);
        if (resp.StatusCode == HttpStatusCode.InsufficientStorage) throw new CalDavException("There isn't enough space left in your storage.");
        EnsureSuccess(resp, $"upload \"{fileName}\"");
    }

    /// <summary>Open a file for streaming to the browser. The caller disposes the response.</summary>
    public async Task<HttpResponseMessage> OpenDownloadAsync(string path, CancellationToken ct)
    {
        var account = await ResolveAccountAsync();
        var resp = await SendAsync(account, HttpMethod.Get, ToUri(account, NormalizePath(path), folder: false), null, [], ct,
            metadata: false, streamBody: true);
        if (!resp.IsSuccessStatusCode)
        {
            resp.Dispose();
            throw new CalDavException(resp.StatusCode == HttpStatusCode.NotFound ? "That file no longer exists." : $"Download failed (HTTP {(int)resp.StatusCode}).");
        }
        return resp;
    }

    public sealed class FileExistsException(string name) : Exception($"\"{name}\" already exists here.")
    {
        public string FileName { get; } = name;
    }

    // ------------------------------------------------------------------ internals

    private async Task<Account> ResolveAccountAsync(string? url = null, string? username = null, string? password = null)
    {
        var prefs = await LoadPrefsAsync();
        var (_, domainUrl) = await DomainSettingsAsync();
        var root = !string.IsNullOrWhiteSpace(url) ? url : prefs.GetValueOrDefault(UrlKey) ?? domainUrl ?? GlobalUrl;
        if (string.IsNullOrWhiteSpace(root)) throw new CalDavException("No Documents server is configured.");
        var rootUri = new Uri(CalDavAccountService.NormalizeUrl(root));
        if (!rootUri.AbsolutePath.EndsWith('/')) rootUri = new Uri(rootUri.AbsoluteUri + "/");

        var user = !string.IsNullOrWhiteSpace(username) ? username.Trim() : prefs.GetValueOrDefault(UserKey);
        var secret = prefs.GetValueOrDefault(SecretKey);
        string pass;
        if (!string.IsNullOrEmpty(password)) pass = password;
        else if (!string.IsNullOrEmpty(secret))
            pass = SecretBox.TryOpen(secret, Cred.Password, SealContext, out var p) ? p
                : throw new InvalidOperationException("Your saved Documents password can't be unlocked because your mail password has changed. Please enter it again.");
        else
        {
            var (calUser, calPass, _) = await calDav.ResolveCredentialsAsync();
            pass = calPass;
            user ??= calUser;
        }
        if (user == null) (user, _, _) = await calDav.ResolveCredentialsAsync();
        rootUri = ExpandPlaceholders(rootUri, user, Cred.Login);
        return new Account(rootUri, user, pass);
    }

    private async Task<DavListing> ListAsync(Account account, string path)
    {
        path = NormalizePath(path);
        const string body = """<?xml version="1.0" encoding="utf-8"?><d:propfind xmlns:d="DAV:"><d:prop><d:resourcetype/><d:getcontentlength/><d:getlastmodified/><d:getcontenttype/><d:quota-used-bytes/><d:quota-available-bytes/></d:prop></d:propfind>""";
        var uri = ToUri(account, path, folder: true);
        for (var hop = 0; hop < 4; hop++)
        {
            using var resp = await SendAsync(account, new HttpMethod("PROPFIND"), uri,
                new StringContent(body, Encoding.UTF8, "application/xml"), new() { ["Depth"] = "1" });
            if ((int)resp.StatusCode is >= 300 and < 400 && resp.Headers.Location is { } loc)
            {
                var next = loc.IsAbsoluteUri ? loc : new Uri(uri, loc);
                if (next.Host != uri.Host) throw new CalDavException($"The server redirected to {next.GetLeftPart(UriPartial.Authority)}; use that address instead.");
                uri = next;
                continue;
            }
            if (resp.StatusCode == HttpStatusCode.NotFound) throw new CalDavException("That folder doesn't exist (any more).");
            EnsureSuccess(resp, "list the folder", expectMultiStatus: true);

            XDocument doc;
            try { doc = XDocument.Parse(await resp.Content.ReadAsStringAsync()); }
            catch (System.Xml.XmlException) { throw new CalDavException("The server sent a response that isn't valid WebDAV XML."); }

            long? used = null, free = null;
            var items = new List<DavItem>();
            foreach (var r in doc.Descendants(Dav + "response"))
            {
                var rel = FromHref(account, r.Element(Dav + "href")?.Value);
                if (rel == null) continue;
                var isFolder = r.Descendants(Dav + "resourcetype").Elements(Dav + "collection").Any();
                var cleanRel = rel.TrimEnd('/');
                if (cleanRel == path.TrimEnd('/'))
                {
                    // The folder itself: carries the quota.
                    used = ParseLong(r.Descendants(Dav + "quota-used-bytes").FirstOrDefault()?.Value);
                    free = ParseLong(r.Descendants(Dav + "quota-available-bytes").FirstOrDefault()?.Value);
                    if (free < 0) free = null; // -1/-2/-3 mean "unknown/unlimited" on some servers
                    continue;
                }
                var name = cleanRel[(cleanRel.LastIndexOf('/') + 1)..];
                if (name.Length == 0) continue;
                DateTimeOffset? modified = DateTimeOffset.TryParse(r.Descendants(Dav + "getlastmodified").FirstOrDefault()?.Value,
                    CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var m) ? m : null;
                items.Add(new DavItem(name, cleanRel + (isFolder ? "/" : ""), isFolder,
                    isFolder ? null : ParseLong(r.Descendants(Dav + "getcontentlength").FirstOrDefault()?.Value),
                    modified, r.Descendants(Dav + "getcontenttype").FirstOrDefault()?.Value));
            }
            items.Sort((a, b) => a.IsFolder != b.IsFolder ? (a.IsFolder ? -1 : 1)
                : string.Compare(a.Name, b.Name, StringComparison.CurrentCultureIgnoreCase));
            return new DavListing(path, items, used, free);
        }
        throw new CalDavException("Too many redirects.");
    }

    private async Task<HttpResponseMessage> SendAsync(Account account, HttpMethod method, Uri uri, HttpContent? content,
        Dictionary<string, string> headers, CancellationToken ct = default, bool metadata = true, bool streamBody = false)
    {
        var http = httpFactory.CreateClient(HttpClientName);
        var req = new HttpRequestMessage(method, uri) { Content = content };
        req.Headers.Authorization = new AuthenticationHeaderValue("Basic",
            Convert.ToBase64String(Encoding.UTF8.GetBytes($"{account.Username}:{account.Password}")));
        foreach (var (k, v) in headers) req.Headers.TryAddWithoutValidation(k, v);

        // Metadata calls get a short timeout; transfers run as long as the user waits.
        using var timeout = metadata ? new CancellationTokenSource(MetadataTimeout) : null;
        using var linked = timeout != null ? CancellationTokenSource.CreateLinkedTokenSource(ct, timeout.Token) : null;
        var resp = await http.SendAsync(req, streamBody ? HttpCompletionOption.ResponseHeadersRead : HttpCompletionOption.ResponseContentRead,
            linked?.Token ?? ct);
        if (resp.StatusCode == HttpStatusCode.Unauthorized)
        {
            resp.Dispose();
            throw new CalDavException("The server rejected the username or password.");
        }
        return resp;
    }

    private static void EnsureSuccess(HttpResponseMessage resp, string action, bool expectMultiStatus = false)
    {
        if (expectMultiStatus ? resp.StatusCode == HttpStatusCode.MultiStatus : resp.IsSuccessStatusCode) return;
        throw resp.StatusCode switch
        {
            HttpStatusCode.Forbidden => new CalDavException($"You don't have permission to {action}."),
            HttpStatusCode.Locked => new CalDavException($"Couldn't {action}: it's locked by someone else."),
            HttpStatusCode.Conflict => new CalDavException($"Couldn't {action}: the folder doesn't exist."),
            HttpStatusCode.RequestEntityTooLarge => new CalDavException($"Couldn't {action}: the server says it's too large."),
            _ when expectMultiStatus && resp.IsSuccessStatusCode => new CalDavException("The server doesn't look like WebDAV."),
            _ => new CalDavException($"Couldn't {action} (HTTP {(int)resp.StatusCode}).")
        };
    }

    /// <summary>Per-user URL templates: {username} → WebDAV sign-in name, {email} → mail address.</summary>
    public static Uri ExpandPlaceholders(Uri root, string username, string email)
    {
        var url = root.AbsoluteUri;
        foreach (var (token, value) in new[] { ("username", username), ("email", email) })
        {
            var escaped = Uri.EscapeDataString(value);
            url = url.Replace("{" + token + "}", escaped, StringComparison.OrdinalIgnoreCase)
                     .Replace("%7B" + token + "%7D", escaped, StringComparison.OrdinalIgnoreCase);
        }
        return new Uri(url);
    }

    // ------------------------------------------------------------------ paths

    /// <summary>"/a/b/" form; rejects "." and ".." so a path can never climb above the account root.</summary>
    public static string NormalizePath(string? path)
    {
        var segments = (path ?? "").Replace('\\', '/').Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (segments.Any(s => s is "." or ".."))
            throw new CalDavException("That path isn't allowed.");
        return "/" + string.Join('/', segments) + (segments.Length > 0 && (path ?? "").EndsWith('/') ? "/" : "");
    }

    private static string Combine(string folder, string name) => NormalizePath(folder).TrimEnd('/') + "/" + name;

    private static Uri ToUri(Account account, string path, bool folder)
    {
        var segments = NormalizePath(path).Split('/', StringSplitOptions.RemoveEmptyEntries).Select(Uri.EscapeDataString);
        var rel = string.Join('/', segments);
        if (folder && rel.Length > 0) rel += "/";
        return new Uri(account.Root, rel);
    }

    /// <summary>Server href → path relative to the root, or null if it lies outside the root.</summary>
    private static string? FromHref(Account account, string? href)
    {
        if (string.IsNullOrWhiteSpace(href)) return null;
        var abs = new Uri(account.Root, href.Trim());
        if (abs.Host != account.Root.Host) return null;
        var full = Uri.UnescapeDataString(abs.AbsolutePath);
        var root = Uri.UnescapeDataString(account.Root.AbsolutePath);
        if (!full.StartsWith(root, StringComparison.Ordinal) && !(full + "/").Equals(root, StringComparison.Ordinal)) return null;
        var rel = full.Length >= root.Length ? full[root.Length..] : "";
        return "/" + rel;
    }

    private static string ValidName(string name)
    {
        name = name.Trim();
        if (name.Length == 0 || name.Length > 255 || name is "." or ".." || name.IndexOfAny(['/', '\\']) >= 0 || name.Any(char.IsControl))
            throw new CalDavException($"\"{name}\" isn't a valid name.");
        return name;
    }

    private static long? ParseLong(string? v) => long.TryParse(v, NumberStyles.Integer, CultureInfo.InvariantCulture, out var n) ? n : null;

    private DavPasswordSource PasswordSource(string? secret) =>
        string.IsNullOrEmpty(secret) ? DavPasswordSource.MailPassword
        : SecretBox.TryOpen(secret, Cred.Password, SealContext, out _) ? DavPasswordSource.Saved
        : DavPasswordSource.NeedsReentry;

    private async Task<Dictionary<string, string>> LoadPrefsAsync() =>
        (await api.GetPreferencesAsync())
            .Where(p => p.Key.StartsWith("webdav.", StringComparison.Ordinal) && !string.IsNullOrEmpty(p.Value))
            .ToDictionary(p => p.Key, p => p.Value!);
}
