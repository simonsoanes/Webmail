// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using System.Net;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.EntityFrameworkCore;
using Nullify.WebMail.Controllers;
using Nullify.WebMail.Data;
using Nullify.WebMail.Services;

// Legacy mail charsets (windows-1252, iso-2022-jp, koi8-r, ...) live in the code-pages provider.
System.Text.Encoding.RegisterProvider(System.Text.CodePagesEncodingProvider.Instance);

var builder = WebApplication.CreateBuilder(args);
var config = builder.Configuration;

// ------------------------------------------------------------------ Storage
var dataDir = config["Storage:DataDirectory"];
if (string.IsNullOrWhiteSpace(dataDir))
    dataDir = Path.Combine(builder.Environment.ContentRootPath, "data");
dataDir = Path.GetFullPath(dataDir);
Directory.CreateDirectory(dataDir);
var dbPath = Path.Combine(dataDir, "nullify-webmail.db");

// SQLite in the data directory unless Database:Provider says PostgreSql. The data
// directory is still used for the key ring either way.
var dbProvider = config["Database:Provider"];
var usePostgres = dbProvider?.Trim().ToLowerInvariant() switch
{
    null or "" or "sqlite" => false,
    "postgresql" or "postgres" or "npgsql" => true,
    _ => throw new InvalidOperationException($"Unknown Database:Provider '{dbProvider}'. Use Sqlite or PostgreSql."),
};
var connectionString = usePostgres
    ? config["Database:ConnectionString"] is { Length: > 0 } cs ? cs
        : throw new InvalidOperationException("Database:ConnectionString is required when Database:Provider is PostgreSql.")
    : $"Data Source={dbPath};Pooling=True;Default Timeout=30";

// AddDbContextFactory alone: it registers the factory (singleton), the options
// (singleton) AND AppDbContext itself (scoped). Mixing in AddDbContext registers a
// second, scoped IDbContextOptionsConfiguration that poisons root-provider resolution.
builder.Services.AddDbContextFactory<AppDbContext>(o =>
{
    if (usePostgres) o.UseNpgsql(connectionString);
    else o.UseSqlite(connectionString);
});
builder.Services.AddDataProtection()
    .SetApplicationName("Nullify.WebMail")
    .PersistKeysToFileSystem(new DirectoryInfo(Path.Combine(dataDir, "keys")));

// ------------------------------------------------------------------ Services
builder.Services.AddSingleton<SettingsService>();
builder.Services.AddSingleton<WriteGate>();
builder.Services.AddSingleton<BrandingCache>();
builder.Services.AddSingleton<ImapClient>();
builder.Services.AddSingleton<SmtpClient>();
builder.Services.AddSingleton<ManageSieveClient>();
builder.Services.AddSingleton<ConnectionPool>();
builder.Services.AddSingleton<MailService>();
builder.Services.AddScoped<AuthService>();
builder.Services.AddScoped<TrustedDeviceService>();
builder.Services.AddScoped<UserSession>();
builder.Services.AddScoped<ApiService>();
builder.Services.AddScoped<AppState>();
builder.Services.AddScoped<MailActions>();
builder.Services.AddScoped<CalDavAccountService>();
builder.Services.AddScoped<WebDavService>();
builder.Services.AddScoped<BrandingService>();
builder.Services.AddScoped<PgpService>();
builder.Services.AddScoped<PgpBrowser>();
// File transfers can take a while; WebDavService applies its own timeout to metadata calls.
builder.Services.AddHttpClient(WebDavService.HttpClientName, c => c.Timeout = Timeout.InfiniteTimeSpan)
    .ConfigurePrimaryHttpMessageHandler(() => new HttpClientHandler { AllowAutoRedirect = false });
builder.Services.AddHttpClient(CalDavAccountService.HttpClientName, c => c.Timeout = TimeSpan.FromSeconds(15))
    .ConfigurePrimaryHttpMessageHandler(() => new HttpClientHandler { AllowAutoRedirect = false });
builder.Services.AddHttpContextAccessor();

// ------------------------------------------------------------------ Blazor
builder.Services.AddRazorComponents().AddInteractiveServerComponents();

// ------------------------------------------------------------------ Authentication
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(o =>
    {
        o.LoginPath = "/";
        o.Cookie.Name = "nullify.webmail.auth";
        o.Cookie.HttpOnly = true;
        o.Cookie.SameSite = SameSiteMode.Lax;
        // SameAsRequest so plain-HTTP LAN deployments work; behind a TLS-terminating
        // proxy the forwarded-headers middleware upgrades the request scheme to https.
        o.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
        o.ExpireTimeSpan = TimeSpan.FromDays(7);
        o.SlidingExpiration = true;
        o.Events = new CookieAuthenticationEvents
        {
            OnRedirectToLogin = ctx =>
            {
                // API callers get a clean 401 instead of an HTML redirect.
                if (ctx.Request.Path.StartsWithSegments("/api"))
                {
                    ctx.Response.StatusCode = StatusCodes.Status401Unauthorized;
                    return Task.CompletedTask;
                }
                ctx.Response.Redirect(ctx.RedirectUri);
                return Task.CompletedTask;
            },
        };
    });

// Tickets (with the mail credential) stay in server memory; the cookie holds only a session key.
builder.Services.AddSingleton<MemoryTicketStore>();
builder.Services.AddOptions<CookieAuthenticationOptions>(CookieAuthenticationDefaults.AuthenticationScheme)
    .Configure<MemoryTicketStore>((o, store) => o.SessionStore = store);

// Signing in a desktop from a phone by QR code; pending requests are in memory too.
builder.Services.AddSingleton<QrLoginService>();
builder.Services.AddRateLimiter(o =>
{
    o.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    static RateLimitPartition<string> PerIp(HttpContext ctx, int perMinute) =>
        RateLimitPartition.GetFixedWindowLimiter(ctx.Connection.RemoteIpAddress?.ToString() ?? "",
            _ => new FixedWindowRateLimiterOptions { PermitLimit = perMinute, Window = TimeSpan.FromMinutes(1) });
    o.AddPolicy(QrAuthController.RateLimitPolicy, ctx => PerIp(ctx, 60));
    o.AddPolicy(QrAuthController.StartRateLimitPolicy, ctx => PerIp(ctx, 12));
});

builder.Services.AddAuthorization();
builder.Services.AddControllers();
builder.Services.AddRouting(o => o.LowercaseUrls = true);

// ------------------------------------------------------------------ Reverse proxy support
var reverseProxyEnabled = config.GetValue("ReverseProxy:Enabled", true);
builder.Services.Configure<ForwardedHeadersOptions>(o =>
{
    o.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto | ForwardedHeaders.XForwardedHost;
    if (config["ReverseProxy:ForwardLimit"] is { } limit && int.TryParse(limit, out var l) && l > 0)
        o.ForwardLimit = l;
    if (config.GetValue<bool>("ReverseProxy:TrustAll"))
    {
        o.KnownIPNetworks.Clear();
        o.KnownProxies.Clear();
    }
    foreach (var proxy in (config["ReverseProxy:KnownProxies"] ?? "").Split(',',
                 StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        if (IPAddress.TryParse(proxy, out var ip)) o.KnownProxies.Add(ip);
    foreach (var network in (config["ReverseProxy:KnownNetworks"] ?? "").Split(',',
                 StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        if (System.Net.IPNetwork.TryParse(network, out var net)) o.KnownIPNetworks.Add(net);
});

var app = builder.Build();

// ------------------------------------------------------------------ Database
// EnsureCreated is not concurrency-safe: two hosts starting at once (e.g. parallel
// test runners) both see an empty file and race on CREATE TABLE. Serialise init
// with a cross-process file lock.
using (AcquireFileLock(dbPath + ".init-lock"))
using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
    db.Database.EnsureCreated();
    if (usePostgres)
    {
        // PostgreSQL support arrived after TrustedDevices, so EnsureCreated already builds every table.
        var pg = new Npgsql.NpgsqlConnectionStringBuilder(connectionString);
        app.Logger.LogInformation("Using PostgreSQL database {Database} on {Host}", pg.Database, pg.Host);
    }
    else
    {
        // EnsureCreated only builds a new database; tables added since then are created here.
        db.Database.ExecuteSqlRaw("""
            CREATE TABLE IF NOT EXISTS "TrustedDevices" (
                "Id" INTEGER NOT NULL CONSTRAINT "PK_TrustedDevices" PRIMARY KEY AUTOINCREMENT,
                "UserId" INTEGER NOT NULL,
                "DeviceId" TEXT NOT NULL,
                "Name" TEXT NOT NULL,
                "CreatedUtc" TEXT NOT NULL,
                "LastUsedUtc" TEXT NOT NULL,
                "ExpiresUtc" TEXT NOT NULL,
                CONSTRAINT "FK_TrustedDevices_Users_UserId" FOREIGN KEY ("UserId") REFERENCES "Users" ("Id") ON DELETE CASCADE);
            CREATE UNIQUE INDEX IF NOT EXISTS "IX_TrustedDevices_DeviceId" ON "TrustedDevices" ("DeviceId");
            CREATE INDEX IF NOT EXISTS "IX_TrustedDevices_UserId" ON "TrustedDevices" ("UserId");
            """);
        db.Database.ExecuteSqlRaw("PRAGMA journal_mode=WAL;");
        app.Logger.LogInformation("Using database {Path}", dbPath);
    }
    app.Services.GetRequiredService<SettingsService>().Load();
}

// ------------------------------------------------------------------ Pipeline
var pathBase = config["PathBase"];
if (!string.IsNullOrWhiteSpace(pathBase)) app.UsePathBase(pathBase);

if (reverseProxyEnabled) app.UseForwardedHeaders();
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/error");
    app.UseHsts();
}

app.Use(async (ctx, next) =>
{
    ctx.Response.Headers.XContentTypeOptions = "nosniff";
    ctx.Response.Headers["Referrer-Policy"] = "same-origin";
    await next();
});

app.UseStaticFiles();
app.UseRouting();
app.UseRateLimiter();
app.UseAuthentication();
// A trusted computer with no session (the server restarted, or the session cookie expired)
// signs in again from its trusted-computer cookie when it loads a page.
app.Use(async (ctx, next) =>
{
    if (HttpMethods.IsGet(ctx.Request.Method)
        && ctx.User.Identity?.IsAuthenticated != true
        && ctx.Request.Cookies.ContainsKey(TrustedDeviceService.CookieName)
        && ctx.Request.Headers.Accept.ToString().Contains("text/html")
        && !ctx.Request.Path.StartsWithSegments("/api")
        && !ctx.Request.Path.StartsWithSegments("/_blazor")
        && !ctx.Request.Path.StartsWithSegments("/_framework"))
    {
        await ctx.RequestServices.GetRequiredService<TrustedDeviceService>().TryRestoreAsync(ctx, ctx.RequestAborted);
    }
    await next();
});
app.UseAuthorization();
app.UseAntiforgery();
app.MapControllers();
app.MapRazorComponents<Nullify.WebMail.Components.App>().AddInteractiveServerRenderMode();

app.Run();

static FileStream AcquireFileLock(string path)
{
    for (var attempt = 0; ; attempt++)
    {
        try
        {
            return new FileStream(path, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
        }
        catch (IOException) when (attempt < 100)
        {
            Thread.Sleep(100);
        }
    }
}

public partial class Program;