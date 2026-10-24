// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using Nullify.WebMail.Data;
using Nullify.WebMail.Shared;

namespace Nullify.WebMail.Services;

public sealed record ServerSettings
{
    public string? PublicUrl { get; init; }
    public string? ImapHost { get; init; }
    public int ImapPort { get; init; } = 993;
    public MailSecurity ImapSecurity { get; init; } = MailSecurity.Tls;
    public bool ImapAllowInvalidCertificates { get; init; }
    public string? SmtpHost { get; init; }
    public int SmtpPort { get; init; } = 587;
    public MailSecurity SmtpSecurity { get; init; } = MailSecurity.StartTls;
    public string? SieveHost { get; init; }
    public int SievePort { get; init; } = 4190;
    public string? CalDavUrl { get; init; }
    public string? CardDavUrl { get; init; }
    public int ConnectionPoolSize { get; init; } = 3;
    public int ConnectionIdleMinutes { get; init; } = 5;
    public bool ImapConfigured => !string.IsNullOrWhiteSpace(ImapHost);
    public bool SmtpConfigured => !string.IsNullOrWhiteSpace(SmtpHost);
    public bool SieveConfigured => !string.IsNullOrWhiteSpace(SieveHost);
    public bool DavConfigured => !string.IsNullOrWhiteSpace(CalDavUrl) || !string.IsNullOrWhiteSpace(CardDavUrl);
}

public sealed class SettingsService(IConfiguration configuration)
{
    private readonly string? _configuredPublicUrl = string.IsNullOrWhiteSpace(configuration["PublicUrl"])
        ? null
        : configuration["PublicUrl"]!.TrimEnd('/');

    public ServerSettings Current { get; private set; } = new();

    public void Load()
    {
        Current = new ServerSettings
        {
            PublicUrl = _configuredPublicUrl,
            ImapHost = configuration["Imap:Host"],
            ImapPort = int.TryParse(configuration["Imap:Port"], out var ip) ? ip : 993,
            ImapSecurity = Enum.TryParse<MailSecurity>(configuration["Imap:Security"], out var isec) ? isec : MailSecurity.Tls,
            ImapAllowInvalidCertificates = bool.TryParse(configuration["Imap:AllowInvalidCertificates"], out var iaic) && iaic,
            SmtpHost = configuration["Smtp:Host"],
            SmtpPort = int.TryParse(configuration["Smtp:Port"], out var sp) ? sp : 587,
            SmtpSecurity = Enum.TryParse<MailSecurity>(configuration["Smtp:Security"], out var ssec) ? ssec : MailSecurity.StartTls,
            SieveHost = configuration["Sieve:Host"],
            SievePort = int.TryParse(configuration["Sieve:Port"], out var svp) ? svp : 4190,
            CalDavUrl = configuration["CalDav:Url"],
            CardDavUrl = configuration["CardDav:Url"],
            ConnectionPoolSize = int.TryParse(configuration["ConnectionPool:Size"], out var cps) ? cps : 3,
            ConnectionIdleMinutes = int.TryParse(configuration["ConnectionPool:IdleMinutes"], out var cim) ? cim : 5,
        };
    }
}