// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using Nullify.WebMail.Shared;

namespace Nullify.WebMail.Data;

public class User
{
    public int Id { get; set; }

    [MaxLength(128)]
    public string Username { get; set; } = string.Empty;

    [MaxLength(256)]
    public string? DisplayName { get; set; }

    [MaxLength(256)]
    public string Email { get; set; } = string.Empty;

    public bool IsAdmin { get; set; }

    [MaxLength(256)]
    public string? ImapHost { get; set; }

    public int? ImapPort { get; set; }

    public MailSecurity? ImapSecurity { get; set; }

    [MaxLength(256)]
    public string? SmtpHost { get; set; }

    public int? SmtpPort { get; set; }

    public MailSecurity? SmtpSecurity { get; set; }

    public DateTime CreatedUtc { get; set; } = DateTime.UtcNow;

    public DateTime? LastLoginUtc { get; set; }

    public ICollection<UserPreference> Preferences { get; set; } = new List<UserPreference>();
    public ICollection<ImapFolderCache> FolderCache { get; set; } = new List<ImapFolderCache>();
    public ICollection<SieveScript> SieveScripts { get; set; } = new List<SieveScript>();
    public ICollection<PgpKey> PgpKeys { get; set; } = new List<PgpKey>();
}

public class UserPreference
{
    public int Id { get; set; }

    public int UserId { get; set; }

    [ForeignKey(nameof(UserId))]
    public User? User { get; set; }

    [MaxLength(128)]
    public string Key { get; set; } = string.Empty;

    public string? Value { get; set; }
}

public class ImapFolderCache
{
    public int Id { get; set; }

    public int UserId { get; set; }

    [ForeignKey(nameof(UserId))]
    public User? User { get; set; }

    [MaxLength(512)]
    public string Name { get; set; } = string.Empty;

    [MaxLength(256)]
    public string? Attributes { get; set; }

    public int TotalMessages { get; set; }

    public int UnreadMessages { get; set; }

    public DateTime LastSyncUtc { get; set; } = DateTime.UtcNow;
}

public class SieveScript
{
    public int Id { get; set; }

    public int UserId { get; set; }

    [ForeignKey(nameof(UserId))]
    public User? User { get; set; }

    [MaxLength(256)]
    public string Name { get; set; } = string.Empty;

    public bool IsActive { get; set; }

    public string Content { get; set; } = string.Empty;

    [MaxLength(256)]
    public string? ETag { get; set; }

    public DateTime LastSyncUtc { get; set; } = DateTime.UtcNow;
}

public class PgpKey
{
    public int Id { get; set; }

    public int UserId { get; set; }

    [ForeignKey(nameof(UserId))]
    public User? User { get; set; }

    [MaxLength(256)]
    public string KeyId { get; set; } = string.Empty;

    [MaxLength(512)]
    public string? UserIds { get; set; }

    /// <summary>Armored private key, encrypted with a server-side key (so it's at rest encrypted).</summary>
    public string ArmoredPrivateKey { get; set; } = string.Empty;

    /// <summary>Armored public key.</summary>
    public string ArmoredPublicKey { get; set; } = string.Empty;

    public DateTime CreatedUtc { get; set; } = DateTime.UtcNow;

    public DateTime? ExpiresUtc { get; set; }
}

public class Domain
{
    public int Id { get; set; }

    /// <summary>The email domain this mapping applies to (e.g. "example.org").</summary>
    [MaxLength(256)]
    public string Name { get; set; } = string.Empty;

    /// <summary>If true, only domains in this table can be used to log in.</summary>
    public bool RestrictToMappedDomains { get; set; }

    [MaxLength(256)]
    public string? ImapHost { get; set; }

    public int? ImapPort { get; set; }

    public MailSecurity? ImapSecurity { get; set; }

    public bool ImapAllowInvalidCertificates { get; set; }

    [MaxLength(256)]
    public string? SmtpHost { get; set; }

    public int? SmtpPort { get; set; }

    public MailSecurity? SmtpSecurity { get; set; }

    [MaxLength(256)]
    public string? SieveHost { get; set; }

    public int? SievePort { get; set; }

    [MaxLength(512)]
    public string? CalDavUrl { get; set; }

    [MaxLength(512)]
    public string? CardDavUrl { get; set; }

    public DateTime CreatedUtc { get; set; } = DateTime.UtcNow;
}

public class AdminSetting
{
    public int Id { get; set; }

    [MaxLength(128)]
    public string Key { get; set; } = string.Empty;

    public string? Value { get; set; }
}
/// <summary>
/// A computer the user said they trust. That browser keeps the mail password in a cookie,
/// encrypted with the server's key ring, so it can sign in again after a restart. The row holds
/// no secret: it exists so the user can see and revoke those computers.
/// </summary>
public class TrustedDevice
{
    public int Id { get; set; }

    public int UserId { get; set; }
    public User? User { get; set; }

    /// <summary>Random id, also sealed inside the browser's cookie.</summary>
    [MaxLength(64)]
    public string DeviceId { get; set; } = string.Empty;

    /// <summary>"Edge on Windows" style description, for the list in Settings.</summary>
    [MaxLength(128)]
    public string Name { get; set; } = string.Empty;

    public DateTime CreatedUtc { get; set; } = DateTime.UtcNow;
    public DateTime LastUsedUtc { get; set; } = DateTime.UtcNow;
    public DateTime ExpiresUtc { get; set; }
}
