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

/// <summary>
/// A passkey that signs in to this account. Besides the usual WebAuthn state it keeps the mail
/// login, encrypted with a key derived from the passkey's PRF output, so the server can't read
/// it again until the passkey is used (see <see cref="Services.PasskeyService"/>).
/// </summary>
public class Passkey
{
    public int Id { get; set; }

    public int UserId { get; set; }
    public User? User { get; set; }

    /// <summary>"Edge on Windows" style description of the browser it was added from.</summary>
    [MaxLength(128)]
    public string Name { get; set; } = string.Empty;

    /// <summary>The WebAuthn credential id, base64url.</summary>
    [MaxLength(1400)]
    public string CredentialId { get; set; } = string.Empty;

    /// <summary>The credential's public key as a COSE_Key.</summary>
    public byte[] PublicKey { get; set; } = [];

    public long SignCount { get; set; }

    /// <summary>Comma-separated WebAuthn transports, as a hint for the browser.</summary>
    [MaxLength(256)]
    public string? Transports { get; set; }

    /// <summary>The WebAuthn user handle (base64url). One per user, shared by their passkeys.</summary>
    [MaxLength(128)]
    public string UserHandle { get; set; } = string.Empty;

    /// <summary>The server salt the current wrap was made with; it changes every time the passkey is used.</summary>
    public byte[] PrfSalt { get; set; } = [];

    /// <summary>nonce | tag | AES-256-GCM(PRF key, Data Protection(login)).</summary>
    public byte[] WrappedCredential { get; set; } = [];

    /// <summary>Goes up each time the login is wrapped again, and is bound into the encryption.</summary>
    public int WrapVersion { get; set; }

    /// <summary>The wrapped password no longer signs in (it was changed): the passkey needs updating.</summary>
    public bool Stale { get; set; }

    public DateTime CreatedUtc { get; set; } = DateTime.UtcNow;
    public DateTime? LastUsedUtc { get; set; }
}
