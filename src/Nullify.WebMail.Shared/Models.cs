// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

namespace Nullify.WebMail.Shared;

/// <param name="TrustDevice">"I trust this computer": the browser keeps the login, encrypted by the server, to sign in again later.</param>
public sealed record LoginRequest(string Username, string Password, bool TrustDevice = false);

public sealed record LoginResponse(bool Success, string? Error);

public sealed record SessionInfo(string Username, string Email, string? DisplayName);

public sealed record FolderInfo(
    string Name, string? Attributes, int TotalMessages, int UnreadMessages,
    string? Delimiter = null, string? SpecialUse = null);

public sealed record MessageSummary(
    long Uid, string Subject, string From, string To, string Date, long Size,
    bool IsSeen, bool IsFlagged, bool IsAnswered, bool IsDraft, string MessageId,
    bool HasAttachments = false);

public sealed record MessagePage(IReadOnlyList<MessageSummary> Messages, int Total, int Page, int PageSize);

public sealed record MessageContent(
    string Source, string? HtmlBody, string? TextBody,
    IReadOnlyDictionary<string, string>? Headers = null,
    IReadOnlyList<AttachmentInfo>? Attachments = null,
    PgpMessageInfo? Pgp = null);

/// <summary>An attachment of a received message; <see cref="PartId"/> is the MIME part path (e.g. "2.1").</summary>
public sealed record AttachmentInfo(string PartId, string Filename, string ContentType, long Size, string? ContentId, bool IsInline);

public sealed record OutgoingAttachment(string Filename, string ContentType, byte[] Data);

public sealed record SendRequest(
    string From, IReadOnlyList<string> To, IReadOnlyList<string>? Cc, IReadOnlyList<string>? Bcc,
    string Subject, string TextBody, string? HtmlBody, IReadOnlyList<string>? AttachmentIds,
    bool PgpSign, bool PgpEncrypt, string? PgpKeyId,
    string? InReplyTo = null, string? References = null,
    IReadOnlyList<OutgoingAttachment>? Attachments = null);

public sealed record FolderOperation(string FolderName);

public sealed record MoveRequest(string Destination);

public sealed record FlagRequest(string? AddFlags, string? RemoveFlags);

public sealed record SieveScriptDto(string Name, bool IsActive, string Content);

public sealed record PreferenceDto(string Key, string? Value);

/// <summary>How a stored secret key is protected. The server only ever holds the protected form.</summary>
public enum PgpProtection { Passphrase, SecurityKey }

/// <summary>
/// One of the user's OpenPGP keys. <see cref="SecretKey"/> is the armored secret key exactly as
/// the browser produced it: encrypted with the user's passphrase, or with a secret only their
/// security key can reproduce (WebAuthn PRF). The server never sees either.
/// </summary>
public sealed record PgpKeyRecord(
    string Fingerprint, string UserId, string PublicKey, string SecretKey,
    DateTime CreatedUtc, DateTime? ExpiresUtc,
    PgpProtection Protection, string? CredentialId, string? PrfSalt, bool IsDefault);

public sealed record PgpSettingsDto(bool SignByDefault, bool EncryptWhenPossible);

public enum PgpMessageKind { None, Encrypted, Signed, InlineEncrypted, InlineSigned }

/// <summary>OpenPGP content found in a message, for the browser to decrypt or verify.</summary>
public sealed record PgpMessageInfo(PgpMessageKind Kind, string? Armored, string? SignedEntityBase64, string? Signature);

/// <summary>
/// One event instance. All-day events carry their dates at midnight UTC and must be shown
/// by date, not converted to a time zone; <see cref="End"/> is exclusive.
/// </summary>
public sealed record CalendarEvent(
    string Uid, string Summary, DateTimeOffset Start, DateTimeOffset End, string? Location, string? Description,
    bool AllDay = false, string? CalendarId = null)
{
    /// <summary>The .ics resource on the server and its ETag (for conflict-safe edits).</summary>
    public string? Href { get; init; }
    public string? ETag { get; init; }
    /// <summary>True for an occurrence of a repeating event; edits then apply to the whole series.</summary>
    public bool IsRecurring { get; init; }
    /// <summary>The occurrence's original start (its RECURRENCE-ID), used to skip just this one.</summary>
    public DateTimeOffset? OccurrenceId { get; init; }
}

/// <summary>Repeat choices offered by the editor (a subset of RRULE).</summary>
public enum EventRepeat { None, Daily, Weekly, Monthly, Yearly }

/// <summary>The editable fields of an event. For all-day events End is the last day (inclusive).</summary>
public sealed record EventEdit(
    string Summary, string? Location, string? Description, bool AllDay,
    DateTime StartLocal, DateTime EndLocal, EventRepeat Repeat);

/// <summary>A calendar collection on the CalDAV server.</summary>
public sealed record CalendarInfo(string Id, string Name, string? Color);

public sealed record CalendarRange(IReadOnlyList<CalendarInfo> Calendars, IReadOnlyList<CalendarEvent> Events, IReadOnlyList<string> Errors);

/// <summary>A note: a VJOURNAL in a CalDAV collection.</summary>
public sealed record NoteItem(string Uid, string Title, string Body, DateTimeOffset? Modified, string CollectionId)
{
    /// <summary>The .ics resource on the server and its ETag (for conflict-safe edits).</summary>
    public string? Href { get; init; }
    public string? ETag { get; init; }
    public IReadOnlyList<string> Categories { get; init; } = [];
}

public sealed record NoteEdit(string Title, string Body);

public sealed record NoteList(IReadOnlyList<CalendarInfo> Collections, IReadOnlyList<NoteItem> Notes, IReadOnlyList<string> Errors);

/// <summary>Task priority as the editor offers it; maps onto RFC 5545 PRIORITY (1 high, 5 medium, 9 low, 0 none).</summary>
public enum TaskPriority { None, High, Medium, Low }

/// <summary>
/// A task: a VTODO in a CalDAV collection. A due date without a time is carried at midnight
/// UTC (like all-day events) and must be shown by date.
/// </summary>
public sealed record TaskItem(
    string Uid, string Title, string? Notes, DateTimeOffset? Due, bool DueIsDate,
    bool Completed, TaskPriority Priority, string CollectionId)
{
    public string? Href { get; init; }
    public string? ETag { get; init; }
    public DateTimeOffset? CompletedAt { get; init; }
    public DateTimeOffset? Created { get; init; }
    /// <summary>True when the task repeats (RRULE); this app edits the series as one task.</summary>
    public bool IsRecurring { get; init; }
}

/// <summary>The editable fields of a task. <see cref="DueLocal"/> is wall-clock in the viewer's zone (a date when <see cref="DueHasTime"/> is false).</summary>
public sealed record TaskEdit(string Title, string? Notes, DateTime? DueLocal, bool DueHasTime, bool Completed, TaskPriority Priority);

public sealed record TaskList(IReadOnlyList<CalendarInfo> Collections, IReadOnlyList<TaskItem> Tasks, IReadOnlyList<string> Errors);

public sealed record ContactInfo(
    string Uid, string FullName, string? Email, string? Phone, string? Organization)
{
    public IReadOnlyList<ContactValue> Emails { get; init; } = [];
    public IReadOnlyList<ContactValue> Phones { get; init; } = [];
    public string? Title { get; init; }
    public string? Note { get; init; }
    public string? Birthday { get; init; }
    /// <summary>Inline photo as a data: URI (remote photo URLs are never fetched).</summary>
    public string? Photo { get; init; }
    public string? AddressBookId { get; init; }
    public string? GivenName { get; init; }
    public string? FamilyName { get; init; }
    /// <summary>The card's URL on the server, and its ETag for conflict-safe updates.</summary>
    public string? Href { get; init; }
    public string? ETag { get; init; }
    /// <summary>The vCard as stored, so edits keep fields this app doesn't show (addresses, custom fields...).</summary>
    public string? RawCard { get; init; }
    /// <summary>The contact's OpenPGP public key (armored), from the vCard KEY property.</summary>
    public string? PublicKey { get; init; }
}

/// <summary>The editable fields of a contact. Lists replace the card's emails/phones wholesale.</summary>
public sealed record ContactEdit(
    string? GivenName, string? FamilyName, string? Organization, string? Title,
    IReadOnlyList<ContactValue> Emails, IReadOnlyList<ContactValue> Phones,
    string? Birthday, string? Note)
{
    /// <summary>Armored OpenPGP public key: null keeps the card's key, empty removes it.</summary>
    public string? PublicKey { get; init; }
}

/// <summary>An email address or phone number with its label ("Work", "Mobile", ...).</summary>
public sealed record ContactValue(string Value, string? Label);

public sealed record ContactList(IReadOnlyList<CalendarInfo> AddressBooks, IReadOnlyList<ContactInfo> Contacts, IReadOnlyList<string> Errors);

public sealed record DomainDto(
    string Name,
    string? ImapHost, int? ImapPort, MailSecurity? ImapSecurity,
    bool ImapAllowInvalidCertificates,
    string? SmtpHost, int? SmtpPort, MailSecurity? SmtpSecurity,
    string? SieveHost, int? SievePort,
    string? CalDavUrl, string? CardDavUrl,
    DateTime CreatedUtc);

public sealed record AdminSettingDto(string Key, string? Value);

public sealed record UserDto(string Username, string Email, bool IsAdmin, DateTime CreatedUtc, DateTime? LastLoginUtc);

public sealed record AdminToggleDto(bool IsAdmin);
/// <summary>Where the CalDAV password comes from: the mail password, a saved separate one, or a saved one that no longer opens.</summary>
public enum DavPasswordSource { MailPassword, Saved, NeedsReentry }

/// <summary>A user's CalDAV account settings as shown in the UI. The password itself is never sent.</summary>
public sealed record CalDavSettingsDto(
    string? Url, string? Username, DavPasswordSource PasswordSource,
    string? DefaultUrl, string MailLogin);

public sealed record CalDavTestResult(bool Success, string Message, IReadOnlyList<string> Calendars, IReadOnlyList<string>? AddressBooks = null);

/// <summary>A user's Documents (WebDAV) settings as shown in the UI. Passwords are never sent.</summary>
public sealed record DocumentsSettingsDto(
    bool Enabled, bool EnabledByDomain, string? Url, string? Username, DavPasswordSource PasswordSource,
    string? DefaultUrl, string DefaultUsername, bool CalDavPasswordIsSeparate);

/// <summary>A file or folder in the WebDAV store. <see cref="Path"/> is relative to the account root, e.g. "/Projects/Q3.pdf".</summary>
public sealed record DavItem(string Name, string Path, bool IsFolder, long? Size, DateTimeOffset? Modified, string? ContentType);

public sealed record DavListing(string Path, IReadOnlyList<DavItem> Items, long? QuotaUsed, long? QuotaAvailable);

/// <summary>Admin-level Documents settings for one domain.</summary>
public sealed record DomainDocumentsDto(string Domain, bool Enabled, string? Url);
