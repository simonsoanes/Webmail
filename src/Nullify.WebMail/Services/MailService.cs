// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using System.Text;
using Nullify.WebMail.Services;
using Nullify.WebMail.Shared;

namespace Nullify.WebMail.Services;

/// <summary>
/// In-process mail operations shared by the Blazor UI facade and the REST controllers.
/// All methods take an explicit credential — no HttpContext dependency, so they work
/// inside interactive circuits.
/// </summary>
public sealed class MailService(ConnectionPool pool, SmtpClient smtp, SettingsService settings, IdentityService identities, ILogger<MailService> logger)
{
    private static readonly string[] SpecialUses = ["Sent", "Drafts", "Trash", "Junk", "Archive"];

    /// <summary>
    /// The folders to show: the subscribed ones (and INBOX), with counts. A server where nothing
    /// is subscribed shows everything, so a fresh account is never left with an empty list.
    /// <paramref name="all"/> lists every folder with its subscription, without counts (for Settings).
    /// </summary>
    public Task<IReadOnlyList<FolderInfo>> GetFoldersAsync(CredentialInfo cred, bool all = false) =>
        WithSession<IReadOnlyList<FolderInfo>>(cred, async s =>
        {
            var folders = await s.ListFoldersAsync();
            HashSet<string> subscribed;
            try { subscribed = await s.ListSubscribedAsync(); }
            catch (ImapProtocolException ex)
            {
                logger.LogDebug("LSUB failed: {Msg}", ex.Message);
                subscribed = folders.Select(f => f.Name).ToHashSet(StringComparer.Ordinal);
            }
            var list = new List<FolderInfo>();
            foreach (var f in folders
                         .Where(f => !f.Attributes.Contains("Noselect", StringComparer.OrdinalIgnoreCase)
                                     && !f.Attributes.Contains("NonExistent", StringComparer.OrdinalIgnoreCase))
                         .Take(all ? 1000 : 200))
            {
                var isSubscribed = subscribed.Contains(f.Name);
                var use = SpecialUseOf(f);
                if (!all && !isSubscribed && use != "Inbox" && subscribed.Count > 0) continue;
                int total = 0, unseen = 0;
                if (!all)
                {
                    try { (total, unseen) = await s.StatusAsync(f.Name); }
                    catch (Exception ex) { logger.LogDebug("STATUS {Folder} failed: {Msg}", f.Name, ex.Message); }
                }
                list.Add(new FolderInfo(f.Name, string.Join(",", f.Attributes), total, unseen,
                    f.Delimiter, use, isSubscribed));
            }
            return list;
        });

    /// <summary>
    /// Show or hide a folder in the folder list by (un)subscribing it. With no subscriptions at
    /// all every folder is shown, so hiding one first subscribes all the others.
    /// </summary>
    public Task SetFolderShownAsync(CredentialInfo cred, string folder, bool shown) =>
        WithSession(cred, async s =>
        {
            var subscribed = await s.ListSubscribedAsync();
            if (!shown && subscribed.Count == 0)
            {
                foreach (var f in await s.ListFoldersAsync())
                    if (f.Name != folder && !f.Attributes.Contains("Noselect", StringComparer.OrdinalIgnoreCase)
                        && !f.Attributes.Contains("NonExistent", StringComparer.OrdinalIgnoreCase))
                        await s.SubscribeAsync(f.Name, true);
                return true;
            }
            await s.SubscribeAsync(folder, shown);
            return true;
        });

    public Task MarkAllSeenAsync(CredentialInfo cred, string folder) =>
        WithSession(cred, async s =>
        {
            var sel = await s.SelectFolderAsync(folder);
            if (sel.Total > 0) await s.MarkAllSeenAsync();
            return true;
        });

    /// <summary>Special-use role (RFC 6154) from LIST attributes, falling back to common names.</summary>
    private static string? SpecialUseOf(FolderEntry f)
    {
        if (f.Name.Equals("INBOX", StringComparison.OrdinalIgnoreCase)) return "Inbox";
        foreach (var use in SpecialUses)
            if (f.Attributes.Contains(use, StringComparer.OrdinalIgnoreCase)) return use;
        if (f.Attributes.Contains("All", StringComparer.OrdinalIgnoreCase)) return "Archive";

        var leaf = string.IsNullOrEmpty(f.Delimiter) ? f.Name : f.Name.Split(f.Delimiter[0])[^1];
        return leaf.ToLowerInvariant() switch
        {
            "sent" or "sent items" or "sent messages" or "sent mail" => "Sent",
            "drafts" or "draft" => "Drafts",
            "trash" or "deleted items" or "deleted messages" or "bin" => "Trash",
            "junk" or "spam" or "junk e-mail" or "junk email" => "Junk",
            "archive" or "archives" => "Archive",
            _ => null,
        };
    }

    public Task<MessagePage> GetMessagesAsync(CredentialInfo cred, string folder, int page, int pageSize) =>
        WithSession(cred, async s =>
        {
            var sel = await s.SelectFolderAsync(folder);
            var envs = await s.FetchEnvelopesAsync(sel.Total, page, pageSize);
            return new MessagePage(envs.Where(e => e.Uid > 0).Select(ToSummary).ToList(), sel.Total, page, pageSize,
                sel.Keywords, sel.CanCreateKeywords);
        });

    private static MessageSummary ToSummary(MessageEnvelope e) => new(
        e.Uid, e.Subject, e.From, e.To, e.Date, e.Size,
        e.IsSeen, e.IsFlagged, e.IsAnswered, e.IsDraft, e.MessageId, e.HasAttachments)
    {
        Keywords = e.Keywords,
    };

    public Task<MessageContent> GetMessageAsync(CredentialInfo cred, string folder, long uid) =>
        WithSession(cred, async s =>
        {
            await s.SelectFolderAsync(folder);
            var raw = await s.FetchLiteralAsync($"UID FETCH {uid} (BODY.PEEK[])");
            try { await s.SetFlagsAsync(uid, "\\Seen", ""); }
            catch (Exception ex) { logger.LogDebug("Mark seen failed: {Msg}", ex.Message); }
            var parsed = MimeParser.Parse(raw);
            var html = parsed.HtmlBody != null ? InlineCidImages(parsed.HtmlBody, parsed.Attachments) : null;
            var attachments = parsed.Attachments
                .Select(a => new AttachmentInfo(a.PartId, a.Filename, a.ContentType, a.Data.LongLength, a.ContentId, a.IsInline))
                .ToList();
            var senderAuth = SenderAuth.Analyse(Encoding.Latin1.GetString(raw), settings.Current.ImapAuthServIds);
            return new MessageContent(Encoding.UTF8.GetString(raw), html, parsed.TextBody, parsed.Headers, attachments,
                DetectPgp(parsed), senderAuth, FindScheduling(parsed));
        });

    /// <summary>
    /// The iTIP object of an invitation, cancellation or reply email (RFC 6047): a text/calendar
    /// part with a METHOD, or an attached .ics carrying one.
    /// </summary>
    public static string? FindScheduling(MimeParts parsed) =>
        parsed.Attachments
            .Where(a => a.ContentType is "text/calendar" or "application/ics" ||
                        a.Filename.EndsWith(".ics", StringComparison.OrdinalIgnoreCase))
            .OrderBy(a => a.ContentType == "text/calendar" ? 0 : 1)
            .Select(a => Encoding.UTF8.GetString(a.Data).TrimStart('\uFEFF'))
            .FirstOrDefault(ics => ICalendar.UnfoldLines(ics).Take(50)
                .Any(l => l.StartsWith("METHOD:", StringComparison.OrdinalIgnoreCase)));

    /// <summary>OpenPGP content for the browser to decrypt/verify: PGP/MIME first, then inline blocks.</summary>
    public static PgpMessageInfo? DetectPgp(MimeParts parsed)
    {
        if (parsed.PgpEncrypted != null)
            return new PgpMessageInfo(PgpMessageKind.Encrypted, parsed.PgpEncrypted, null, null);
        if (parsed.PgpSignedEntity != null && parsed.PgpSignature != null)
            return new PgpMessageInfo(PgpMessageKind.Signed, null,
                Convert.ToBase64String(Encoding.Latin1.GetBytes(parsed.PgpSignedEntity)), parsed.PgpSignature);
        var text = parsed.TextBody ?? "";
        if (Block(text, "PGP MESSAGE") is { } message)
            return new PgpMessageInfo(PgpMessageKind.InlineEncrypted, message, null, null);
        if (text.Contains("-----BEGIN PGP SIGNED MESSAGE-----"))
        {
            var start = text.IndexOf("-----BEGIN PGP SIGNED MESSAGE-----", StringComparison.Ordinal);
            var end = text.IndexOf("-----END PGP SIGNATURE-----", start, StringComparison.Ordinal);
            if (end > start)
                return new PgpMessageInfo(PgpMessageKind.InlineSigned, text[start..(end + "-----END PGP SIGNATURE-----".Length)], null, null);
        }
        return null;

        static string? Block(string text, string type)
        {
            var begin = $"-----BEGIN {type}-----";
            var stop = $"-----END {type}-----";
            var s = text.IndexOf(begin, StringComparison.Ordinal);
            var e = s < 0 ? -1 : text.IndexOf(stop, s, StringComparison.Ordinal);
            return e > s ? text[s..(e + stop.Length)] : null;
        }
    }

    /// <summary>Rewrite cid: references to data: URIs so inline images render inside the sandboxed preview.</summary>
    public static string InlineCidImages(string html, IReadOnlyList<MimeAttachment> attachments)
    {
        foreach (var a in attachments.Where(a => a.ContentId != null && a.ContentType.StartsWith("image/")))
        {
            var cid = "cid:" + a.ContentId;
            if (!html.Contains(cid, StringComparison.OrdinalIgnoreCase)) continue;
            html = html.Replace(cid, $"data:{a.ContentType};base64,{Convert.ToBase64String(a.Data)}",
                StringComparison.OrdinalIgnoreCase);
        }
        return html;
    }

    public Task<MimeAttachment?> GetAttachmentAsync(CredentialInfo cred, string folder, long uid, string partId) =>
        WithSession(cred, async s =>
        {
            await s.SelectFolderAsync(folder);
            var raw = await s.FetchLiteralAsync($"UID FETCH {uid} (BODY.PEEK[])");
            return MimeParser.Parse(raw).Attachments.FirstOrDefault(a => a.PartId == partId);
        });

    public Task SetFlagsAsync(CredentialInfo cred, string folder, long uid, string add, string remove) =>
        SetFlagsAsync(cred, folder, [uid], add, remove);

    public Task SetFlagsAsync(CredentialInfo cred, string folder, IReadOnlyCollection<long> uids, string add, string remove) =>
        WithSession(cred, async s =>
        {
            if (uids.Count == 0) return true;
            await s.SelectFolderAsync(folder);
            await s.SetFlagsAsync(ImapSession.UidSet(uids), add, remove);
            return true;
        });

    public Task MoveAsync(CredentialInfo cred, string folder, long uid, string destination) =>
        MoveAsync(cred, folder, [uid], destination);

    public Task MoveAsync(CredentialInfo cred, string folder, IReadOnlyCollection<long> uids, string destination) =>
        WithSession(cred, async s =>
        {
            if (uids.Count == 0 || folder == destination) return true;
            await s.SelectFolderAsync(folder);
            await s.MoveMessagesAsync(ImapSession.UidSet(uids), destination);
            return true;
        });

    public Task DeleteAsync(CredentialInfo cred, string folder, long uid) =>
        DeleteAsync(cred, folder, [uid]);

    /// <summary>
    /// Move messages to Trash; messages already in Trash (or when the server has no Trash)
    /// are removed permanently. Returns true when the delete was permanent.
    /// </summary>
    public Task<bool> DeleteAsync(CredentialInfo cred, string folder, IReadOnlyCollection<long> uids) =>
        WithSession(cred, async s =>
        {
            if (uids.Count == 0) return false;
            var trash = await FindSpecialFolderAsync(s, "Trash");
            await s.SelectFolderAsync(folder);
            var set = ImapSession.UidSet(uids);
            if (trash != null && !trash.Equals(folder, StringComparison.Ordinal))
            {
                await s.MoveMessagesAsync(set, trash);
                return false;
            }
            await s.ExpungeUidsAsync(set);
            return true;
        });

    // Subscriptions follow the folder: some servers leave them behind on RENAME and DELETE,
    // and a new folder that isn't subscribed would not appear in the list.
    public Task CreateFolderAsync(CredentialInfo cred, string name) =>
        WithSession(cred, async s =>
        {
            await s.CreateFolderAsync(name);
            // With no subscriptions at all every folder is shown; subscribing just this one would hide the rest.
            if ((await s.ListSubscribedAsync()).Count > 0) await TrySubscribe(s, name, true);
            return true;
        });

    public Task DeleteFolderAsync(CredentialInfo cred, string name) =>
        WithSession(cred, async s =>
        {
            await s.DeleteFolderAsync(name);
            await TrySubscribe(s, name, false);
            return true;
        });

    public Task RenameFolderAsync(CredentialInfo cred, string oldName, string newName) =>
        WithSession(cred, async s =>
        {
            var wasSubscribed = (await s.ListSubscribedAsync()).Contains(oldName);
            await s.RenameFolderAsync(oldName, newName);
            if (wasSubscribed)
            {
                await TrySubscribe(s, oldName, false);
                await TrySubscribe(s, newName, true);
            }
            return true;
        });

    private async Task TrySubscribe(ImapSession s, string name, bool subscribe)
    {
        try { await s.SubscribeAsync(name, subscribe); }
        catch (ImapProtocolException ex) { logger.LogDebug("(UN)SUBSCRIBE {Folder} failed: {Msg}", name, ex.Message); }
    }

    public Task<IReadOnlyList<MessageSummary>> SearchAsync(CredentialInfo cred, string folder, string query, int limit) =>
        WithSession<IReadOnlyList<MessageSummary>>(cred, async s =>
        {
            await s.SelectFolderAsync(folder);
            var escaped = query.Replace("\"", "").Replace("\\", "").Trim();
            if (escaped.Length == 0) return new List<MessageSummary>();
            var criteria = $"OR OR SUBJECT \"{escaped}\" FROM \"{escaped}\" TO \"{escaped}\"";
            // Non-ASCII terms need an explicit charset.
            if (escaped.Any(c => c > 127)) criteria = "CHARSET UTF-8 " + criteria;
            var uids = await s.SearchAsync(criteria);
            var newest = uids.OrderDescending().Take(limit).ToList();
            var envs = await s.FetchEnvelopesByUidAsync(newest);
            return envs.Where(e => e.Uid > 0).Select(ToSummary).ToList();
        });

    public Task<byte[]> FetchAttachmentAsync(CredentialInfo cred, string folder, long uid, string part) =>
        WithSession(cred, async s =>
        {
            await s.SelectFolderAsync(folder);
            return await s.FetchBodyPartAsync(uid, part);
        });

    public async Task SendAsync(CredentialInfo cred, SendRequest req, string? bodyEntity = null)
    {
        req = req with { From = await identities.ResolveFromAsync(cred.Login, req.From) };
        var mime = BuildMimeMessage(req, cred.Login, bodyEntity);
        var recipients = req.To.Concat(req.Cc ?? []).Concat(req.Bcc ?? [])
            .Select(ExtractAddress).Where(a => a.Length > 0).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        await smtp.SendAsync(
            new SmtpEndpoint(cred.SmtpHost, cred.SmtpPort, cred.SmtpSecurity, false),
            cred.Login, cred.Password,
            ExtractAddress(string.IsNullOrWhiteSpace(req.From) ? cred.Login : req.From),
            recipients, mime);

        // Best-effort save to the Sent folder (server naming varies).
        try
        {
            await WithSession(cred, async s =>
            {
                var sent = await FindSpecialFolderAsync(s, "Sent");
                if (sent != null) await s.AppendMessageAsync(sent, mime);
                return true;
            });
        }
        catch (Exception ex)
        {
            logger.LogWarning("Save to Sent failed: {Msg}", ex.Message);
        }
    }

    /// <summary>Store a draft in the Drafts folder. Returns the folder used, or null if none exists.</summary>
    public async Task<string?> SaveDraftAsync(CredentialInfo cred, SendRequest req)
    {
        req = req with { From = await identities.ResolveFromAsync(cred.Login, req.From) };
        return await WithSession(cred, async s =>
        {
            var drafts = await FindSpecialFolderAsync(s, "Drafts");
            if (drafts == null) return null;
            await s.AppendMessageAsync(drafts, BuildMimeMessage(req, cred.Login), "\\Seen \\Draft");
            return drafts;
        });
    }

    private static async Task<string?> FindSpecialFolderAsync(ImapSession session, string use)
    {
        var folders = await session.ListFoldersAsync();
        return folders.FirstOrDefault(f => f.Attributes.Contains(use, StringComparer.OrdinalIgnoreCase))?.Name
            ?? folders.FirstOrDefault(f => SpecialUseOf(f) == use)?.Name;
    }

    /// <summary>"Name &lt;a@b&gt;" → "a@b"; bare addresses pass through.</summary>
    public static string ExtractAddress(string value)
    {
        var lt = value.LastIndexOf('<');
        var gt = value.LastIndexOf('>');
        return (lt >= 0 && gt > lt ? value[(lt + 1)..gt] : value).Trim();
    }

    /// <param name="bodyEntity">
    /// A prepared body entity (headers + content, CRLF) to use instead of building one from
    /// <paramref name="req"/> — e.g. a PGP/MIME multipart/signed or multipart/encrypted entity.
    /// </param>
    public static string BuildMimeMessage(SendRequest req, string fallbackFrom, string? bodyEntity = null)
    {
        var from = string.IsNullOrWhiteSpace(req.From) ? fallbackFrom : req.From;
        var sb = new StringBuilder();
        sb.Append("From: ").AppendLine(EncodeAddressList([from]));
        sb.Append("To: ").AppendLine(EncodeAddressList(req.To));
        if (req.Cc is { Count: > 0 }) sb.Append("Cc: ").AppendLine(EncodeAddressList(req.Cc));
        sb.Append("Subject: ").AppendLine(EncodeHeaderWord(req.Subject));
        sb.Append("Date: ").AppendLine(DateTimeOffset.UtcNow.ToString("R"));
        var address = ExtractAddress(from);
        var domain = address.Contains('@') ? address[(address.IndexOf('@') + 1)..] : "localhost";
        sb.Append("Message-ID: <").Append(Guid.NewGuid().ToString("N")).Append('@').Append(domain).AppendLine(">");
        if (!string.IsNullOrWhiteSpace(req.InReplyTo)) sb.Append("In-Reply-To: ").AppendLine(req.InReplyTo.Trim());
        if (!string.IsNullOrWhiteSpace(req.References)) sb.Append("References: ").AppendLine(req.References.Trim());
        if (req.Important)
        {
            // Importance is RFC 2156; X-Priority is what Outlook and most others still read.
            sb.AppendLine("Importance: high");
            sb.AppendLine("X-Priority: 1 (Highest)");
        }
        sb.AppendLine("MIME-Version: 1.0");
        sb.AppendLine("User-Agent: Nullify WebMail");
        sb.Append(bodyEntity ?? BuildBodyEntity(req));

        // IMAP APPEND and SMTP DATA both want CRLF line endings.
        return sb.ToString().Replace("\r\n", "\n").Replace("\n", "\r\n");
    }

    /// <summary>
    /// The message content (text, HTML alternative, attachments) as a standalone MIME entity
    /// with CRLF line endings: what PGP/MIME signs or encrypts.
    /// </summary>
    public static string BuildBodyEntity(SendRequest req)
    {
        var sb = new StringBuilder();
        var attachments = (req.Attachments ?? []).Where(a => a.ContentId == null).ToList();
        if (attachments.Count > 0)
        {
            var mixed = $"----=_Mixed_{Guid.NewGuid():N}";
            sb.Append("Content-Type: multipart/mixed; boundary=\"").Append(mixed).AppendLine("\"");
            sb.AppendLine();
            sb.AppendLine("This is a multi-part message in MIME format.");
            sb.Append("--").AppendLine(mixed);
            AppendBody(sb, req);
            foreach (var a in attachments)
            {
                sb.Append("--").AppendLine(mixed);
                var name = EncodeParam(a.Filename);
                sb.Append("Content-Type: ").Append(string.IsNullOrWhiteSpace(a.ContentType) ? "application/octet-stream" : a.ContentType)
                    .Append("; name=").AppendLine(name);
                sb.AppendLine("Content-Transfer-Encoding: base64");
                sb.Append("Content-Disposition: attachment; filename=").AppendLine(name);
                sb.AppendLine();
                sb.AppendLine(Convert.ToBase64String(a.Data, Base64FormattingOptions.InsertLineBreaks));
            }
            sb.Append("--").Append(mixed).AppendLine("--");
        }
        else
        {
            AppendBody(sb, req);
        }
        return sb.ToString().Replace("\r\n", "\n").Replace("\n", "\r\n");
    }

    /// <summary>RFC 3156 section 4: multipart/encrypted around an armored OpenPGP message.</summary>
    public static string PgpEncryptedEntity(string armoredMessage)
    {
        var boundary = $"----=_Pgp_{Guid.NewGuid():N}";
        var sb = new StringBuilder();
        sb.Append("Content-Type: multipart/encrypted; protocol=\"application/pgp-encrypted\"; boundary=\"").Append(boundary).AppendLine("\"");
        sb.AppendLine();
        sb.AppendLine("This is an OpenPGP/MIME encrypted message (RFC 4880 and 3156)");
        sb.Append("--").AppendLine(boundary);
        sb.AppendLine("Content-Type: application/pgp-encrypted");
        sb.AppendLine("Content-Description: PGP/MIME version identification");
        sb.AppendLine();
        sb.AppendLine("Version: 1");
        sb.AppendLine();
        sb.Append("--").AppendLine(boundary);
        sb.AppendLine("Content-Type: application/octet-stream; name=\"encrypted.asc\"");
        sb.AppendLine("Content-Description: OpenPGP encrypted message");
        sb.AppendLine("Content-Disposition: inline; filename=\"encrypted.asc\"");
        sb.AppendLine();
        sb.AppendLine(armoredMessage.TrimEnd());
        sb.AppendLine();
        sb.Append("--").Append(boundary).AppendLine("--");
        return sb.ToString().Replace("\r\n", "\n").Replace("\n", "\r\n");
    }

    /// <summary>
    /// RFC 3156 section 5: multipart/signed. <paramref name="signedEntity"/> must be exactly
    /// the bytes that were signed (CRLF); it is inserted unchanged.
    /// </summary>
    public static string PgpSignedEntity(string signedEntity, string armoredSignature, string micalg)
    {
        var boundary = $"----=_PgpSig_{Guid.NewGuid():N}";
        var head = new StringBuilder();
        head.Append("Content-Type: multipart/signed; micalg=").Append(micalg)
            .Append("; protocol=\"application/pgp-signature\"; boundary=\"").Append(boundary).AppendLine("\"");
        head.AppendLine();
        head.AppendLine("This is an OpenPGP/MIME signed message (RFC 4880 and 3156)");
        head.Append("--").AppendLine(boundary);
        var tail = new StringBuilder();
        tail.AppendLine();
        tail.Append("--").AppendLine(boundary);
        tail.AppendLine("Content-Type: application/pgp-signature; name=\"signature.asc\"");
        tail.AppendLine("Content-Description: OpenPGP digital signature");
        tail.AppendLine("Content-Disposition: attachment; filename=\"signature.asc\"");
        tail.AppendLine();
        tail.AppendLine(armoredSignature.TrimEnd());
        tail.AppendLine();
        tail.Append("--").Append(boundary).AppendLine("--");
        string Crlf(string x) => x.Replace("\r\n", "\n").Replace("\n", "\r\n");
        // The signed part must not gain or lose a single byte, so it is not re-normalised.
        return Crlf(head.ToString()) + signedEntity.TrimEnd('\r', '\n') + Crlf(tail.ToString());
    }

    private static void AppendBody(StringBuilder sb, SendRequest req)
    {
        if (!string.IsNullOrEmpty(req.HtmlBody) || req.Calendar != null)
        {
            var boundary = $"----=_Alt_{Guid.NewGuid():N}";
            sb.Append("Content-Type: multipart/alternative; boundary=\"").Append(boundary).AppendLine("\"");
            sb.AppendLine();
            sb.Append("--").AppendLine(boundary);
            AppendTextPart(sb, "text/plain", req.TextBody ?? "");
            if (!string.IsNullOrEmpty(req.HtmlBody))
            {
                sb.Append("--").AppendLine(boundary);
                AppendHtml(sb, req);
            }
            if (req.Calendar is { } cal)
            {
                // Last, as the richest alternative: mail apps that understand it show an invitation.
                sb.Append("--").AppendLine(boundary);
                AppendTextPart(sb, $"text/calendar; method={cal.Method}", cal.Ics);
            }
            sb.Append("--").Append(boundary).AppendLine("--");
        }
        else
        {
            AppendTextPart(sb, "text/plain", req.TextBody ?? "");
        }
    }

    /// <summary>The HTML part, wrapped in multipart/related with any images it shows (RFC 2387).</summary>
    private static void AppendHtml(StringBuilder sb, SendRequest req)
    {
        var images = (req.Attachments ?? []).Where(a => a.ContentId != null).ToList();
        if (images.Count == 0)
        {
            AppendTextPart(sb, "text/html", req.HtmlBody!);
            return;
        }
        var boundary = $"----=_Rel_{Guid.NewGuid():N}";
        sb.Append("Content-Type: multipart/related; type=\"text/html\"; boundary=\"").Append(boundary).AppendLine("\"");
        sb.AppendLine();
        sb.Append("--").AppendLine(boundary);
        AppendTextPart(sb, "text/html", req.HtmlBody!);
        foreach (var img in images)
        {
            sb.Append("--").AppendLine(boundary);
            var name = EncodeParam(img.Filename);
            sb.Append("Content-Type: ").Append(OneLine(img.ContentType)).Append("; name=").AppendLine(name);
            sb.AppendLine("Content-Transfer-Encoding: base64");
            sb.Append("Content-ID: <").Append(OneLine(img.ContentId!).Trim('<', '>')).AppendLine(">");
            sb.Append("Content-Disposition: inline; filename=").AppendLine(name);
            sb.AppendLine();
            sb.AppendLine(Convert.ToBase64String(img.Data, Base64FormattingOptions.InsertLineBreaks));
        }
        sb.Append("--").Append(boundary).AppendLine("--");
    }

    private static string OneLine(string value) => value.Replace("\r", "").Replace("\n", "");

    private static void AppendTextPart(StringBuilder sb, string type, string text)
    {
        sb.Append("Content-Type: ").Append(type).AppendLine("; charset=utf-8");
        sb.AppendLine("Content-Transfer-Encoding: base64");
        sb.AppendLine();
        sb.AppendLine(Convert.ToBase64String(Encoding.UTF8.GetBytes(text), Base64FormattingOptions.InsertLineBreaks));
    }

    /// <summary>RFC 2047 B-encoding for non-ASCII header text.</summary>
    public static string EncodeHeaderWord(string value)
    {
        if (value.All(c => c >= 32 && c < 127)) return value;
        // Keep each encoded word under the 75-char limit by chunking on char boundaries.
        var words = new List<string>();
        var chunk = new StringBuilder();
        foreach (var rune in value.EnumerateRunes())
        {
            chunk.Append(rune.ToString());
            if (Encoding.UTF8.GetByteCount(chunk.ToString()) >= 40)
            {
                words.Add(chunk.ToString());
                chunk.Clear();
            }
        }
        if (chunk.Length > 0) words.Add(chunk.ToString());
        return string.Join("\r\n ", words.Select(w => "=?utf-8?B?" + Convert.ToBase64String(Encoding.UTF8.GetBytes(w)) + "?="));
    }

    private static string EncodeAddressList(IEnumerable<string> addresses) =>
        string.Join(", ", addresses.Select(a =>
        {
            var addr = ExtractAddress(a);
            var lt = a.LastIndexOf('<');
            if (lt <= 0) return addr;
            var name = a[..lt].Trim().Trim('"');
            if (name.Length == 0) return addr;
            var encoded = name.All(c => c >= 32 && c < 127)
                ? "\"" + name.Replace("\\", "\\\\").Replace("\"", "\\\"") + "\""
                : EncodeHeaderWord(name);
            return $"{encoded} <{addr}>";
        }));

    private static string EncodeParam(string filename)
    {
        var safe = filename.Replace("\r", "").Replace("\n", "");
        return safe.All(c => c >= 32 && c < 127)
            ? "\"" + safe.Replace("\\", "\\\\").Replace("\"", "\\\"") + "\""
            : "\"" + EncodeHeaderWord(safe).Replace("\r\n ", "") + "\"";
    }

    private async Task<T> WithSession<T>(CredentialInfo cred, Func<ImapSession, Task<T>> op)
    {
        var ep = new ImapEndpoint(cred.Host, cred.Port, cred.Security, cred.AllowInvalidCertificates);
        var key = ConnectionPool.KeyFor(ep, cred.Login);
        var session = await pool.GetSessionAsync(ep, cred.Login, cred.Password);
        try
        {
            var result = await op(session);
            pool.ReturnSession(key, session);
            return result;
        }
        catch
        {
            pool.RemoveSession(key, session);
            throw;
        }
    }
}
