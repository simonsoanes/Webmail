// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Nullify.WebMail.Services;
using Nullify.WebMail.Shared;

namespace Nullify.WebMail.Controllers;

/// <summary>REST surface for mail operations (parity with the in-process facade the UI uses).</summary>
[ApiController]
[Route("api/mail")]
[Authorize]
public class MailController(AuthService auth, MailService mail) : ControllerBase
{
    private CredentialInfo? Cred => auth.GetCredential();

    [HttpGet("folders")]
    public async Task<ActionResult<IReadOnlyList<FolderInfo>>> Folders()
    {
        if (Cred is not { } cred) return Unauthorized();
        return Ok(await mail.GetFoldersAsync(cred));
    }

    [HttpGet("folders/{folderName}/messages")]
    public async Task<ActionResult<MessagePage>> Messages(
        string folderName, [FromQuery] int page = 0, [FromQuery] int pageSize = 50)
    {
        if (Cred is not { } cred) return Unauthorized();
        pageSize = Math.Clamp(pageSize, 1, 200);
        return Ok(await mail.GetMessagesAsync(cred, folderName, Math.Max(0, page), pageSize));
    }

    [HttpGet("folders/{folderName}/messages/{uid:long}")]
    public async Task<ActionResult<MessageContent>> Message(string folderName, long uid)
    {
        if (Cred is not { } cred) return Unauthorized();
        return Ok(await mail.GetMessageAsync(cred, folderName, uid));
    }

    [HttpGet("folders/{folderName}/messages/{uid:long}/attachments/{part}")]
    public async Task<IActionResult> Attachment(string folderName, long uid, string part)
    {
        if (Cred is not { } cred) return Unauthorized();
        var attachment = await mail.GetAttachmentAsync(cred, folderName, uid, part);
        if (attachment == null) return NotFound();
        // Always a download: serving mail-supplied HTML/SVG inline would run it on our origin.
        return File(attachment.Data, "application/octet-stream", attachment.Filename);
    }

    /// <summary>Query-string form for the UI: folder names may contain '/', which a route segment cannot carry.</summary>
    [HttpGet("attachment")]
    public Task<IActionResult> AttachmentByQuery([FromQuery] string folder, [FromQuery] long uid, [FromQuery] string part) =>
        Attachment(folder, uid, part);

    [HttpPut("folders/{folderName}/messages/{uid:long}/flags")]
    public async Task<IActionResult> SetFlags(string folderName, long uid, [FromBody] FlagRequest req)
    {
        if (Cred is not { } cred) return Unauthorized();
        await mail.SetFlagsAsync(cred, folderName, uid, req.AddFlags ?? "", req.RemoveFlags ?? "");
        return Ok();
    }

    [HttpPost("folders/{folderName}/messages/{uid:long}/move")]
    public async Task<IActionResult> Move(string folderName, long uid, [FromBody] MoveRequest req)
    {
        if (Cred is not { } cred) return Unauthorized();
        await mail.MoveAsync(cred, folderName, uid, req.Destination);
        return Ok();
    }

    [HttpDelete("folders/{folderName}/messages/{uid:long}")]
    public async Task<IActionResult> Delete(string folderName, long uid)
    {
        if (Cred is not { } cred) return Unauthorized();
        await mail.DeleteAsync(cred, folderName, uid);
        return Ok();
    }

    [HttpGet("folders/{folderName}/search")]
    public async Task<ActionResult<IReadOnlyList<MessageSummary>>> Search(
        string folderName, [FromQuery] string q, [FromQuery] int limit = 50)
    {
        if (Cred is not { } cred) return Unauthorized();
        if (string.IsNullOrWhiteSpace(q)) return Ok(Array.Empty<MessageSummary>());
        return Ok(await mail.SearchAsync(cred, folderName, q, Math.Clamp(limit, 1, 200)));
    }

    [HttpPost("send")]
    public async Task<IActionResult> Send([FromBody] SendRequest req)
    {
        if (Cred is not { } cred) return Unauthorized();
        if (req.To == null || req.To.Count == 0) return BadRequest("No recipients.");
        await mail.SendAsync(cred, req);
        return Ok();
    }

    [HttpPost("folders")]
    public async Task<IActionResult> CreateFolder([FromBody] FolderOperation req)
    {
        if (Cred is not { } cred) return Unauthorized();
        await mail.CreateFolderAsync(cred, req.FolderName);
        return Ok();
    }

    [HttpDelete("folders/{folderName}")]
    public async Task<IActionResult> DeleteFolder(string folderName)
    {
        if (Cred is not { } cred) return Unauthorized();
        await mail.DeleteFolderAsync(cred, folderName);
        return Ok();
    }

    [HttpPut("folders/{folderName}")]
    public async Task<IActionResult> RenameFolder(string folderName, [FromBody] FolderOperation req)
    {
        if (Cred is not { } cred) return Unauthorized();
        await mail.RenameFolderAsync(cred, folderName, req.FolderName);
        return Ok();
    }
}