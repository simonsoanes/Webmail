// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using Nullify.WebMail.Shared;

namespace Nullify.WebMail.Services;

/// <summary>
/// Message actions shared by the list, the reading pane and keyboard shortcuts. Each one
/// updates <see cref="AppState"/> optimistically, then calls the server and reports via a toast.
/// </summary>
public sealed class MailActions(ApiService api, AppState state)
{
    private string? Folder => state.SelectedFolder;

    public MessageSummary? Find(long uid) => state.CurrentMessages.FirstOrDefault(m => m.Uid == uid);

    public async Task ToggleFlaggedAsync(long uid)
    {
        if (Folder == null || Find(uid) is not { } msg) return;
        var flagged = !msg.IsFlagged;
        Update(uid, m => m with { IsFlagged = flagged });
        await Run(() => api.SetFlagsAsync(Folder, [uid], flagged ? "\\Flagged" : null, flagged ? null : "\\Flagged"),
            null, "Could not update the star");
    }

    public async Task SetSeenAsync(IReadOnlyCollection<long> uids, bool seen)
    {
        if (Folder == null || uids.Count == 0) return;
        var changed = state.CurrentMessages.Count(m => uids.Contains(m.Uid) && m.IsSeen != seen);
        foreach (var uid in uids) Update(uid, m => m with { IsSeen = seen });
        state.AdjustUnread(Folder, seen ? -changed : changed);
        await Run(() => api.SetFlagsAsync(Folder, uids, seen ? "\\Seen" : null, seen ? null : "\\Seen"),
            uids.Count > 1 ? $"Marked {uids.Count} messages as {(seen ? "read" : "unread")}" : null,
            "Could not update read state");
    }

    /// <summary>Add or remove a tag (IMAP keyword) on messages.</summary>
    public async Task SetTagAsync(IReadOnlyCollection<long> uids, string keyword, bool on)
    {
        if (Folder == null || uids.Count == 0 || !MailTags.IsValidKeyword(keyword)) return;
        foreach (var uid in uids)
            Update(uid, m => m with
            {
                Keywords = on
                    ? m.Keywords.Append(keyword).Distinct(StringComparer.OrdinalIgnoreCase).ToList()
                    : m.Keywords.Where(k => !k.Equals(keyword, StringComparison.OrdinalIgnoreCase)).ToList(),
            });
        if (on && !state.FolderTags.Contains(keyword, StringComparer.OrdinalIgnoreCase))
            state.FolderTags = state.FolderTags.Append(keyword).ToList();
        var label = MailTags.Label(keyword);
        await Run(() => api.SetFlagsAsync(Folder, uids, on ? keyword : null, on ? null : keyword),
            uids.Count > 1 ? (on ? $"Tagged {uids.Count} messages \"{label}\"" : $"Removed \"{label}\" from {uids.Count} messages") : null,
            "Could not update tags");
    }

    /// <summary>Remove every tag from messages.</summary>
    public async Task ClearTagsAsync(IReadOnlyCollection<long> uids)
    {
        if (Folder == null || uids.Count == 0) return;
        var tags = state.CurrentMessages.Where(m => uids.Contains(m.Uid))
            .SelectMany(m => MailTags.Tags(m.Keywords)).Where(MailTags.IsValidKeyword)
            .Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        if (tags.Count == 0) return;
        foreach (var uid in uids) Update(uid, m => m with { Keywords = m.Keywords.Where(k => !MailTags.IsTag(k)).ToList() });
        await Run(() => api.SetFlagsAsync(Folder, uids, null, string.Join(' ', tags)), null, "Could not remove tags");
    }

    public async Task MarkFolderReadAsync(string folder)
    {
        if (folder == Folder)
            state.CurrentMessages = state.CurrentMessages.Select(m => m.IsSeen ? m : m with { IsSeen = true }).ToList();
        state.Folders = state.Folders.Select(f => f.Name == folder ? f with { UnreadMessages = 0 } : f).ToList();
        state.NotifyStateChanged();
        var label = state.Folders.FirstOrDefault(f => f.Name == folder) is { } f ? MailFormat.FolderLeaf(f) : folder;
        await Run(() => api.MarkAllReadAsync(folder), $"Marked everything in {label} as read", "Could not mark the folder as read");
        Refresh();
    }

    /// <summary>Local-only: the server marks a message seen when its body is fetched.</summary>
    public void MarkSeenLocally(long uid)
    {
        if (Folder == null || Find(uid) is not { IsSeen: false }) return;
        Update(uid, m => m with { IsSeen = true });
        state.AdjustUnread(Folder, -1);
        state.NotifyStateChanged();
    }

    public async Task DeleteAsync(IReadOnlyCollection<long> uids)
    {
        if (Folder == null || uids.Count == 0) return;
        var folder = Folder;
        var inTrash = state.FindSpecialFolder("Trash")?.Name == folder;
        RemoveLocally(uids);
        var noun = uids.Count == 1 ? "Message" : $"{uids.Count} messages";
        try
        {
            var permanent = await api.DeleteAsync(folder, uids);
            state.ShowToast(permanent || inTrash ? $"{noun} deleted permanently" : $"{noun} moved to Trash");
        }
        catch (Exception ex)
        {
            state.ShowToast($"Delete failed: {ex.InnerException?.Message ?? ex.Message}", isError: true);
        }
        Refresh();
    }

    public async Task MoveAsync(IReadOnlyCollection<long> uids, string destination)
    {
        if (Folder == null || uids.Count == 0 || destination == Folder) return;
        var folder = Folder;
        RemoveLocally(uids);
        var label = state.Folders.FirstOrDefault(f => f.Name == destination) is { } f ? MailFormat.FolderLeaf(f) : destination;
        try
        {
            await api.MoveAsync(folder, uids, destination);
            state.ShowToast(uids.Count == 1 ? $"Moved to {label}" : $"Moved {uids.Count} messages to {label}");
        }
        catch (Exception ex)
        {
            state.ShowToast($"Move failed: {ex.InnerException?.Message ?? ex.Message}", isError: true);
        }
        Refresh();
    }

    public Task ArchiveAsync(IReadOnlyCollection<long> uids)
    {
        var archive = state.FindSpecialFolder("Archive");
        if (archive == null)
        {
            state.ShowToast("No Archive folder on this server — create one named \"Archive\".", isError: true);
            return Task.CompletedTask;
        }
        return MoveAsync(uids, archive.Name);
    }

    public Task JunkAsync(IReadOnlyCollection<long> uids)
    {
        var junk = state.FindSpecialFolder("Junk");
        if (junk == null)
        {
            state.ShowToast("No Junk folder on this server.", isError: true);
            return Task.CompletedTask;
        }
        return MoveAsync(uids, junk.Name);
    }

    public async Task SetFlaggedAsync(IReadOnlyCollection<long> uids, bool flagged)
    {
        if (Folder == null || uids.Count == 0) return;
        foreach (var uid in uids) Update(uid, m => m with { IsFlagged = flagged });
        await Run(() => api.SetFlagsAsync(Folder, uids, flagged ? "\\Flagged" : null, flagged ? null : "\\Flagged"),
            null, "Could not update the star");
    }

    /// <summary>Select the next (or previous) message relative to the open one.</summary>
    public void SelectRelative(int offset)
    {
        var list = state.CurrentMessages;
        if (list.Count == 0) return;
        var index = state.SelectedMessageUid is { } uid ? list.ToList().FindIndex(m => m.Uid == uid) : -1;
        var next = index < 0 ? 0 : Math.Clamp(index + offset, 0, list.Count - 1);
        state.SelectedMessageUid = list[next].Uid;
        state.ShowCompose = false;
        state.NotifyStateChanged();
    }

    private void RemoveLocally(IReadOnlyCollection<long> uids)
    {
        var list = state.CurrentMessages.ToList();
        if (Folder != null)
            state.AdjustUnread(Folder, -list.Count(m => uids.Contains(m.Uid) && !m.IsSeen));

        // Keep the reading flow going: open the message after the removed one.
        if (state.SelectedMessageUid is { } open && uids.Contains(open))
        {
            var index = list.FindIndex(m => m.Uid == open);
            var after = list.Skip(index + 1).FirstOrDefault(m => !uids.Contains(m.Uid))
                        ?? list.Take(index).LastOrDefault(m => !uids.Contains(m.Uid));
            state.SelectedMessageUid = after?.Uid;
        }
        state.CurrentMessages = list.Where(m => !uids.Contains(m.Uid)).ToList();
        state.CurrentTotal = Math.Max(0, state.CurrentTotal - uids.Count);
        state.NotifyStateChanged();
    }

    private void Update(long uid, Func<MessageSummary, MessageSummary> change)
    {
        state.CurrentMessages = state.CurrentMessages.Select(m => m.Uid == uid ? change(m) : m).ToList();
        state.NotifyStateChanged();
    }

    private void Refresh()
    {
        state.FoldersVersion++;
        state.NotifyStateChanged();
    }

    private async Task Run(Func<Task> op, string? success, string failure)
    {
        try
        {
            await op();
            if (success != null) state.ShowToast(success);
        }
        catch (Exception ex)
        {
            state.ShowToast($"{failure}: {ex.InnerException?.Message ?? ex.Message}", isError: true);
            state.ListVersion++; // resync with the server
            state.NotifyStateChanged();
        }
    }
}
