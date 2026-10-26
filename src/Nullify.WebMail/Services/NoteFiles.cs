// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using Nullify.WebMail.Shared;

namespace Nullify.WebMail.Services;

/// <summary>
/// Notes as files on the user's computer. A note saves as a plain-text file named after its
/// title, holding its body; a text file loads back the same way. An .ics file loads every
/// VJOURNAL it carries.
/// </summary>
public static class NoteFiles
{
    public const string Accept = ".txt,.md,.markdown,.text,.ics,text/plain,text/markdown,text/calendar";

    private static readonly char[] Unsafe = ['\\', '/', ':', '*', '?', '"', '<', '>', '|'];

    /// <summary>What a note is called in the list: its title, else its first line.</summary>
    public static string DisplayTitle(NoteItem n) =>
        n.Title.Length > 0 ? n.Title : FirstLine(n.Body) is { Length: > 0 } first ? first : "Untitled";

    /// <summary>A filename that's safe on any desktop, from the note's title.</summary>
    public static string FileName(NoteItem n)
    {
        var name = new string(DisplayTitle(n).Select(c => char.IsControl(c) || Unsafe.Contains(c) ? ' ' : c).ToArray());
        name = string.Join(' ', name.Split(' ', StringSplitOptions.RemoveEmptyEntries)).Trim('.', ' ');
        if (name.Length > 80) name = name[..80].TrimEnd('.', ' ');
        return (name.Length == 0 ? "Note" : name) + ".txt";
    }

    public static string Content(NoteItem n) => n.Body.EndsWith('\n') || n.Body.Length == 0 ? n.Body : n.Body + "\n";

    /// <summary>
    /// The notes a file holds. A text file is one note titled after the file, unless the name is
    /// just the first line (as an untitled note saves), which then stays untitled.
    /// </summary>
    public static IReadOnlyList<NoteEdit> Read(string fileName, string content, TimeZoneInfo zone)
    {
        content = content.Replace("\r\n", "\n").Replace('\r', '\n');
        if (Path.GetExtension(fileName).Equals(".ics", StringComparison.OrdinalIgnoreCase) || content.TrimStart().StartsWith("BEGIN:VCALENDAR", StringComparison.OrdinalIgnoreCase))
        {
            return ICalendar.ParseJournals(content, zone).Where(j => j.Status != "CANCELLED")
                .Where(j => j.Summary.Length > 0 || j.Description.Length > 0)
                .Select(j => new NoteEdit(j.Summary, j.Description)).ToList();
        }

        var body = content.Trim('\n');
        var title = Path.GetFileNameWithoutExtension(fileName).Trim();
        if (title == FirstLine(body)) title = "";
        return title.Length == 0 && body.Trim().Length == 0 ? [] : [new NoteEdit(title, body)];
    }

    private static string FirstLine(string text) =>
        text.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).FirstOrDefault() ?? "";
}
