// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using Nullify.WebMail.Shared;

namespace Nullify.WebMail.Services;

/// <summary>
/// Writes VJOURNALs (notes) and VTODOs (tasks). As with events, updates rewrite only the
/// properties the editor owns and keep everything else (alarms, categories, X- properties).
/// </summary>
public static partial class ICalendarWriter
{
    private static readonly HashSet<string> NoteManaged = new(StringComparer.OrdinalIgnoreCase)
        { "SUMMARY", "DESCRIPTION", "DTSTAMP", "LAST-MODIFIED", "SEQUENCE" };

    private static readonly HashSet<string> TodoManaged = new(StringComparer.OrdinalIgnoreCase)
        { "SUMMARY", "DESCRIPTION", "DUE", "PRIORITY", "DTSTAMP", "LAST-MODIFIED", "SEQUENCE" };

    // Only rewritten when the task is ticked or unticked, so IN-PROCESS and partial progress survive other edits.
    private static readonly HashSet<string> TodoStatus = new(StringComparer.OrdinalIgnoreCase)
        { "STATUS", "COMPLETED", "PERCENT-COMPLETE" };

    public static string NewJournal(string uid, NoteEdit edit)
    {
        var lines = Header();
        lines.Add("BEGIN:VJOURNAL");
        lines.Add("UID:" + uid);
        lines.Add("CREATED:" + UtcStamp());
        lines.Add($"DTSTART;VALUE=DATE:{DateTime.UtcNow:yyyyMMdd}");
        lines.AddRange(NoteProperties(edit, sequence: 0));
        lines.Add("END:VJOURNAL");
        lines.Add("END:VCALENDAR");
        return Serialize(lines);
    }

    public static string UpdateJournal(string existing, NoteEdit edit) =>
        Serialize(UpdateComponent(existing, "VJOURNAL", name => NoteManaged.Contains(name), _ => false,
            sequence => NoteProperties(edit, sequence)));

    public static string NewTodo(string uid, TaskEdit edit, TimeZoneInfo zone)
    {
        var lines = Header();
        if (edit is { DueLocal: not null, DueHasTime: true } && TzidOf(zone) is { } tzid)
            lines.AddRange(VTimezone(zone, tzid, edit.DueLocal.Value.Year));
        lines.Add("BEGIN:VTODO");
        lines.Add("UID:" + uid);
        lines.Add("CREATED:" + UtcStamp());
        lines.AddRange(TodoProperties(edit, zone, sequence: 0));
        lines.AddRange(StatusProperties(edit.Completed));
        lines.Add("END:VTODO");
        lines.Add("END:VCALENDAR");
        return Serialize(lines);
    }

    /// <summary>Rewrite a task. The completion properties change only when <see cref="TaskEdit.Completed"/> differs from what's stored.</summary>
    public static string UpdateTodo(string existing, TaskEdit edit, TimeZoneInfo zone)
    {
        var stored = ICalendar.ParseTodos(existing, zone).FirstOrDefault()
            ?? throw new InvalidOperationException("The task has no editable component.");
        var statusChanged = stored.IsCompleted != edit.Completed;
        var due = edit.DueLocal is { } d
            ? edit.DueHasTime ? new DateTimeOffset(d, zone.GetUtcOffset(d)) : new DateTimeOffset(d.Date, TimeSpan.Zero)
            : (DateTimeOffset?)null;

        var output = UpdateComponent(existing, "VTODO",
            name => TodoManaged.Contains(name) || (statusChanged && TodoStatus.Contains(name)),
            line => due != null && DropForDue(line, due.Value, zone),
            sequence =>
            {
                var props = TodoProperties(edit, zone, sequence).ToList();
                if (statusChanged) props.AddRange(StatusProperties(edit.Completed));
                return props;
            });
        if (edit is { DueLocal: not null, DueHasTime: true }) EnsureVTimezone(output, zone, edit.DueLocal.Value.Year);
        return Serialize(output);
    }

    /// <summary>Tick or untick a task, leaving everything else (including its due time and zone) as stored.</summary>
    public static string SetTodoCompleted(string existing, bool completed) =>
        Serialize(UpdateComponent(existing, "VTODO",
            name => TodoStatus.Contains(name) || name is "DTSTAMP" or "LAST-MODIFIED" or "SEQUENCE", _ => false,
            sequence => ["DTSTAMP:" + UtcStamp(), "LAST-MODIFIED:" + UtcStamp(), "SEQUENCE:" + sequence, .. StatusProperties(completed)]));

    /// <summary>
    /// DUE can't be combined with DURATION, and must not be before DTSTART (RFC 5545 3.6.2):
    /// a start that's later than the new due date is dropped rather than making the task invalid.
    /// </summary>
    private static bool DropForDue(string line, DateTimeOffset due, TimeZoneInfo zone)
    {
        var name = PropertyName(line);
        if (name == "DURATION") return true;
        if (name != "DTSTART") return false;
        var (_, parameters, value) = ICalendar.SplitProperty(line);
        if (!ICalendar.TryParseTime(value, parameters, zone, out var wall, out var z, out var allDay)) return true;
        var start = allDay ? new DateTimeOffset(wall.Date, TimeSpan.Zero) : new DateTimeOffset(wall, z.GetUtcOffset(wall));
        return start > due;
    }

    // ------------------------------------------------------------------ pieces

    private static List<string> Header() =>
        ["BEGIN:VCALENDAR", "VERSION:2.0", "PRODID:-//Nullify//WebMail//EN", "CALSCALE:GREGORIAN"];

    private static IEnumerable<string> NoteProperties(NoteEdit edit, int sequence)
    {
        yield return "DTSTAMP:" + UtcStamp();
        yield return "LAST-MODIFIED:" + UtcStamp();
        yield return "SEQUENCE:" + sequence;
        yield return "SUMMARY:" + Escape(string.IsNullOrWhiteSpace(edit.Title) ? "Untitled" : edit.Title.Trim());
        if (!string.IsNullOrWhiteSpace(edit.Body)) yield return "DESCRIPTION:" + Escape(edit.Body.TrimEnd());
    }

    private static IEnumerable<string> TodoProperties(TaskEdit edit, TimeZoneInfo zone, int sequence)
    {
        yield return "DTSTAMP:" + UtcStamp();
        yield return "LAST-MODIFIED:" + UtcStamp();
        yield return "SEQUENCE:" + sequence;
        yield return "SUMMARY:" + Escape(string.IsNullOrWhiteSpace(edit.Title) ? "(no title)" : edit.Title.Trim());
        if (!string.IsNullOrWhiteSpace(edit.Notes)) yield return "DESCRIPTION:" + Escape(edit.Notes.Trim());
        if (edit.DueLocal is { } due)
            yield return edit.DueHasTime ? "DUE" + TimeValue(due, zone) : $"DUE;VALUE=DATE:{due:yyyyMMdd}";
        var priority = edit.Priority switch { TaskPriority.High => 1, TaskPriority.Medium => 5, TaskPriority.Low => 9, _ => 0 };
        if (priority > 0) yield return "PRIORITY:" + priority;
    }

    private static IEnumerable<string> StatusProperties(bool completed)
    {
        if (completed)
        {
            yield return "STATUS:COMPLETED";
            yield return "COMPLETED:" + UtcStamp();
            yield return "PERCENT-COMPLETE:100";
        }
        else
        {
            yield return "STATUS:NEEDS-ACTION";
        }
    }

    /// <summary>
    /// Rewrite the first <paramref name="component"/> that isn't an override (no RECURRENCE-ID):
    /// drop its top-level properties that <paramref name="managed"/> or <paramref name="drop"/>
    /// select, and insert <paramref name="properties"/> (given the next SEQUENCE) after BEGIN.
    /// </summary>
    private static List<string> UpdateComponent(string existing, string component, Func<string, bool> managed,
        Func<string, bool> drop, Func<int, IEnumerable<string>> properties)
    {
        var lines = ICalendar.UnfoldLines(existing).ToList();
        var (begin, end) = FindMain(lines, component);
        if (begin < 0) throw new InvalidOperationException($"The item has no editable {component}.");

        var sequence = 0;
        var output = new List<string>();
        var depth = 0;
        for (var i = 0; i < lines.Count; i++)
        {
            var line = lines[i];
            if (i > begin && i < end)
            {
                if (line.StartsWith("BEGIN:", StringComparison.OrdinalIgnoreCase)) depth++;
                else if (line.StartsWith("END:", StringComparison.OrdinalIgnoreCase)) depth--;
                else if (depth == 0)
                {
                    var name = PropertyName(line);
                    if (name == "SEQUENCE" && int.TryParse(line[(line.IndexOf(':') + 1)..], out var seq)) sequence = seq + 1;
                    if (managed(name) || drop(line)) continue;
                }
            }
            output.Add(line);
            if (i == begin) output.AddRange(properties(Math.Max(sequence, 1)));
        }

        // SEQUENCE is only known once the whole component has been read; fix up the inserted value.
        var seqAt = output.FindIndex(begin + 1, l => PropertyName(l) == "SEQUENCE");
        if (seqAt >= 0) output[seqAt] = "SEQUENCE:" + Math.Max(sequence, 1);
        return output;
    }

    private static (int Begin, int End) FindMain(List<string> lines, string component)
    {
        for (var i = 0; i < lines.Count; i++)
        {
            if (!lines[i].Equals("BEGIN:" + component, StringComparison.OrdinalIgnoreCase)) continue;
            var depth = 0;
            var isOverride = false;
            var j = i + 1;
            for (; j < lines.Count; j++)
            {
                var l = lines[j];
                if (depth == 0 && l.Equals("END:" + component, StringComparison.OrdinalIgnoreCase)) break;
                if (l.StartsWith("BEGIN:", StringComparison.OrdinalIgnoreCase)) depth++;
                else if (l.StartsWith("END:", StringComparison.OrdinalIgnoreCase)) depth--;
                else if (depth == 0 && PropertyName(l) == "RECURRENCE-ID") isOverride = true;
            }
            if (!isOverride) return (i, j);
            i = j;
        }
        return (-1, -1);
    }
}
