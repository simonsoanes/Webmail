// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

namespace Nullify.WebMail.Services;

/// <summary>A VJOURNAL as stored. Several DESCRIPTIONs are allowed by RFC 5545; they're joined by a blank line.</summary>
public sealed class ICalJournal
{
    public string Uid { get; init; } = "";
    public string Summary { get; init; } = "";
    public string Description { get; init; } = "";
    public string? Status { get; init; }
    public DateTimeOffset? Modified { get; init; }
    public IReadOnlyList<string> Categories { get; init; } = [];
}

/// <summary>A VTODO as stored. A date-only DUE is pinned to midnight UTC (<see cref="DueIsDate"/>).</summary>
public sealed class ICalTodo
{
    public string Uid { get; init; } = "";
    public string Summary { get; init; } = "";
    public string? Description { get; init; }
    public string? Status { get; init; }
    public DateTimeOffset? Due { get; init; }
    public bool DueIsDate { get; init; }
    public DateTimeOffset? Completed { get; init; }
    public int Priority { get; init; }
    public DateTimeOffset? Created { get; init; }
    public DateTimeOffset? Modified { get; init; }
    public string? RRule { get; init; }

    public bool IsCompleted => Status == "COMPLETED" || (Completed != null && Status is null or "");
}

/// <summary>Reading VJOURNALs (notes) and VTODOs (tasks). Overrides of repeating items (RECURRENCE-ID) are skipped.</summary>
public static partial class ICalendar
{
    public static List<ICalJournal> ParseJournals(string ics, TimeZoneInfo floatingZone) =>
        Components(ics, "VJOURNAL").Where(p => !p.ContainsKey("RECURRENCE-ID")).Select(p => new ICalJournal
        {
            Uid = First(p, "UID") ?? Guid.NewGuid().ToString(),
            Summary = Unescape(First(p, "SUMMARY") ?? "").Trim(),
            Description = string.Join("\n\n", All(p, "DESCRIPTION").Select(d => Unescape(d).Trim()).Where(d => d.Length > 0)),
            Status = First(p, "STATUS")?.ToUpperInvariant(),
            Modified = Stamp(p, "LAST-MODIFIED", floatingZone) ?? Stamp(p, "DTSTAMP", floatingZone) ?? Stamp(p, "DTSTART", floatingZone),
            Categories = All(p, "CATEGORIES").SelectMany(SplitList).Select(c => c.Trim()).Where(c => c.Length > 0).Distinct().ToList(),
        }).ToList();

    public static List<ICalTodo> ParseTodos(string ics, TimeZoneInfo floatingZone) =>
        Components(ics, "VTODO").Where(p => !p.ContainsKey("RECURRENCE-ID")).Select(p =>
        {
            DateTimeOffset? due = null;
            var dueIsDate = false;
            if (p.TryGetValue("DUE", out var d) &&
                TryParseTime(d[0].Value, d[0].Params, floatingZone, out var wall, out var zone, out var allDay))
            {
                due = allDay ? new DateTimeOffset(wall.Date, TimeSpan.Zero) : new DateTimeOffset(wall, zone.GetUtcOffset(wall));
                dueIsDate = allDay;
            }
            return new ICalTodo
            {
                Uid = First(p, "UID") ?? Guid.NewGuid().ToString(),
                Summary = Unescape(First(p, "SUMMARY") ?? "").Trim(),
                Description = NullIfEmpty(Unescape(First(p, "DESCRIPTION") ?? "")),
                Status = First(p, "STATUS")?.Trim().ToUpperInvariant(),
                Due = due,
                DueIsDate = dueIsDate,
                Completed = Stamp(p, "COMPLETED", floatingZone),
                Priority = int.TryParse(First(p, "PRIORITY"), out var pr) && pr is >= 0 and <= 9 ? pr : 0,
                Created = Stamp(p, "CREATED", floatingZone),
                Modified = Stamp(p, "LAST-MODIFIED", floatingZone),
                RRule = First(p, "RRULE"),
            };
        }).ToList();

    /// <summary>RFC 5545 PRIORITY → the editor's three levels: 1–4 high, 5 medium, 6–9 low, 0 none.</summary>
    public static Shared.TaskPriority PriorityOf(int value) => value switch
    {
        >= 1 and <= 4 => Shared.TaskPriority.High,
        5 => Shared.TaskPriority.Medium,
        >= 6 and <= 9 => Shared.TaskPriority.Low,
        _ => Shared.TaskPriority.None,
    };

    // ------------------------------------------------------------------ structure

    private sealed class PropertyBag : Dictionary<string, List<(string Value, Dictionary<string, string> Params)>>
    {
        public PropertyBag() : base(StringComparer.OrdinalIgnoreCase) { }
    }

    /// <summary>Top-level properties of each <paramref name="component"/>; nested components (VALARM) are skipped.</summary>
    private static IEnumerable<PropertyBag> Components(string ics, string component)
    {
        PropertyBag? props = null;
        var depth = 0;
        foreach (var line in Unfold(ics))
        {
            if (props == null)
            {
                if (line.Equals("BEGIN:" + component, StringComparison.OrdinalIgnoreCase)) { props = new(); depth = 0; }
                continue;
            }
            if (line.StartsWith("BEGIN:", StringComparison.OrdinalIgnoreCase)) { depth++; continue; }
            if (line.StartsWith("END:", StringComparison.OrdinalIgnoreCase))
            {
                if (depth > 0) { depth--; continue; }
                yield return props;
                props = null;
                continue;
            }
            if (depth > 0) continue;
            var (name, parameters, value) = SplitProperty(line);
            if (!props.TryGetValue(name, out var list)) props[name] = list = new();
            list.Add((value, parameters));
        }
    }

    private static string? First(PropertyBag p, string name) => p.TryGetValue(name, out var v) ? v[0].Value : null;

    private static IEnumerable<string> All(PropertyBag p, string name) => p.TryGetValue(name, out var v) ? v.Select(x => x.Value) : [];

    private static DateTimeOffset? Stamp(PropertyBag p, string name, TimeZoneInfo floating)
    {
        if (!p.TryGetValue(name, out var v) || !TryParseTime(v[0].Value, v[0].Params, floating, out var wall, out var zone, out var allDay))
            return null;
        return allDay ? new DateTimeOffset(wall.Date, TimeSpan.Zero) : new DateTimeOffset(wall, zone.GetUtcOffset(wall));
    }

    /// <summary>A comma-separated text list ("a,b\,c" → "a", "b,c").</summary>
    private static IEnumerable<string> SplitList(string value)
    {
        var current = new System.Text.StringBuilder();
        for (var i = 0; i < value.Length; i++)
        {
            if (value[i] == '\\' && i + 1 < value.Length) { current.Append(value[i]).Append(value[++i]); continue; }
            if (value[i] == ',') { yield return Unescape(current.ToString()); current.Clear(); continue; }
            current.Append(value[i]);
        }
        if (current.Length > 0) yield return Unescape(current.ToString());
    }
}
