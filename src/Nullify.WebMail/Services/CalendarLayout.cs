// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

namespace Nullify.WebMail.Services;

/// <summary>
/// Days or times highlighted on the calendar. For all-day slots <see cref="End"/> is the last
/// day (inclusive), as the event editor takes it; for timed slots it is exclusive.
/// </summary>
public readonly record struct CalendarSlot(DateTime Start, DateTime End, bool AllDay)
{
    public bool Contains(DateOnly day) =>
        AllDay ? day >= DateOnly.FromDateTime(Start) && day <= DateOnly.FromDateTime(End)
               : day.ToDateTime(TimeOnly.MinValue) < End && day.AddDays(1).ToDateTime(TimeOnly.MinValue) > Start;
}

/// <summary>Placing timed events on a day of the week and day views.</summary>
public static class CalendarLayout
{
    /// <summary>
    /// An event's box on the day, in percent of the day's height (top and height) and as one of
    /// <see cref="Columns"/> side-by-side columns shared with the events it overlaps.
    /// </summary>
    public readonly record struct Placed<T>(T Item, double Top, double Height, int Column, int Columns);

    /// <summary>
    /// Lay out events on <paramref name="day"/>: each is clipped to the day, given at least
    /// <paramref name="minMinutes"/> of height so short ones stay readable, and events that
    /// overlap (including through that minimum) share the width in columns.
    /// </summary>
    public static List<Placed<T>> Day<T>(IEnumerable<T> items, Func<T, (DateTime Start, DateTime End)> span, DateOnly day, int minMinutes = 20)
    {
        var dayStart = day.ToDateTime(TimeOnly.MinValue);
        var boxes = items.Select(item =>
            {
                var (s, e) = span(item);
                var start = Math.Clamp((s - dayStart).TotalMinutes, 0, 1440);
                var end = Math.Clamp((e - dayStart).TotalMinutes, 0, 1440);
                end = Math.Min(1440, Math.Max(end, start + minMinutes));
                start = Math.Min(start, end - minMinutes); // something at 23:55 still gets its height
                return (Item: item, Start: start, End: end);
            })
            .OrderBy(b => b.Start).ThenByDescending(b => b.End - b.Start)
            .ToList();

        var result = new List<Placed<T>>(boxes.Count);
        var cluster = new List<(int Index, int Column)>();
        var columnEnds = new List<double>();
        var clusterEnd = double.MinValue;

        void Close()
        {
            foreach (var (index, column) in cluster)
            {
                var b = boxes[index];
                result.Add(new Placed<T>(b.Item, b.Start / 14.4, (b.End - b.Start) / 14.4, column, columnEnds.Count));
            }
            cluster.Clear();
            columnEnds.Clear();
        }

        for (var i = 0; i < boxes.Count; i++)
        {
            var b = boxes[i];
            if (b.Start >= clusterEnd) Close();
            var column = columnEnds.FindIndex(end => end <= b.Start);
            if (column < 0) { column = columnEnds.Count; columnEnds.Add(b.End); }
            else columnEnds[column] = b.End;
            cluster.Add((i, column));
            clusterEnd = cluster.Count == 1 ? b.End : Math.Max(clusterEnd, b.End);
        }
        Close();
        return result;
    }
}
