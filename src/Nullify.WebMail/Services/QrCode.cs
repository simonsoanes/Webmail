// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using System.Text;

namespace Nullify.WebMail.Services;

/// <summary>
/// Minimal QR code encoder (ISO/IEC 18004): byte mode, error correction level M, versions 1–40.
/// Enough for sign-in URLs; written here because the app takes no third-party packages.
/// </summary>
public sealed class QrCode
{
    public int Version { get; }
    public int Size { get; }
    public int Mask { get; }

    private readonly bool[,] _modules;   // [y, x], true = dark
    private readonly bool[,] _function;  // [y, x], true = finder/timing/alignment/format/version

    public bool this[int x, int y] => _modules[y, x];

    // Level M, indexed by version (index 0 unused).
    private static readonly int[] EccPerBlock =
    [
        -1, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26, 26,
        26, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28,
    ];
    private static readonly int[] BlockCount =
    [
        -1, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14, 16,
        17, 17, 18, 20, 21, 23, 25, 26, 28, 29, 31, 33, 35, 37, 38, 40, 43, 45, 47, 49,
    ];
    private const int EccLevelBits = 0b00; // M

    public static QrCode Encode(string text, int mask = -1) => Encode(Encoding.UTF8.GetBytes(text), mask);

    /// <summary>Encode in the smallest version that fits. <paramref name="mask"/> -1 picks the best mask.</summary>
    public static QrCode Encode(byte[] data, int mask = -1)
    {
        if (mask is < -1 or > 7) throw new ArgumentOutOfRangeException(nameof(mask));
        for (var version = 1; version <= 40; version++)
        {
            var countBits = version <= 9 ? 8 : 16;
            if (4 + countBits + data.Length * 8 <= DataCodewords(version) * 8)
                return new QrCode(version, data, mask);
        }
        throw new ArgumentException("Too much data for a QR code.", nameof(data));
    }

    private QrCode(int version, byte[] data, int mask)
    {
        Version = version;
        Size = version * 4 + 17;
        _modules = new bool[Size, Size];
        _function = new bool[Size, Size];

        DrawFunctionPatterns();
        PlaceCodewords(AddErrorCorrection(DataBytes(data)));

        if (mask < 0)
        {
            var best = int.MaxValue;
            for (var m = 0; m < 8; m++)
            {
                ApplyMask(m);
                DrawFormatBits(m);
                var penalty = Penalty();
                if (penalty < best) { best = penalty; mask = m; }
                ApplyMask(m); // XOR again to undo
            }
        }
        Mask = mask;
        ApplyMask(mask);
        DrawFormatBits(mask);
    }

    // ------------------------------------------------------------------ capacity

    private static int RawDataModules(int version)
    {
        var result = (16 * version + 128) * version + 64;
        if (version >= 2)
        {
            var align = version / 7 + 2;
            result -= (25 * align - 10) * align - 55;
            if (version >= 7) result -= 36;
        }
        return result;
    }

    private static int DataCodewords(int version) =>
        RawDataModules(version) / 8 - EccPerBlock[version] * BlockCount[version];

    /// <summary>Centre coordinates of the alignment patterns on each axis.</summary>
    public static int[] AlignmentPositions(int version)
    {
        if (version == 1) return [];
        var count = version / 7 + 2;
        var step = version == 32 ? 26 : (version * 4 + count * 2 + 1) / (count * 2 - 2) * 2;
        var result = new int[count];
        result[0] = 6;
        for (int i = count - 1, pos = version * 4 + 10; i >= 1; i--, pos -= step)
            result[i] = pos;
        return result;
    }

    // ------------------------------------------------------------------ codewords

    private byte[] DataBytes(byte[] data)
    {
        var capacity = DataCodewords(Version) * 8;
        var bits = new List<bool>(capacity);
        void Append(int value, int length)
        {
            for (var i = length - 1; i >= 0; i--) bits.Add(((value >> i) & 1) != 0);
        }

        Append(0b0100, 4); // byte mode
        Append(data.Length, Version <= 9 ? 8 : 16);
        foreach (var b in data) Append(b, 8);
        Append(0, Math.Min(4, capacity - bits.Count));      // terminator
        Append(0, (8 - bits.Count % 8) % 8);                  // byte align
        for (var pad = 0xEC; bits.Count < capacity; pad ^= 0xEC ^ 0x11) Append(pad, 8);

        var bytes = new byte[bits.Count / 8];
        for (var i = 0; i < bits.Count; i++)
            if (bits[i]) bytes[i >> 3] |= (byte)(0x80 >> (i & 7));
        return bytes;
    }

    private byte[] AddErrorCorrection(byte[] data)
    {
        var blocks = BlockCount[Version];
        var ecc = EccPerBlock[Version];
        var total = RawDataModules(Version) / 8;
        var shortBlocks = blocks - total % blocks;
        var shortLength = total / blocks; // data + ecc, for a short block
        var generator = RsGenerator(ecc);

        var dataBlocks = new List<byte[]>();
        var eccBlocks = new List<byte[]>();
        for (int i = 0, k = 0; i < blocks; i++)
        {
            var length = shortLength - ecc + (i < shortBlocks ? 0 : 1);
            var block = data[k..(k + length)];
            k += length;
            dataBlocks.Add(block);
            eccBlocks.Add(RsRemainder(block, generator));
        }

        var result = new List<byte>(total);
        for (var i = 0; i <= shortLength - ecc; i++)
            foreach (var block in dataBlocks)
                if (i < block.Length) result.Add(block[i]);
        for (var i = 0; i < ecc; i++)
            foreach (var block in eccBlocks)
                result.Add(block[i]);
        return [.. result];
    }

    // Reed–Solomon over GF(2^8) with the QR polynomial x^8 + x^4 + x^3 + x^2 + 1.
    private static byte GfMultiply(byte x, byte y)
    {
        var z = 0;
        for (var i = 7; i >= 0; i--)
        {
            z = (z << 1) ^ ((z >> 7) * 0x11D);
            z ^= ((y >> i) & 1) * x;
        }
        return (byte)z;
    }

    /// <summary>Coefficients of (x - α^0)(x - α^1)…(x - α^(degree-1)), highest power first, leading 1 dropped.</summary>
    private static byte[] RsGenerator(int degree)
    {
        var result = new byte[degree];
        result[degree - 1] = 1;
        byte root = 1;
        for (var i = 0; i < degree; i++)
        {
            for (var j = 0; j < degree; j++)
            {
                result[j] = GfMultiply(result[j], root);
                if (j + 1 < degree) result[j] ^= result[j + 1];
            }
            root = GfMultiply(root, 0x02);
        }
        return result;
    }

    private static byte[] RsRemainder(byte[] data, byte[] generator)
    {
        var result = new byte[generator.Length];
        foreach (var b in data)
        {
            var factor = (byte)(b ^ result[0]);
            Array.Copy(result, 1, result, 0, result.Length - 1);
            result[^1] = 0;
            for (var i = 0; i < result.Length; i++)
                result[i] ^= GfMultiply(generator[i], factor);
        }
        return result;
    }

    // ------------------------------------------------------------------ matrix

    private void SetFunction(int x, int y, bool dark)
    {
        _modules[y, x] = dark;
        _function[y, x] = true;
    }

    private void DrawFunctionPatterns()
    {
        for (var i = 0; i < Size; i++)
        {
            SetFunction(6, i, i % 2 == 0);
            SetFunction(i, 6, i % 2 == 0);
        }

        DrawFinder(3, 3);
        DrawFinder(Size - 4, 3);
        DrawFinder(3, Size - 4);

        var align = AlignmentPositions(Version);
        for (var i = 0; i < align.Length; i++)
            for (var j = 0; j < align.Length; j++)
            {
                // Skip the three corners occupied by finder patterns.
                if ((i == 0 && j == 0) || (i == 0 && j == align.Length - 1) || (i == align.Length - 1 && j == 0)) continue;
                for (var dy = -2; dy <= 2; dy++)
                    for (var dx = -2; dx <= 2; dx++)
                        SetFunction(align[i] + dx, align[j] + dy, Math.Max(Math.Abs(dx), Math.Abs(dy)) != 1);
            }

        DrawFormatBits(0); // reserve the areas; real bits are drawn once the mask is chosen
        DrawVersionBits();
    }

    private void DrawFinder(int cx, int cy)
    {
        for (var dy = -4; dy <= 4; dy++)
            for (var dx = -4; dx <= 4; dx++)
            {
                int x = cx + dx, y = cy + dy;
                if (x < 0 || x >= Size || y < 0 || y >= Size) continue;
                var d = Math.Max(Math.Abs(dx), Math.Abs(dy)); // 4 = separator, 2 = light ring
                SetFunction(x, y, d != 2 && d != 4);
            }
    }

    private void DrawFormatBits(int mask)
    {
        var data = EccLevelBits << 3 | mask;
        var rem = data;
        for (var i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >> 9) * 0x537);
        var bits = (data << 10 | rem) ^ 0x5412;
        bool Bit(int i) => ((bits >> i) & 1) != 0;

        // Copy 1, around the top-left finder.
        for (var i = 0; i <= 5; i++) SetFunction(8, i, Bit(i));
        SetFunction(8, 7, Bit(6));
        SetFunction(8, 8, Bit(7));
        SetFunction(7, 8, Bit(8));
        for (var i = 9; i < 15; i++) SetFunction(14 - i, 8, Bit(i));

        // Copy 2, split between the other two finders.
        for (var i = 0; i < 8; i++) SetFunction(Size - 1 - i, 8, Bit(i));
        for (var i = 8; i < 15; i++) SetFunction(8, Size - 15 + i, Bit(i));
        SetFunction(8, Size - 8, true); // the always-dark module
    }

    private void DrawVersionBits()
    {
        if (Version < 7) return;
        var rem = Version;
        for (var i = 0; i < 12; i++) rem = (rem << 1) ^ ((rem >> 11) * 0x1F25);
        var bits = Version << 12 | rem;
        for (var i = 0; i < 18; i++)
        {
            var dark = ((bits >> i) & 1) != 0;
            int a = Size - 11 + i % 3, b = i / 3;
            SetFunction(a, b, dark);
            SetFunction(b, a, dark);
        }
    }

    private void PlaceCodewords(byte[] codewords)
    {
        var bit = 0;
        var totalBits = codewords.Length * 8;
        // Two-module-wide columns from the right edge, zigzagging up and down; column 6 is the timing pattern.
        for (var right = Size - 1; right >= 1; right -= 2)
        {
            if (right == 6) right = 5;
            for (var v = 0; v < Size; v++)
                for (var j = 0; j < 2; j++)
                {
                    var x = right - j;
                    var upward = ((right + 1) & 2) == 0;
                    var y = upward ? Size - 1 - v : v;
                    if (_function[y, x]) continue;
                    if (bit < totalBits)
                        _modules[y, x] = ((codewords[bit >> 3] >> (7 - (bit & 7))) & 1) != 0;
                    bit++; // remainder bits stay light
                }
        }
    }

    private void ApplyMask(int mask)
    {
        for (var y = 0; y < Size; y++)
            for (var x = 0; x < Size; x++)
            {
                if (_function[y, x]) continue;
                var invert = mask switch
                {
                    0 => (x + y) % 2 == 0,
                    1 => y % 2 == 0,
                    2 => x % 3 == 0,
                    3 => (x + y) % 3 == 0,
                    4 => (x / 3 + y / 2) % 2 == 0,
                    5 => x * y % 2 + x * y % 3 == 0,
                    6 => (x * y % 2 + x * y % 3) % 2 == 0,
                    _ => ((x + y) % 2 + x * y % 3) % 2 == 0,
                };
                if (invert) _modules[y, x] = !_modules[y, x];
            }
    }

    private int Penalty()
    {
        var penalty = 0;

        // Runs of five or more modules of one colour, in rows and columns.
        for (var pass = 0; pass < 2; pass++)
            for (var a = 0; a < Size; a++)
            {
                var run = 0;
                var last = false;
                for (var b = 0; b < Size; b++)
                {
                    var dark = pass == 0 ? _modules[a, b] : _modules[b, a];
                    if (b > 0 && dark == last) run++;
                    else
                    {
                        if (run >= 5) penalty += run - 2;
                        run = 1;
                        last = dark;
                    }
                }
                if (run >= 5) penalty += run - 2;
            }

        // 2×2 blocks of one colour.
        for (var y = 0; y < Size - 1; y++)
            for (var x = 0; x < Size - 1; x++)
            {
                var c = _modules[y, x];
                if (c == _modules[y, x + 1] && c == _modules[y + 1, x] && c == _modules[y + 1, x + 1]) penalty += 3;
            }

        // Finder-like 1:1:3:1:1 patterns with four light modules on one side.
        bool[] p1 = [true, false, true, true, true, false, true, false, false, false, false];
        bool[] p2 = [false, false, false, false, true, false, true, true, true, false, true];
        for (var pass = 0; pass < 2; pass++)
            for (var a = 0; a < Size; a++)
                for (var b = 0; b + 11 <= Size; b++)
                {
                    bool m1 = true, m2 = true;
                    for (var k = 0; k < 11 && (m1 || m2); k++)
                    {
                        var dark = pass == 0 ? _modules[a, b + k] : _modules[b + k, a];
                        m1 &= dark == p1[k];
                        m2 &= dark == p2[k];
                    }
                    if (m1) penalty += 40;
                    if (m2) penalty += 40;
                }

        // Balance of dark and light modules.
        var darkCount = 0;
        foreach (var m in _modules) if (m) darkCount++;
        var total = Size * Size;
        var k5 = (Math.Abs(darkCount * 20 - total * 10) + total - 1) / total - 1;
        penalty += Math.Max(0, k5) * 10;

        return penalty;
    }

    // ------------------------------------------------------------------ output

    /// <summary>Square SVG, dark modules on a white background with a quiet zone (always light, whatever the theme).</summary>
    public string ToSvg(int border = 4)
    {
        var dim = Size + border * 2;
        var sb = new StringBuilder();
        sb.Append($"""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {dim} {dim}" shape-rendering="crispEdges" role="img">""");
        sb.Append($"""<rect width="{dim}" height="{dim}" fill="#fff"/><path fill="#000" d=""").Append('"');
        for (var y = 0; y < Size; y++)
            for (var x = 0; x < Size; x++)
                if (_modules[y, x]) sb.Append($"M{x + border} {y + border}h1v1h-1z");
        sb.Append("\"/></svg>");
        return sb.ToString();
    }
}
