// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using System.Text;
using System.Text.RegularExpressions;

namespace Nullify.WebMail.Services;

/// <summary>ASCII armor (RFC 9580 section 6) for moving keys between vCards, files and the browser engine.</summary>
public static partial class OpenPgpArmor
{
    public static string Armor(string type, byte[] data)
    {
        var sb = new StringBuilder();
        sb.Append("-----BEGIN ").Append(type).Append("-----\r\n\r\n");
        var b64 = Convert.ToBase64String(data);
        for (var i = 0; i < b64.Length; i += 64) sb.Append(b64, i, Math.Min(64, b64.Length - i)).Append("\r\n");
        var crc = Crc24(data);
        sb.Append('=').Append(Convert.ToBase64String([(byte)(crc >> 16), (byte)(crc >> 8), (byte)crc])).Append("\r\n");
        sb.Append("-----END ").Append(type).Append("-----\r\n");
        return sb.ToString();
    }

    /// <summary>The binary packets inside the first armored block, or null.</summary>
    public static byte[]? Dearmor(string text)
    {
        var m = BlockRx().Match(text);
        if (!m.Success) return null;
        var lines = m.Groups[2].Value.Split('\n').Select(l => l.Trim()).ToList();
        var start = lines.FindIndex(l => l.Length == 0); // body follows the (optional) headers
        var body = new StringBuilder();
        foreach (var line in lines.Skip(start < 0 ? 0 : start + 1))
        {
            if (line.Length == 0 || (line.StartsWith('=') && line.Length == 5)) continue;
            body.Append(line);
        }
        try { return Convert.FromBase64String(body.ToString()); }
        catch (FormatException) { return null; }
    }

    private static int Crc24(byte[] data)
    {
        var crc = 0xB704CE;
        foreach (var b in data)
        {
            crc ^= b << 16;
            for (var i = 0; i < 8; i++)
            {
                crc <<= 1;
                if ((crc & 0x1000000) != 0) crc ^= 0x1864CFB;
            }
        }
        return crc & 0xFFFFFF;
    }

    [GeneratedRegex(@"-----BEGIN ([A-Z0-9 ]+)-----\r?\n([\s\S]*?)-----END \1-----")]
    private static partial Regex BlockRx();
}
