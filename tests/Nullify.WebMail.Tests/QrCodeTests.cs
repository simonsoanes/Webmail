// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using System.Security.Cryptography;
using System.Text;
using Nullify.WebMail.Services;

namespace Nullify.WebMail.Tests;

[TestClass]
public class QrCodeTests
{
    // Reference matrices from an independent encoder (segno 1.6.6, error='m', mode='byte',
    // fixed mask, no error boost), as SHA-256 of the rows of 0/1 joined by '\n'. segno appends
    // a whole zero byte when the terminator already ends on a byte boundary, where
    // ISO/IEC 18004 7.4.10 adds none, so the references were made with its padding step
    // corrected to (8 - length % 8) % 8 bits.
    // Together they cover one block, several blocks of two lengths, version bits (v7+) and
    // the 16-bit length field (v10+).
    [TestMethod]
    [DataRow("hello", 0, 1, "52a7aa67e7296ede539d6be86579c7180e3b6d417445712ae8bd314c1818458a")]
    [DataRow("https://mail.example.com/m/approve#Q2xhdWRlIHdhcyBoZXJlIQ", 3, 4, "963067be3febbe60dfb0d9f13a9b6c8079c257d2e24af6a93e85716452d612c4")]
    [DataRow("LONG_URL", 5, 8, "2cfc5f5ee586fb6887d301b612f83ce6d2f6bb4922cf27733cc4b0a6b4d64b5e")]
    [DataRow("SEQ7_300", 6, 13, "58f8e02f8448489d0150bffe6002a85d23561bbcd25331d125a904c0b4b3482e")]
    [DataRow("SEQ11_1200", 2, 29, "89b161cba7c10fbc7e5e020bd44a53e309f55aeab59ebb3f54d22d8a9ee4292b")]
    public void Matrix_MatchesReferenceEncoder(string text, int mask, int version, string sha256)
    {
        text = text switch
        {
            "LONG_URL" => "https://webmail.nullifynetwork.com/webmail/m/approve#" + new string('x', 60) + "-tail/with?query=1&b=2",
            "SEQ7_300" => Sequence(7, 300),
            "SEQ11_1200" => Sequence(11, 1200),
            _ => text,
        };

        var qr = QrCode.Encode(text, mask);

        Assert.AreEqual(version, qr.Version);
        Assert.AreEqual(sha256, Hash(qr));
    }

    [TestMethod]
    public void AutomaticMask_IsAValidChoice()
    {
        var qr = QrCode.Encode("https://mail.example.com/m/approve#Q2xhdWRlIHdhcyBoZXJlIQ");
        Assert.IsTrue(qr.Mask is >= 0 and <= 7);
        Assert.AreEqual(Hash(QrCode.Encode("https://mail.example.com/m/approve#Q2xhdWRlIHdhcyBoZXJlIQ", qr.Mask)), Hash(qr));
    }

    [TestMethod]
    [DataRow(2, new[] { 6, 18 })]
    [DataRow(7, new[] { 6, 22, 38 })]
    [DataRow(10, new[] { 6, 28, 50 })]
    [DataRow(32, new[] { 6, 34, 60, 86, 112, 138 })]
    [DataRow(40, new[] { 6, 30, 58, 86, 114, 142, 170 })]
    public void AlignmentPositions_MatchTheStandardTable(int version, int[] expected) =>
        CollectionAssert.AreEqual(expected, QrCode.AlignmentPositions(version));

    [TestMethod]
    public void Svg_IsSquareWithQuietZone()
    {
        var qr = QrCode.Encode("hello");
        var svg = qr.ToSvg();
        StringAssert.StartsWith(svg, "<svg");
        StringAssert.Contains(svg, "viewBox=\"0 0 29 29\""); // 21 modules + 2×4 border
    }

    [TestMethod]
    public void TooMuchData_Throws() =>
        Assert.ThrowsExactly<ArgumentException>(() => QrCode.Encode(new byte[2400]));

    private static string Sequence(int step, int length) =>
        string.Concat(Enumerable.Range(0, length).Select(i => (char)(33 + i * step % 90)));

    private static string Hash(QrCode qr)
    {
        var rows = new List<string>();
        for (var y = 0; y < qr.Size; y++)
        {
            var row = new StringBuilder();
            for (var x = 0; x < qr.Size; x++) row.Append(qr[x, y] ? '1' : '0');
            rows.Add(row.ToString());
        }
        return Convert.ToHexStringLower(SHA256.HashData(Encoding.ASCII.GetBytes(string.Join('\n', rows))));
    }
}
