// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

namespace Nullify.WebMail.Services;

/// <summary>Display helpers for OpenPGP values.</summary>
public static class PgpFormat
{
    /// <summary>"ABCD 1234 ..." in groups of four, the way people read fingerprints aloud.</summary>
    public static string Fingerprint(string? fpr)
    {
        if (string.IsNullOrEmpty(fpr)) return "";
        var hex = fpr.Replace(" ", "").ToUpperInvariant();
        var groups = Enumerable.Range(0, (hex.Length + 3) / 4).Select(i => hex.Substring(i * 4, Math.Min(4, hex.Length - i * 4)));
        return string.Join(" ", groups);
    }

    public static string SignatureLabel(PgpSignatureResult s) => s.Status switch
    {
        "good" => $"Signed by {s.Signer ?? KeyLabel(s)}",
        "weak-hash" => $"Signed by {s.Signer ?? KeyLabel(s)} (with the outdated SHA-1 hash)",
        "bad" => "The signature doesn't match — the message may have been altered",
        "revoked-key" => $"Signed with a revoked key ({s.Signer ?? KeyLabel(s)})",
        "expired-key" => $"Signed with an expired key ({s.Signer ?? KeyLabel(s)})",
        "invalid-key" => $"Signed with a key that isn't valid ({s.Signer ?? KeyLabel(s)})",
        "unsupported" => "Signed in a format this app can't check",
        _ => $"Signed by key {KeyLabel(s)}, which you don't have — add it to the sender's contact to check it",
    };

    private static string KeyLabel(PgpSignatureResult s) => Fingerprint(s.Fingerprint ?? s.KeyId ?? "unknown");
}
