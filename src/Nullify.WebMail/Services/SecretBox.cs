// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using System.Security.Cryptography;
using System.Text;

namespace Nullify.WebMail.Services;

/// <summary>
/// Password-keyed sealing for small secrets (e.g. a CalDAV password) stored in the DB.
/// The key is derived from the user's mail password with PBKDF2-SHA256 and the secret is
/// sealed with AES-256-GCM, so the stored value is useless without that password. When the
/// mail password changes the value no longer opens and must be re-entered — by design.
/// Format: "v1." + base64(salt[16] | nonce[12] | tag[16] | ciphertext).
/// </summary>
public static class SecretBox
{
    private const string Prefix = "v1.";
    private const int Iterations = 210_000; // OWASP guidance for PBKDF2-HMAC-SHA256
    private const int SaltSize = 16, NonceSize = 12, TagSize = 16, KeySize = 32;

    /// <param name="context">Binds the value to its owner/purpose (authenticated, not secret).</param>
    public static string Seal(string plaintext, string password, string context)
    {
        var salt = RandomNumberGenerator.GetBytes(SaltSize);
        var nonce = RandomNumberGenerator.GetBytes(NonceSize);
        var key = DeriveKey(password, salt);
        try
        {
            var pt = Encoding.UTF8.GetBytes(plaintext);
            var ct = new byte[pt.Length];
            var tag = new byte[TagSize];
            using (var aes = new AesGcm(key, TagSize))
                aes.Encrypt(nonce, pt, ct, tag, Encoding.UTF8.GetBytes(context));

            var blob = new byte[SaltSize + NonceSize + TagSize + ct.Length];
            salt.CopyTo(blob, 0);
            nonce.CopyTo(blob, SaltSize);
            tag.CopyTo(blob, SaltSize + NonceSize);
            ct.CopyTo(blob, SaltSize + NonceSize + TagSize);
            return Prefix + Convert.ToBase64String(blob);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    /// <summary>False when the password (or context) is wrong, or the value is malformed.</summary>
    public static bool TryOpen(string? sealedValue, string password, string context, out string plaintext)
    {
        plaintext = "";
        if (string.IsNullOrEmpty(sealedValue) || !sealedValue.StartsWith(Prefix, StringComparison.Ordinal)) return false;

        byte[] blob;
        try { blob = Convert.FromBase64String(sealedValue[Prefix.Length..]); }
        catch (FormatException) { return false; }
        if (blob.Length < SaltSize + NonceSize + TagSize) return false;

        var salt = blob.AsSpan(0, SaltSize);
        var nonce = blob.AsSpan(SaltSize, NonceSize);
        var tag = blob.AsSpan(SaltSize + NonceSize, TagSize);
        var ct = blob.AsSpan(SaltSize + NonceSize + TagSize);
        var key = DeriveKey(password, salt.ToArray());
        try
        {
            var pt = new byte[ct.Length];
            using var aes = new AesGcm(key, TagSize);
            aes.Decrypt(nonce, ct, tag, pt, Encoding.UTF8.GetBytes(context));
            plaintext = Encoding.UTF8.GetString(pt);
            return true;
        }
        catch (AuthenticationTagMismatchException)
        {
            return false;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    private static byte[] DeriveKey(string password, byte[] salt) =>
        Rfc2898DeriveBytes.Pbkdf2(password, salt, Iterations, HashAlgorithmName.SHA256, KeySize);
}
