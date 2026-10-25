// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using System.Buffers.Binary;
using System.Buffers.Text;
using System.Formats.Cbor;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Nullify.WebMail.Services;

/// <summary>A WebAuthn response that doesn't check out. The message is safe to show the user.</summary>
public sealed class WebAuthnException(string message) : Exception(message);

/// <summary>The parts of WebAuthn authenticator data this app uses.</summary>
public sealed record AuthenticatorData(
    byte[] RpIdHash, byte Flags, uint SignCount, byte[]? CredentialId, byte[]? CosePublicKey)
{
    public bool UserPresent => (Flags & 0x01) != 0;
    public bool UserVerified => (Flags & 0x04) != 0;
}

/// <summary>
/// The relying-party side of WebAuthn, enough for passkeys with <c>attestation: 'none'</c>:
/// client data, authenticator data, attestation objects and ES256/RS256 signatures. Built on
/// System.Formats.Cbor and System.Security.Cryptography only.
/// </summary>
public static class WebAuthn
{
    public const int Es256 = -7;
    public const int Rs256 = -257;

    /// <summary>The COSE algorithms offered at registration, most preferred first.</summary>
    public static readonly int[] Algorithms = [Es256, Rs256];

    /// <summary>Check clientDataJSON against the ceremony the server started.</summary>
    public static void VerifyClientData(byte[] clientDataJson, string expectedType, byte[] expectedChallenge, Func<string, bool> originAllowed)
    {
        string? type, challenge, origin;
        bool crossOrigin;
        try
        {
            using var doc = JsonDocument.Parse(clientDataJson);
            var root = doc.RootElement;
            type = root.GetProperty("type").GetString();
            challenge = root.GetProperty("challenge").GetString();
            origin = root.GetProperty("origin").GetString();
            crossOrigin = root.TryGetProperty("crossOrigin", out var co) && co.ValueKind == JsonValueKind.True;
        }
        catch (Exception ex) when (ex is JsonException or KeyNotFoundException or InvalidOperationException)
        {
            throw new WebAuthnException("The passkey's response couldn't be read.");
        }

        if (type != expectedType)
            throw new WebAuthnException("The passkey answered a different request.");
        if (challenge == null || !CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(challenge), Encoding.ASCII.GetBytes(Base64Url.EncodeToString(expectedChallenge))))
            throw new WebAuthnException("The passkey answered a different sign-in request. Try again.");
        if (origin == null || crossOrigin)
            throw new WebAuthnException("The passkey was used from a different site.");
        if (!originAllowed(origin))
            throw new WebAuthnException($"The passkey was used from {origin}, which isn't this site's address.");
    }

    public static AuthenticatorData ParseAuthenticatorData(byte[] data)
    {
        if (data.Length < 37)
            throw new WebAuthnException("The passkey's response is too short.");
        var flags = data[32];
        var signCount = BinaryPrimitives.ReadUInt32BigEndian(data.AsSpan(33, 4));
        byte[]? credentialId = null, publicKey = null;

        if ((flags & 0x40) != 0) // attested credential data: aaguid[16] | idLength[2] | id | COSE key
        {
            if (data.Length < 37 + 18)
                throw new WebAuthnException("The passkey's response is too short.");
            var idLength = BinaryPrimitives.ReadUInt16BigEndian(data.AsSpan(37 + 16, 2));
            var idStart = 37 + 18;
            if (idLength == 0 || idLength > 1023 || data.Length < idStart + idLength + 1)
                throw new WebAuthnException("The passkey's id isn't valid.");
            credentialId = data.AsSpan(idStart, idLength).ToArray();
            try
            {
                var reader = new CborReader(data.AsMemory(idStart + idLength), CborConformanceMode.Lax, allowMultipleRootLevelValues: true);
                publicKey = reader.ReadEncodedValue().ToArray();
            }
            catch (CborContentException)
            {
                throw new WebAuthnException("The passkey's public key couldn't be read.");
            }
        }

        return new AuthenticatorData(data.AsSpan(0, 32).ToArray(), flags, signCount, credentialId, publicKey);
    }

    /// <summary>The authenticator data inside an attestation object. The attestation statement itself is ignored (we ask for none).</summary>
    public static byte[] AuthenticatorDataFromAttestation(byte[] attestationObject)
    {
        try
        {
            var reader = new CborReader(attestationObject, CborConformanceMode.Lax);
            var count = reader.ReadStartMap();
            byte[]? authData = null;
            for (var i = 0; count == null || i < count; i++)
            {
                if (count == null && reader.PeekState() == CborReaderState.EndMap) break;
                var key = reader.ReadTextString();
                if (key == "authData") authData = reader.ReadByteString();
                else reader.SkipValue();
            }
            return authData ?? throw new WebAuthnException("The passkey's registration has no authenticator data.");
        }
        catch (Exception ex) when (ex is CborContentException or InvalidOperationException)
        {
            throw new WebAuthnException("The passkey's registration couldn't be read.");
        }
    }

    /// <summary>Check the authenticator data is for this site and the user was verified (PIN or biometric).</summary>
    public static void VerifyRpAndUser(AuthenticatorData data, string rpId)
    {
        if (!CryptographicOperations.FixedTimeEquals(data.RpIdHash, SHA256.HashData(Encoding.UTF8.GetBytes(rpId))))
            throw new WebAuthnException("The passkey belongs to a different site.");
        if (!data.UserPresent || !data.UserVerified)
            throw new WebAuthnException("The passkey didn't verify you (with a PIN, fingerprint or face).");
    }

    /// <summary>Check a COSE public key is one this app can verify signatures with.</summary>
    public static void ValidatePublicKey(byte[] coseKey)
    {
        using var _ = ImportKey(coseKey);
    }

    /// <summary>Verify an assertion signature: over authenticatorData | SHA-256(clientDataJSON).</summary>
    public static bool VerifySignature(byte[] coseKey, byte[] authenticatorData, byte[] clientDataJson, byte[] signature)
    {
        var signed = new byte[authenticatorData.Length + 32];
        authenticatorData.CopyTo(signed, 0);
        SHA256.HashData(clientDataJson, signed.AsSpan(authenticatorData.Length));

        using var key = ImportKey(coseKey);
        try
        {
            return key switch
            {
                ECDsa ec => ec.VerifyData(signed, signature, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence),
                RSA rsa => rsa.VerifyData(signed, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1),
                _ => false,
            };
        }
        catch (CryptographicException)
        {
            return false; // malformed signature
        }
    }

    private static AsymmetricAlgorithm ImportKey(byte[] coseKey)
    {
        int? kty = null, alg = null, crv = null;
        byte[]? x = null, y = null, n = null; // for RSA keys, x (label -2) is the exponent
        try
        {
            var reader = new CborReader(coseKey, CborConformanceMode.Lax);
            var count = reader.ReadStartMap() ?? throw new WebAuthnException("The passkey's public key isn't supported.");
            for (var i = 0; i < count; i++)
            {
                if (reader.PeekState() is not (CborReaderState.UnsignedInteger or CborReaderState.NegativeInteger))
                {
                    reader.SkipValue();
                    reader.SkipValue();
                    continue;
                }
                var label = reader.ReadInt32();
                switch (label)
                {
                    case 1: kty = reader.ReadInt32(); break;
                    case 3: alg = reader.ReadInt32(); break;
                    // -1 is the curve for EC2 keys and the modulus for RSA keys.
                    case -1 when reader.PeekState() == CborReaderState.ByteString: n = reader.ReadByteString(); break;
                    case -1: crv = reader.ReadInt32(); break;
                    case -2: x = reader.ReadByteString(); break;
                    case -3: y = reader.ReadByteString(); break;
                    default: reader.SkipValue(); break;
                }
            }
        }
        catch (Exception ex) when (ex is CborContentException or InvalidOperationException or OverflowException)
        {
            throw new WebAuthnException("The passkey's public key couldn't be read.");
        }

        try
        {
            if (kty == 2 && alg == Es256 && crv == 1 && x is { Length: 32 } && y is { Length: 32 })
                return ECDsa.Create(new ECParameters { Curve = ECCurve.NamedCurves.nistP256, Q = new ECPoint { X = x, Y = y } });
            if (kty == 3 && alg == Rs256 && n is { Length: >= 256 } && x is { Length: > 0 })
            {
                var rsa = RSA.Create();
                rsa.ImportParameters(new RSAParameters { Modulus = n, Exponent = x });
                return rsa;
            }
        }
        catch (CryptographicException)
        {
            throw new WebAuthnException("The passkey's public key isn't valid.");
        }
        throw new WebAuthnException("This passkey uses a kind of key that isn't supported here.");
    }
}
