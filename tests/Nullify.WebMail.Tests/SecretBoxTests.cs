// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using Nullify.WebMail.Services;

namespace Nullify.WebMail.Tests;

[TestClass]
public class SecretBoxTests
{
    private const string Context = "nullify.caldav.v1|user@example.test";

    [TestMethod]
    public void Seal_ThenOpen_WithSameMailPassword_RoundTrips()
    {
        var sealedValue = SecretBox.Seal("dav-secret ✓", "mail-pass-1", Context);
        Assert.IsTrue(SecretBox.TryOpen(sealedValue, "mail-pass-1", Context, out var plain));
        Assert.AreEqual("dav-secret ✓", plain);
    }

    [TestMethod]
    public void Open_AfterMailPasswordChange_Fails()
    {
        var sealedValue = SecretBox.Seal("dav-secret", "old-mail-pass", Context);
        Assert.IsFalse(SecretBox.TryOpen(sealedValue, "new-mail-pass", Context, out _));
    }

    [TestMethod]
    public void Open_ForAnotherUser_Fails()
    {
        // Copying another user's stored value is useless even with the same password.
        var sealedValue = SecretBox.Seal("dav-secret", "shared-pass", Context);
        Assert.IsFalse(SecretBox.TryOpen(sealedValue, "shared-pass", "nullify.caldav.v1|other@example.test", out _));
    }

    [TestMethod]
    public void Seal_IsRandomised_AndDoesNotContainPlaintext()
    {
        var a = SecretBox.Seal("dav-secret", "pw", Context);
        var b = SecretBox.Seal("dav-secret", "pw", Context);
        Assert.AreNotEqual(a, b);
        Assert.DoesNotContain("dav-secret", a);
        Assert.StartsWith("v1.", a);
    }

    [TestMethod]
    public void Open_TamperedOrMalformed_Fails()
    {
        var sealedValue = SecretBox.Seal("dav-secret", "pw", Context);
        var bytes = Convert.FromBase64String(sealedValue[3..]);
        bytes[^1] ^= 1;
        Assert.IsFalse(SecretBox.TryOpen("v1." + Convert.ToBase64String(bytes), "pw", Context, out _));
        Assert.IsFalse(SecretBox.TryOpen("v1.not-base64!", "pw", Context, out _));
        Assert.IsFalse(SecretBox.TryOpen(null, "pw", Context, out _));
    }

    [TestMethod]
    public void NormalizeUrl_AddsSchemeAndRejectsOthers()
    {
        Assert.AreEqual("https://dav.example.org/", CalDavAccountService.NormalizeUrl("dav.example.org"));
        Assert.ThrowsExactly<FormatException>(() => CalDavAccountService.NormalizeUrl("ftp://dav.example.org"));
    }
}
