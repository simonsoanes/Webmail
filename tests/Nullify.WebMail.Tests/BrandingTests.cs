// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using Nullify.WebMail.Services;

namespace Nullify.WebMail.Tests;

[TestClass]
public class BrandingTests
{
    [TestMethod]
    public void Resolve_NothingSet_IsNullify()
    {
        Assert.AreEqual("Nullify", BrandingService.Resolve(null, null));
        Assert.AreEqual("Nullify", BrandingService.Resolve("  ", ""));
    }

    [TestMethod]
    public void Resolve_InstanceSet_UsedWhenDomainHasNone()
    {
        Assert.AreEqual("Acme", BrandingService.Resolve(null, "Acme"));
        Assert.AreEqual("Acme", BrandingService.Resolve(" ", "Acme"));
    }

    [TestMethod]
    public void Resolve_DomainSet_WinsOverInstance()
    {
        Assert.AreEqual("Example Mail", BrandingService.Resolve("Example Mail", "Acme"));
        Assert.AreEqual("Example Mail", BrandingService.Resolve("Example Mail", null));
    }

    [TestMethod]
    public void Clean_TrimsAndCaps()
    {
        Assert.AreEqual("Acme", BrandingService.Clean("  Acme \n"));
        Assert.AreEqual(BrandingService.MaxLength, BrandingService.Clean(new string('x', 200))!.Length);
        Assert.IsNull(BrandingService.Clean("   "));
    }

    [TestMethod]
    public void DomainKey_IsCaseInsensitive()
    {
        Assert.AreEqual(BrandingService.DomainKey("example.org"), BrandingService.DomainKey("Example.ORG"));
    }

    [TestMethod]
    public async Task Cache_LoadsOnce_UntilInvalidated()
    {
        var cache = new BrandingCache();
        var loads = 0;
        var stored = "Acme";
        Task<string?> Load(string _) { loads++; return Task.FromResult<string?>(stored); }

        Assert.AreEqual("Acme", await cache.GetAsync(BrandingService.InstanceKey, Load));
        Assert.AreEqual("Acme", await cache.GetAsync(BrandingService.InstanceKey, Load));
        Assert.AreEqual(1, loads);

        stored = "Example";
        cache.Invalidate(BrandingService.InstanceKey);
        Assert.AreEqual("Example", await cache.GetAsync(BrandingService.InstanceKey, Load));
        Assert.AreEqual(2, loads);
    }

    [TestMethod]
    public async Task Cache_RemembersUnsetTitles()
    {
        var cache = new BrandingCache();
        var loads = 0;
        Task<string?> Load(string _) { loads++; return Task.FromResult<string?>(null); }

        Assert.IsNull(await cache.GetAsync(BrandingService.DomainKey("example.org"), Load));
        Assert.IsNull(await cache.GetAsync(BrandingService.DomainKey("example.org"), Load));
        Assert.AreEqual(1, loads);
    }

    [TestMethod]
    public async Task Cache_WriteDuringLoad_IsNotCachedStale()
    {
        var cache = new BrandingCache();
        var release = new TaskCompletionSource<string?>();
        var pending = cache.GetAsync(BrandingService.InstanceKey, _ => release.Task);

        cache.Invalidate(BrandingService.InstanceKey);   // an admin saved while the old value was loading
        release.SetResult("Old");
        Assert.AreEqual("Old", await pending);

        Assert.AreEqual("New", await cache.GetAsync(BrandingService.InstanceKey, _ => Task.FromResult<string?>("New")));
    }

    [TestMethod]
    public async Task Cache_OtherSettingWrites_DoNotEvict()
    {
        var cache = new BrandingCache();
        var loads = 0;
        Task<string?> Load(string _) { loads++; return Task.FromResult<string?>("Acme"); }

        await cache.GetAsync(BrandingService.InstanceKey, Load);
        cache.Invalidate("restrict_domains");
        await cache.GetAsync(BrandingService.InstanceKey, Load);
        Assert.AreEqual(1, loads);
    }
}
