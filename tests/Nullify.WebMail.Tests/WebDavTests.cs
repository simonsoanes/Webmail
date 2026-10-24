// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using Nullify.WebMail.Services;

namespace Nullify.WebMail.Tests;

[TestClass]
public class WebDavTests
{
    [TestMethod]
    public void NormalizePath_CollapsesSlashes_AndKeepsFolderMarker()
    {
        Assert.AreEqual("/", WebDavService.NormalizePath(""));
        Assert.AreEqual("/a/b/", WebDavService.NormalizePath("a//b/"));
        Assert.AreEqual("/a/b.txt", WebDavService.NormalizePath(@"\a\b.txt"));
    }

    [TestMethod]
    public void NormalizePath_RejectsClimbingAboveTheRoot()
    {
        Assert.ThrowsExactly<CalDavException>(() => WebDavService.NormalizePath("/a/../../etc/passwd"));
        Assert.ThrowsExactly<CalDavException>(() => WebDavService.NormalizePath("./x"));
    }

    [TestMethod]
    public void ExpandPlaceholders_FillsPerUserTemplate_EvenAfterUrlNormalisation()
    {
        var template = new Uri(CalDavAccountService.NormalizeUrl("https://cloud.example.org/remote.php/dav/files/{username}/"));
        var expanded = WebDavService.ExpandPlaceholders(template, "ada@example.org", "ada@example.org");
        Assert.AreEqual("https://cloud.example.org/remote.php/dav/files/ada%40example.org/", expanded.AbsoluteUri);

        var byEmail = WebDavService.ExpandPlaceholders(new Uri("https://dav.example.org/{email}/"), "ada", "ada@example.org");
        Assert.AreEqual("https://dav.example.org/ada%40example.org/", byEmail.AbsoluteUri);
    }
}
