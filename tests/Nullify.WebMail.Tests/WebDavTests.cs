// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using Nullify.WebMail.Services;
using Nullify.WebMail.Shared;

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
    public void MoveTarget_PutsTheItemInsideTheDestination()
    {
        var file = new DavItem("a.txt", "/docs/a.txt", false, 1, null, null);
        Assert.AreEqual("/a.txt", WebDavService.MoveTarget(file, "/"));
        Assert.AreEqual("/other/sub/a.txt", WebDavService.MoveTarget(file, "/other/sub/"));

        var folder = new DavItem("Photos", "/docs/Photos/", true, null, null, null);
        Assert.AreEqual("/Archive/Photos", WebDavService.MoveTarget(folder, "/Archive/"));
        Assert.AreEqual("/docs/Photos2/Photos", WebDavService.MoveTarget(folder, "/docs/Photos2/")); // a sibling sharing a prefix is fine
    }

    [TestMethod]
    public void MoveTarget_RefusesMovesThatGoNowhereOrIntoThemselves()
    {
        var folder = new DavItem("Photos", "/docs/Photos/", true, null, null, null);
        Assert.ThrowsExactly<CalDavException>(() => WebDavService.MoveTarget(folder, "/docs/"));
        Assert.ThrowsExactly<CalDavException>(() => WebDavService.MoveTarget(folder, "/docs/Photos/"));
        Assert.ThrowsExactly<CalDavException>(() => WebDavService.MoveTarget(folder, "/docs/Photos/2024/"));
        Assert.ThrowsExactly<CalDavException>(() => WebDavService.MoveTarget(new DavItem("a.txt", "/a.txt", false, 1, null, null), "/"));
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
