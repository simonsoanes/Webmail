// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using Nullify.WebMail.Services;
using Nullify.WebMail.Shared;

namespace Nullify.WebMail.Tests;

[TestClass]
public class SenderAuthTests
{
    // A real delivery through Postfix + SpamAssassin + Dovecot LMTP. Everything from the
    // ingress Received (the first with a public client IP) down was supplied by the sender.
    private const string ServerTop = """
        Received: from tau.nullify.net
        	by tau2 with LMTP
        	id tLo4H8NE3WoXFwEAI7dfHA
        	(envelope-from <notifications@github.com>)
        	for <simon@nullifynetwork.com>; Sat, 24 Oct 2026 23:52:35 +0000
        Authentication-Results: tau.nullify.net;
        	dkim=pass (2048-bit key; unprotected) header.d=github.com header.i=@github.com header.a=rsa-sha256 header.s=pf2026 header.b=QJIC2GaH;
        	dkim-atps=neutral
        Received: from tau.nullify.net (localhost [127.0.0.1])
        	by tau.nullify.net (Postfix) with ESMTP id 48B7F400D3
        	for <simon@nullifynetwork.com>; Sat, 24 Oct 2026 23:52:35 +0000 (UTC)
        Received: by tau.nullify.net (Postfix, from userid 1008)
        	id 2BB42432CB; Sat, 24 Oct 2026 23:52:35 +0000 (UTC)
        X-Spam-Checker-Version: SpamAssassin 4.0.2 (2025-08-27) on tau2
        X-Spam-Status: No, score=-3.0 required=5.0 tests=BAYES_00,DKIM_SIGNED,
        	DKIM_VALID,DKIM_VALID_AU,DMARC_PASS,SPF_PASS autolearn=ham version=4.0.2
        Received-SPF: Pass (mailfrom) identity=mailfrom; client-ip=192.30.252.129; helo=out-30.smtp.github.com; envelope-from=notifications@github.com; receiver=nullifynetwork.com

        """;

    private const string Ingress = """
        Received: from out-30.smtp.github.com (out-30.smtp.github.com [192.30.252.129])
        	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits))
        	(No client certificate requested)
        	by tau.nullify.net (Postfix) with ESMTPS id 1A2B3C4D5E
        	for <simon@nullifynetwork.com>; Sat, 24 Oct 2026 23:52:34 +0000 (UTC)

        """;

    private const string SenderPart = """
        From: GitHub <notifications@github.com>
        To: simon@nullifynetwork.com
        Subject: Hello

        Body
        """;

    private static string Msg(params string[] blocks) =>
        string.Concat(blocks.Select(b => b.Replace("\r\n", "\n").TrimEnd('\n') + "\n")).Replace("\n", "\r\n");

    private static string WithFrom(string from) => SenderPart.Replace("From: GitHub <notifications@github.com>", from);

    [TestMethod]
    public void RealDelivery_IsVerifiedForTheFromDomain()
    {
        var info = SenderAuth.Analyse(Msg(ServerTop, Ingress, SenderPart));
        Assert.IsNotNull(info);
        Assert.AreEqual(SenderAuthVerdict.Verified, info.Verdict);
        Assert.AreEqual("github.com", info.FromDomain);
        Assert.IsTrue(info.Checks.Any(c => c is { Method: "dkim", Result: "pass", Domain: "github.com", Aligned: true }));
        Assert.IsTrue(info.Checks.Any(c => c is { Method: "spf", Result: "pass", Domain: "github.com", Aligned: true }));
        Assert.IsEmpty(info.Problems);
    }

    [TestMethod]
    public void NoIngressHop_ShowsNothing()
    {
        // The header block alone (no hop from the internet) can't be placed relative to the sender's content.
        Assert.IsNull(SenderAuth.Analyse(Msg(ServerTop, SenderPart)));
    }

    [TestMethod]
    public void ServerThatRecordsNoResults_ShowsNothing()
    {
        Assert.IsNull(SenderAuth.Analyse(Msg(Ingress, SenderPart)));
    }

    [TestMethod]
    public void LocalMailWithoutAPublicHop_ShowsNothing()
    {
        var local = """
            Authentication-Results: tau.nullify.net; dkim=none
            Received: from tau.nullify.net (localhost [127.0.0.1]) by tau.nullify.net (Postfix) with ESMTP id 1
            Received: from printer (printer.lan [192.168.1.20]) by tau.nullify.net (Postfix) with SMTP id 2
            """;
        Assert.IsNull(SenderAuth.Analyse(Msg(local, SenderPart)));
    }

    [TestMethod]
    public void AuthenticatedSubmission_ShowsNothing()
    {
        var submission = """
            Received-SPF: None (mailfrom) identity=mailfrom; envelope-from=simon@nullifynetwork.com
            Received: from [10.0.0.2] (host.example [203.0.113.9]) by tau.nullify.net (Postfix) with ESMTPSA id 9
            """;
        Assert.IsNull(SenderAuth.Analyse(Msg(submission, WithFrom("From: simon@nullifynetwork.com"))));
    }

    [TestMethod]
    public void ForgedPassBelowIngress_IsIgnored()
    {
        // The sender wrote results in our server's name, plus a fake Received with a public IP.
        var forged = """
            Authentication-Results: tau.nullify.net; dkim=pass header.d=paypal.com; spf=pass smtp.mailfrom=paypal.com; dmarc=pass header.from=paypal.com
            Received-SPF: Pass identity=mailfrom; envelope-from=service@paypal.com
            Received: from mx.paypal.com ([64.4.250.1]) by tau.nullify.net (Postfix) with ESMTPS id 7
            """;
        var info = SenderAuth.Analyse(Msg(Ingress, forged, WithFrom("From: PayPal <service@paypal.com>")));
        Assert.IsNull(info, "Fake results must never produce an indicator, let alone a verified one");
    }

    [TestMethod]
    public void ForgedPassBelowIngress_WithRealResults_IsFlagged()
    {
        var real = """
            Authentication-Results: tau.nullify.net; dkim=none; spf=softfail smtp.mailfrom=evil.example
            """;
        var forged = """
            Authentication-Results: tau.nullify.net; dkim=pass header.d=paypal.com; dmarc=pass header.from=paypal.com
            """;
        var info = SenderAuth.Analyse(Msg(real, Ingress, forged, WithFrom("From: PayPal <service@paypal.com>")));
        Assert.IsNotNull(info);
        Assert.AreEqual(SenderAuthVerdict.NotVerified, info.Verdict);
        Assert.IsTrue(info.Problems.Any(p => p.Contains("forgery")));
        Assert.IsFalse(info.Checks.Any(c => c.Result == "pass"), "Results below the ingress hop must not be counted");
    }

    [TestMethod]
    public void FailingChecks_AreNotVerified()
    {
        var top = """
            Authentication-Results: tau.nullify.net; dkim=fail (bad signature) header.d=github.com; spf=softfail smtp.mailfrom=github.com
            """;
        var info = SenderAuth.Analyse(Msg(top, Ingress, SenderPart));
        Assert.AreEqual(SenderAuthVerdict.NotVerified, info?.Verdict);
        Assert.IsTrue(info!.Problems.Any(p => p.Contains("Neither DKIM nor SPF passed for github.com")));
    }

    [TestMethod]
    public void PassForAnotherDomain_DoesNotVouchForTheFromAddress()
    {
        var top = """
            Authentication-Results: tau.nullify.net; dkim=pass header.d=evil.example; spf=pass smtp.mailfrom=bounce@evil.example
            """;
        var info = SenderAuth.Analyse(Msg(top, Ingress, WithFrom("From: \"GitHub\" <notifications@github.com>")));
        Assert.AreEqual(SenderAuthVerdict.NotVerified, info?.Verdict);
        Assert.IsTrue(info!.Problems.Any(p => p.Contains("only verified for evil.example, not for github.com")));
    }

    [TestMethod]
    public void DisplayNameCannotSupplyTheDomain()
    {
        var top = "Authentication-Results: tau.nullify.net; dkim=pass header.d=evil.example";
        var info = SenderAuth.Analyse(Msg(top, Ingress, WithFrom("From: \"security@github.com\" <x@evil.example>")));
        Assert.AreEqual(SenderAuthVerdict.Verified, info?.Verdict);
        Assert.AreEqual("evil.example", info!.FromDomain, "The verified domain is the real address, shown to the user");
    }

    [TestMethod]
    public void LookalikeDomains_AreNotAligned()
    {
        foreach (var d in new[] { "github.com.evil.example", "hub.com", "ithub.com", "com" })
        {
            var top = $"Authentication-Results: tau.nullify.net; dkim=pass header.d={d}";
            Assert.AreEqual(SenderAuthVerdict.NotVerified, SenderAuth.Analyse(Msg(top, Ingress, SenderPart))?.Verdict, d);
        }
    }

    [TestMethod]
    public void SubdomainSignature_IsAligned()
    {
        var top = "Authentication-Results: tau.nullify.net; dkim=pass header.d=mail.github.com";
        Assert.AreEqual(SenderAuthVerdict.Verified, SenderAuth.Analyse(Msg(top, Ingress, SenderPart))?.Verdict);
    }

    [TestMethod]
    public void TwoFromHeaders_AreNotVerified()
    {
        var info = SenderAuth.Analyse(Msg(ServerTop, Ingress, "From: PayPal <service@paypal.com>", SenderPart));
        Assert.AreEqual(SenderAuthVerdict.NotVerified, info?.Verdict);
        Assert.IsTrue(info!.Problems.Any(p => p.Contains("more than one From")));
    }

    [TestMethod]
    public void DmarcFail_OverridesAPass()
    {
        var top = "Authentication-Results: tau.nullify.net; dkim=pass header.d=github.com; dmarc=fail header.from=github.com";
        Assert.AreEqual(SenderAuthVerdict.NotVerified, SenderAuth.Analyse(Msg(top, Ingress, SenderPart))?.Verdict);
    }

    [TestMethod]
    public void ResultsFromAnotherAuthServId_AreIgnored()
    {
        // Above the ingress hop, but naming a server that isn't one of ours.
        var top = "Authentication-Results: mx.google.com; dkim=pass header.d=github.com";
        Assert.IsNull(SenderAuth.Analyse(Msg(top, Ingress, SenderPart)));
    }

    [TestMethod]
    public void ConfiguredAuthServId_IsTheOnlyOneTrusted()
    {
        var top = """
            Authentication-Results: other.example; dkim=pass header.d=github.com
            Authentication-Results: Filter.Nullify.Net; dkim=fail header.d=github.com
            """;
        var info = SenderAuth.Analyse(Msg(top, Ingress, SenderPart), ["filter.nullify.net"]);
        Assert.AreEqual(SenderAuthVerdict.NotVerified, info?.Verdict);
        Assert.HasCount(1, info!.Checks);
        Assert.IsNull(SenderAuth.Analyse(Msg(top, Ingress, SenderPart), ["nothing.example"]));
    }

    [TestMethod]
    public void HeloOnlySpf_DoesNotVouchForTheSender()
    {
        var top = "Received-SPF: Pass (helo) identity=helo; client-ip=192.30.252.129; helo=github.com; envelope-from=x@evil.example";
        var info = SenderAuth.Analyse(Msg(top, Ingress, SenderPart));
        Assert.AreEqual(SenderAuthVerdict.NotVerified, info?.Verdict);
    }

    [TestMethod]
    public void Ipv6Ingress_IsRecognised()
    {
        var ingress6 = "Received: from mail.github.com (mail.github.com [IPv6:2606:50c0:8000::153]) by tau.nullify.net (Postfix) with ESMTPS id 5";
        var top = "Authentication-Results: tau.nullify.net; dkim=pass header.d=github.com";
        Assert.AreEqual(SenderAuthVerdict.Verified, SenderAuth.Analyse(Msg(top, ingress6, SenderPart))?.Verdict);
    }

    [TestMethod]
    public void KeywordsInsideComments_DoNotConfuseTheParser()
    {
        // "by" and ';' inside comments, and a HELO that is itself an IP literal of a private host.
        var ingress = "Received: from 10.1.1.1 (unknown [198.51.100.7]; claims (to be) by mx.paypal.com) by tau.nullify.net (Postfix) with ESMTP id 3";
        var top = "Authentication-Results: tau.nullify.net; dkim=pass header.d=github.com";
        Assert.AreEqual(SenderAuthVerdict.Verified, SenderAuth.Analyse(Msg(top, ingress, SenderPart))?.Verdict);
    }
}
