using System.Security.Cryptography;
using System.Text;
using Compliance.Core;

var now = DateTimeOffset.Parse("2026-10-13T12:00:00Z");
var p = new PolicyDocument
{
    RequiredModules = ["installed", "proxy", "users"],
    Products = [new("cursor", "Cursor", "ai", [], ["cursor.exe"], [], [])],
    IssuedAt = now.AddDays(-1),
    ExpiresAt = now.AddDays(1),
};
var clean = new ScanSnapshot
{
    DeviceId = "dev1",
    PolicyVersion = 1,
    CollectedAt = now,
    Modules =
    [
        new("installed", "machine", "Complete", now),
        new("proxy", "machine", "Complete", now),
        new("users", "machine", "Complete", now),
    ],
};
var violation = new Evidence(
    "cursor",
    "Cursor",
    EvidenceKind.Installation,
    "Cursor",
    "registry",
    "Cursor installation",
    "S-1-5-21-123"
);
int failed = 0,
    passed = 0;
void Test(string name, Action run)
{
    try
    {
        run();
        passed++;
        Console.WriteLine($"PASS {name}");
    }
    catch (Exception e)
    {
        failed++;
        Console.WriteLine($"FAIL {name}: {e.Message}");
    }
}
void Eq<T>(T expected, T actual)
{
    if (!EqualityComparer<T>.Default.Equals(expected, actual))
        throw new Exception($"expected {expected}, got {actual}");
}
void Yes(bool v)
{
    if (!v)
        throw new Exception("assertion failed");
}
void Throws(Action f)
{
    try
    {
        f();
    }
    catch (ArgumentException)
    {
        return;
    }
    catch (CryptographicException)
    {
        return;
    }
    throw new Exception("should reject");
}
Test(
    "complete clean audit is scoped PASS without claiming enforcement",
    () =>
    {
        var r = ReportEngine.Evaluate(p, clean, now);
        Eq(Verdict.PASS, r.Verdict);
        Yes(r.ProtectionStatus.Contains("审计"));
    }
);
Test(
    "missing mandatory module cannot be PASS",
    () => Eq(Verdict.UNKNOWN, ReportEngine.Evaluate(p, clean with { Modules = clean.Modules[..2] }, now).Verdict)
);
Test(
    "offline user hive failure cannot be hidden by machine success",
    () =>
        Eq(
            Verdict.UNKNOWN,
            ReportEngine
                .Evaluate(
                    p,
                    clean with
                    {
                        Modules =
                        [
                            .. clean.Modules,
                            new("proxy", "S-1-5-21-123", "Unavailable", now, "Hive not loaded"),
                        ],
                    },
                    now
                )
                .Verdict
        )
);
Test(
    "inventory stale cannot be refreshed by recent proxy scan",
    () =>
        Eq(
            Verdict.UNKNOWN,
            ReportEngine
                .Evaluate(
                    p,
                    clean with
                    {
                        Modules = [new("installed", "machine", "Complete", now.AddHours(-3)), .. clean.Modules[1..]],
                    },
                    now
                )
                .Verdict
        )
);
Test(
    "old confirmed evidence no longer asserts current FAIL",
    () =>
        Eq(
            Verdict.UNKNOWN,
            ReportEngine.Evaluate(p, clean with { CollectedAt = now.AddHours(-3), Evidence = [violation] }, now).Verdict
        )
);
Test(
    "confirmed violation wins over missing coverage",
    () => Eq(Verdict.FAIL, ReportEngine.Evaluate(p, clean with { Evidence = [violation], Modules = [] }, now).Verdict)
);
Test(
    "multiple PID evidence is one violated product per user",
    () =>
    {
        var r = ReportEngine.Evaluate(
            p,
            clean with
            {
                Evidence = [violation, violation with { Kind = EvidenceKind.Process, ObjectKey = "pid12" }],
            },
            now
        );
        Eq(1, r.ViolationCount);
        Eq(2, r.EvidenceCount);
    }
);
Test(
    "one product with installation and process evidence has one readable reason",
    () =>
    {
        var r = ReportEngine.Evaluate(
            p,
            clean with
            {
                Evidence =
                [
                    violation,
                    violation with
                    {
                        Kind = EvidenceKind.Process,
                        ObjectKey = "pid12",
                        Summary = "Running PID 12",
                    },
                ],
            },
            now
        );
        Eq(1, r.Reasons.Length);
        Yes(r.Reasons[0].Contains("Cursor") && r.Reasons[0].Contains("共 2 条证据"));
        Eq(2, r.EvidenceCount);
    }
);
Test(
    "unknown filename port and TUN clues never confirm violation",
    () =>
        Eq(
            Verdict.PASS,
            ReportEngine
                .Evaluate(
                    p,
                    clean with
                    {
                        Evidence = [violation with { Kind = EvidenceKind.Clue, Confirmed = false }],
                    },
                    now
                )
                .Verdict
        )
);
Test(
    "confirmed enabled proxy rejected even without installed software",
    () =>
        Eq(
            Verdict.FAIL,
            ReportEngine
                .Evaluate(
                    p,
                    clean with
                    {
                        Evidence = [new("system-proxy", "Proxy", EvidenceKind.Proxy, "HKU", "WinINET", "Enabled")],
                    },
                    now
                )
                .Verdict
        )
);
Test(
    "blocked attempt is not successful use or installation violation",
    () =>
        Eq(
            Verdict.PASS,
            ReportEngine
                .Evaluate(p, clean with { Evidence = [violation with { Kind = EvidenceKind.BlockedAttempt }] }, now)
                .Verdict
        )
);
Test(
    "enforcement missing network capability cannot pass",
    () =>
        Eq(
            Verdict.UNKNOWN,
            ReportEngine
                .Evaluate(
                    p with
                    {
                        Mode = "Enforce",
                    },
                    clean with
                    {
                        Controls =
                        [
                            new("edge", 1, "Applied", "readback", true),
                            new("application", 1, "Applied", "loaded", true),
                        ],
                    },
                    now
                )
                .Verdict
        )
);
Test(
    "readback without actual verification cannot satisfy protection",
    () =>
        Eq(
            Verdict.UNKNOWN,
            ReportEngine
                .Evaluate(
                    p with
                    {
                        Mode = "Enforce",
                        RequiredControls = ["edge"],
                    },
                    clean with
                    {
                        Controls = [new("edge", 1, "Applied", "readback", false)],
                    },
                    now
                )
                .Verdict
        )
);
Test(
    "all required verified controls permit enforcement PASS",
    () =>
        Eq(
            Verdict.PASS,
            ReportEngine
                .Evaluate(
                    p with
                    {
                        Mode = "Enforce",
                        RequiredControls = ["edge"],
                    },
                    clean with
                    {
                        Controls = [new("edge", 1, "Verified", "verified canary", true)],
                    },
                    now
                )
                .Verdict
        )
);
Test(
    "policy mismatch cannot pass",
    () => Eq(Verdict.UNKNOWN, ReportEngine.Evaluate(p, clean with { PolicyVersion = 0 }, now).Verdict)
);
Test(
    "disabled ban is invalid policy rather than silent pass",
    () => Eq(Verdict.UNKNOWN, ReportEngine.Evaluate(p with { DenyInstalled = false }, clean, now).Verdict)
);
Test(
    "simulated report cannot be real device PASS",
    () => Eq(Verdict.UNKNOWN, ReportEngine.Evaluate(p, clean with { Simulated = true }, now).Verdict)
);
Test(
    "future data cannot assert current PASS",
    () => Eq(Verdict.UNKNOWN, ReportEngine.Evaluate(p, clean with { CollectedAt = now.AddMinutes(10) }, now).Verdict)
);
Test(
    "signed policy validates and preserves version",
    () =>
    {
        using var k = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var signed = PolicyCrypto.Sign(p, k, "key1");
        Eq(1L, PolicyCrypto.Verify(signed, k.ExportSubjectPublicKeyInfoPem(), "dev1", 1, now).Version);
    }
);
Test(
    "tampering signed policy rejected",
    () =>
    {
        using var k = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var signed = PolicyCrypto.Sign(p, k, "key1");
        Throws(() =>
            PolicyCrypto.Verify(
                signed with
                {
                    Payload = signed.Payload.Replace("Audit", "Enforce"),
                },
                k.ExportSubjectPublicKeyInfoPem(),
                "dev1",
                1,
                now
            )
        );
    }
);
Test(
    "policy downgrade refused",
    () =>
    {
        using var k = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var signed = PolicyCrypto.Sign(p, k, "key1");
        Throws(() => PolicyCrypto.Verify(signed, k.ExportSubjectPublicKeyInfoPem(), "dev1", 2, now));
    }
);
Test(
    "policy intended for another device rejected",
    () =>
    {
        using var k = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var signed = PolicyCrypto.Sign(p with { TargetDeviceIds = ["other"] }, k, "key1");
        Throws(() => PolicyCrypto.Verify(signed, k.ExportSubjectPublicKeyInfoPem(), "dev1", 0, now));
    }
);
Test(
    "expired policy refused without removing cached OS controls",
    () =>
    {
        using var k = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var signed = PolicyCrypto.Sign(p with { ExpiresAt = now.AddDays(-1) }, k, "key1");
        Throws(() => PolicyCrypto.Verify(signed, k.ExportSubjectPublicKeyInfoPem(), "dev1", 0, now));
    }
);
Test(
    "request signature binds path method nonce and actual body",
    () =>
    {
        using var k = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var body = Encoding.UTF8.GetBytes("{\"events\":[]}");
        var sig = RequestAuthentication.Sign(k, "POST", "/api/agent/events", "123", "n1", body);
        var pub = k.ExportSubjectPublicKeyInfoPem();
        Yes(RequestAuthentication.Verify(pub, "POST", "/api/agent/events", "123", "n1", body, sig));
        Yes(!RequestAuthentication.Verify(pub, "GET", "/api/agent/policy", "123", "n1", body, sig));
        Yes(!RequestAuthentication.Verify(pub, "POST", "/api/agent/events", "123", "n2", body, sig));
        Yes(
            !RequestAuthentication.Verify(
                pub,
                "POST",
                "/api/agent/events",
                "123",
                "n1",
                Encoding.UTF8.GetBytes("{}"),
                sig
            )
        );
    }
);
Test(
    "domain matches hostname boundary only",
    () =>
    {
        Yes(DomainRules.Matches("api.example.com", "example.com"));
        Yes(DomainRules.Matches("EXAMPLE.COM.", "example.com"));
        Yes(!DomainRules.Matches("example.com.evil.test", "example.com"));
        Yes(!DomainRules.Matches("evil-example.com", "example.com"));
    }
);
Test(
    "invalid domain path and wildcard rejected",
    () =>
    {
        Throws(() => DomainRules.Normalize("https://example.com/path"));
        Throws(() => DomainRules.Normalize("*.example.com"));
        Throws(() => DomainRules.Normalize("127.0.0.1"));
        Throws(() => DomainRules.Normalize("localhost"));
    }
);
Test(
    "Edge policy rejects rather than truncates over limit",
    () => Throws(() => DomainRules.CompileEdge(Enumerable.Range(0, 1001).Select(x => $"host{x}.example.com")))
);
Test(
    "report redacts credentials and URL query in JSON too",
    () =>
    {
        var r = ReportEngine.Evaluate(
            p,
            clean with
            {
                Evidence =
                [
                    violation with
                    {
                        Summary = "https://alice:pw@proxy.example.com/pac?token=secret Authorization: Bearer abc123",
                        Source = "TOKEN=secret",
                    },
                ],
            },
            now
        );
        var json = Wire.Serialize(r);
        Yes(!json.Contains("pw@") && !json.Contains("secret") && !json.Contains("abc123"));
    }
);
Test(
    "fixed report has nine sections and includes missing coverage",
    () =>
    {
        var r = ReportEngine.Evaluate(p, clean with { Modules = [] }, now);
        var md = ReportRenderer.Markdown(r);
        Eq(9, md.Split('\n').Count(x => x.StartsWith("## ")));
        Yes(md.Contains("无法判断") && md.Contains("缺少必需检查项：已安装软件") && md.Contains("只检查，不拦截"));
    }
);
Test(
    "report explains raw evidence count and translates coverage status",
    () =>
    {
        var r = ReportEngine.Evaluate(
            p,
            clean with
            {
                Evidence = [violation, violation with { Kind = EvidenceKind.Process, ObjectKey = "pid12" }],
                Modules =
                [
                    .. clean.Modules,
                    new("extensions", "S-1-5-21-123", "Error", now, "JsonException; inspection incomplete"),
                ],
            },
            now
        );
        var md = ReportRenderer.Markdown(r);
        Yes(md.Contains("合并计为一个违规对象") && md.Contains("编辑器扩展") && md.Contains("读取失败"));
    }
);
Test(
    "Markdown evidence cannot inject hidden headings",
    () =>
    {
        var r = ReportEngine.Evaluate(
            p,
            clean with
            {
                Evidence = [violation with { Summary = "oops\n## fake <script>alert(1)</script>" }],
            },
            now
        );
        var md = ReportRenderer.Markdown(r);
        Eq(9, md.Split('\n').Count(x => x.StartsWith("## ")));
        Yes(!md.Contains("<script>"));
    }
);
Test(
    "old inventory evidence cannot become fresh through new light scan",
    () =>
        Eq(
            Verdict.UNKNOWN,
            ReportEngine
                .Evaluate(
                    p,
                    clean with
                    {
                        Evidence = [violation],
                        Modules = [new("installed", "machine", "Complete", now.AddHours(-3)), .. clean.Modules[1..]],
                    },
                    now
                )
                .Verdict
        )
);
Test(
    "unknown confirmed product is unresolved rather than PASS",
    () =>
        Eq(
            Verdict.UNKNOWN,
            ReportEngine.Evaluate(p, clean with { Evidence = [violation with { ProductId = "unlisted" }] }, now).Verdict
        )
);
Test(
    "explicit aged evidence cannot become current even with fresh module metadata",
    () =>
        Eq(
            Verdict.UNKNOWN,
            ReportEngine
                .Evaluate(p, clean with { Evidence = [violation with { CollectedAt = now.AddHours(-3) }] }, now)
                .Verdict
        )
);
Test(
    "approved network adapters must be short explicit names",
    () =>
    {
        PolicyCrypto.Validate(p with { ApprovedNetworkAdapters = ["aTrust", "Corporate VPN"] });
        Throws(() => PolicyCrypto.Validate(p with { ApprovedNetworkAdapters = [""] }));
        Throws(() => PolicyCrypto.Validate(p with { ApprovedNetworkAdapters = ["a"] }));
        Throws(() => PolicyCrypto.Validate(p with { ApprovedNetworkAdapters = null! }));
    }
);
Console.WriteLine($"Core tests: {passed} passed, {failed} failed");
return failed == 0 ? 0 : 1;
