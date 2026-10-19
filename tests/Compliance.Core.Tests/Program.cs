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
    "user accounts the policy does not list do not limit the verdict, unless they could not be listed at all",
    () =>
    {
        var processesOnly = p with { RequiredModules = ["processes"] };
        var hiveNotLoaded = clean with
        {
            Modules =
            [
                new("processes", "machine", "Complete", now),
                new("users", "machine", "Complete", now),
                new("users", "S-1-5-21-123", "Unknown", now, "Hive not loaded"),
            ],
        };
        Eq(Verdict.PASS, ReportEngine.Evaluate(processesOnly, hiveNotLoaded, now).Verdict);
        Eq(
            Verdict.UNKNOWN,
            ReportEngine
                .Evaluate(processesOnly with { RequiredModules = ["processes", "users"] }, hiveNotLoaded, now)
                .Verdict
        );
        var unlisted = clean with
        {
            Modules =
            [
                new("processes", "machine", "Complete", now),
                new("users", "machine", "Error", now, "ProfileList unreadable"),
            ],
        };
        Eq(Verdict.UNKNOWN, ReportEngine.Evaluate(processesOnly, unlisted, now).Verdict);
    }
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
    "every full-check module stays fresh between full checks, while quick checks keep running",
    () =>
    {
        // Quick check every 10 minutes, full check every 60: a quick check 53 minutes after the last full one.
        var policy = p with
        {
            RequiredModules = [.. PolicyDocument.AllModules],
            LightweightFreshMinutes = 20,
            InventoryFreshMinutes = 120,
        };
        var snapshot = clean with
        {
            Modules =
            [
                .. PolicyDocument.AllModules.Select(m => new ModuleResult(
                    m,
                    "machine",
                    "Complete",
                    PolicyDocument.InventoryModules.Contains(m) ? now.AddMinutes(-53) : now
                )),
            ],
        };
        var r = ReportEngine.Evaluate(policy, snapshot, now);
        Eq(Verdict.PASS, r.Verdict);
        Eq(Verdict.UNKNOWN, ReportEngine.Evaluate(policy with { InventoryFreshMinutes = 40 }, snapshot, now).Verdict);
    }
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
    "enforcement needs every required measure in effect",
    () =>
        Eq(
            Verdict.UNKNOWN,
            ReportEngine
                .Evaluate(
                    p with
                    {
                        Mode = "Enforce",
                        RequiredControls = ["process", "browser"],
                    },
                    clean with
                    {
                        Controls = [new("browser", 1, "Applied", "readback", true)],
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
                        RequiredControls = ["browser"],
                    },
                    clean with
                    {
                        Controls = [new("browser", 1, "Applied", "readback", false)],
                    },
                    now
                )
                .Verdict
        )
);
Test(
    "a measure that is only ready does not count while enforcing",
    () =>
        Eq(
            Verdict.UNKNOWN,
            ReportEngine
                .Evaluate(
                    p with
                    {
                        Mode = "Enforce",
                        RequiredControls = ["browser"],
                    },
                    clean with
                    {
                        Controls = [new("browser", 1, "Ready", "can write", true)],
                    },
                    now
                )
                .Verdict
        )
);
Test(
    "legacy measure names map onto the measures that exist",
    () =>
        Eq(
            Verdict.PASS,
            ReportEngine
                .Evaluate(
                    p with
                    {
                        Mode = "Enforce",
                        RequiredControls = ["edge", "network"],
                    },
                    clean with
                    {
                        Controls = [new("browser", 1, "Applied", "readback", true)],
                    },
                    now
                )
                .Verdict
        )
);
Test(
    "all required measures in effect permit enforcement PASS",
    () =>
        Eq(
            Verdict.PASS,
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
                            new("process", 1, "Applied", "sweeping", true),
                            new("browser", 1, "Applied", "readback", true),
                        ],
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
    "a policy's own version may be lower after moving policies, its serial may not",
    () =>
    {
        using var k = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var pem = k.ExportSubjectPublicKeyInfoPem();
        var moved = PolicyCrypto.Sign(p with { Version = 2, Sequence = 7 }, k, "key1");
        Eq(7L, PolicyCrypto.Verify(moved, pem, "dev1", 6, now).Serial);
        Throws(() => PolicyCrypto.Verify(moved, pem, "dev1", 8, now));
        // Releases from before per-policy versions have no serial; their version was it.
        var legacy = PolicyCrypto.Sign(p with { Version = 9 }, k, "key1");
        Eq(9L, PolicyCrypto.Verify(legacy, pem, "dev1", 7, now).Serial);
        Throws(() => PolicyCrypto.Verify(legacy, pem, "dev1", 10, now));
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
Test(
    "reports name user accounts instead of SIDs",
    () =>
    {
        const string sid = "S-1-5-21-1-2-3-1001";
        var r = ReportEngine.Evaluate(
            p,
            clean with
            {
                Evidence = [violation with { UserSid = sid }],
                Modules = [.. clean.Modules, new("proxy", sid, "Unknown", now, "hive")],
                Users = [new(sid, "kaiyu")],
            },
            now
        );
        Yes(r.Reasons.Any(x => x.Contains("用户 kaiyu")) && r.Reasons.All(x => !x.Contains(sid)));
        Yes(r.CoverageGaps.Any(x => x.Contains("系统代理（用户 kaiyu）")));
        var md = ReportRenderer.Markdown(r);
        Yes(md.Contains("用户账户：kaiyu（" + sid + "）") && md.Contains("| 用户 kaiyu |"));
    }
);
var secretRule = new SensitiveFileRule("secret", "机密文件", ["机密", "Confidential"]);
var sensitivePolicy = p with
{
    SensitiveFiles = new() { Enabled = true, Rules = [secretRule] },
};
var sensitiveHit = new Evidence(
    "secret",
    "机密文件",
    EvidenceKind.SensitiveFile,
    @"D:\项目\2025机密合同.xlsx",
    "drive:D",
    "文件名包含“机密”（规则：机密文件）"
)
{
    CollectedAt = now.AddHours(-2),
};
var sensitiveScan = clean with
{
    Evidence = [sensitiveHit],
    Modules = [.. clean.Modules, new(SensitiveFiles.Module, "drive:D", "Complete", now.AddHours(-2))],
};
Test(
    "Chinese keywords match file names ignoring case and full-width letters",
    () =>
    {
        var matcher = new SensitiveNameMatcher([
            secretRule,
            new("contract", "合同", ["合同"]) { Extensions = [".xlsx", ".DOCX"] },
        ]);
        Eq(2, matcher.Match("2025机密合同.xlsx", false).Count);
        Eq("机密", matcher.Match("项目-机密-v2.docx", false)[0].Keyword);
        Eq(1, matcher.Match("ＣＯＮＦＩＤＥＮＴＩＡＬ report.pdf", false).Count);
        Eq(1, matcher.Match("confidential.txt", false).Count);
        Eq("contract", matcher.Match("采购合同.docx", false).Single().Rule.Id);
        Eq(0, matcher.Match("采购合同.pdf", false).Count);
        Eq(0, matcher.Match("機密.txt", false).Count);
        // A rule limited to extensions never matches folders; one already reported for a parent folder is skipped.
        Eq("secret", matcher.Match("机密合同", true).Single().Rule.Id);
        Eq(1, matcher.Match("机密合同.xlsx", false, new HashSet<string> { "secret" }).Count);
    }
);
Test(
    "sensitive file alerts do not change the verdict and incomplete scans are only notes",
    () =>
    {
        var r = ReportEngine.Evaluate(sensitivePolicy, sensitiveScan, now);
        Eq(Verdict.PASS, r.Verdict);
        Eq(0, r.SensitiveFileNotes.Length);
        var partial = ReportEngine.Evaluate(
            sensitivePolicy,
            sensitiveScan with
            {
                Modules = [.. clean.Modules, new(SensitiveFiles.Module, "drive:E", "Unknown", now, "磁盘未就绪")],
            },
            now
        );
        Eq(Verdict.PASS, partial.Verdict);
        Yes(partial.SensitiveFileNotes.Any(x => x.Contains("敏感文件（E 盘）") && x.Contains("磁盘未就绪")));
        var missing = ReportEngine.Evaluate(sensitivePolicy, clean, now);
        Eq(Verdict.PASS, missing.Verdict);
        Yes(missing.SensitiveFileNotes.Any(x => x.Contains("尚未上报")));
        Eq(0, ReportEngine.Evaluate(p, clean, now).SensitiveFileNotes.Length);
    }
);
Test(
    "violation rules fail the device and require complete fresh scans",
    () =>
    {
        var failing = sensitivePolicy with
        {
            SensitiveFiles = sensitivePolicy.SensitiveFiles with { Rules = [secretRule with { Action = "Violation" }] },
        };
        var r = ReportEngine.Evaluate(failing, sensitiveScan, now);
        Eq(Verdict.FAIL, r.Verdict);
        Yes(r.Reasons.Single().Contains("机密文件（整机）：敏感文件"));
        var pending = ReportEngine.Evaluate(failing, clean, now);
        Eq(Verdict.UNKNOWN, pending.Verdict);
        Yes(pending.CoverageGaps.Any(x => x.Contains("尚未上报")));
        var aged = sensitiveScan with
        {
            Evidence = [sensitiveHit with { CollectedAt = now.AddHours(-30) }],
            Modules = [.. clean.Modules, new(SensitiveFiles.Module, "drive:D", "Complete", now.AddHours(-30))],
        };
        Eq(Verdict.UNKNOWN, ReportEngine.Evaluate(failing, aged, now).Verdict);
        Eq(Verdict.PASS, ReportEngine.Evaluate(failing, sensitiveScan with { Evidence = [] }, now).Verdict);
    }
);
Test(
    "report lists sensitive files without adding a section",
    () =>
    {
        var md = ReportRenderer.Markdown(ReportEngine.Evaluate(sensitivePolicy, sensitiveScan, now));
        Eq(9, md.Split('\n').Count(x => x.StartsWith("## ")));
        Yes(md.Contains("### 敏感文件") && md.Contains(@"D:\项目\2025机密合同.xlsx") && md.Contains("| D 盘 |"));
        Yes(!ReportRenderer.Markdown(ReportEngine.Evaluate(p, clean, now)).Contains("### 敏感文件"));
    }
);
Test(
    "sensitive file rules are validated",
    () =>
    {
        PolicyCrypto.Validate(sensitivePolicy);
        PolicyCrypto.Validate(p with { SensitiveFiles = new() });
        SensitiveFilePolicy With(SensitiveFileRule rule) => sensitivePolicy.SensitiveFiles with { Rules = [rule] };
        Throws(() => PolicyCrypto.Validate(p with { SensitiveFiles = null! }));
        Throws(() => PolicyCrypto.Validate(p with { SensitiveFiles = new() { Enabled = true } }));
        Throws(() => PolicyCrypto.Validate(p with { SensitiveFiles = With(secretRule with { Keywords = ["密"] }) }));
        Throws(() => PolicyCrypto.Validate(p with { SensitiveFiles = With(secretRule with { Keywords = [" 机密"] }) }));
        Throws(() => PolicyCrypto.Validate(p with { SensitiveFiles = With(secretRule with { Keywords = [] }) }));
        Throws(() => PolicyCrypto.Validate(p with { SensitiveFiles = With(secretRule with { Action = "Delete" }) }));
        Throws(() => PolicyCrypto.Validate(p with { SensitiveFiles = With(secretRule with { Id = "机密" }) }));
        Throws(() =>
            PolicyCrypto.Validate(p with { SensitiveFiles = With(secretRule with { Extensions = ["xlsx"] }) })
        );
        Throws(() =>
            PolicyCrypto.Validate(
                p with
                {
                    SensitiveFiles = sensitivePolicy.SensitiveFiles with { Rules = [secretRule, secretRule] },
                }
            )
        );
        Throws(() =>
            PolicyCrypto.Validate(
                p with
                {
                    SensitiveFiles = sensitivePolicy.SensitiveFiles with
                    {
                        ScanUserProfiles = false,
                        ScanOtherFixedDrives = false,
                    },
                }
            )
        );
        Throws(() =>
            PolicyCrypto.Validate(p with { SensitiveFiles = sensitivePolicy.SensitiveFiles with { RescanHours = 0 } })
        );
        // Policies published before this feature carry no sensitive file settings and stay valid.
        var old = Wire.Read<PolicyDocument>(Wire.Serialize(p).Replace("\"sensitiveFiles\"", "\"unused\""));
        Yes(!old.SensitiveFiles.Enabled);
        PolicyCrypto.Validate(old);
    }
);
Test(
    "a report stays the same until its ValidUntil, whatever the timestamps",
    () =>
    {
        var random = new Random(7);
        var rule = new SensitiveFileRule("secret", "机密文件", ["机密"]) { Action = "Violation" };
        DateTimeOffset At(int spreadMinutes) => now.AddMinutes(random.Next(-spreadMinutes, 10));
        string Key(ComplianceReport r) =>
            string.Join(
                "|",
                r.Verdict,
                r.Summary,
                string.Join(";", r.Reasons),
                string.Join(";", r.CoverageGaps),
                r.ViolationCount,
                r.EvidenceCount,
                r.ProtectionStatus,
                string.Join(";", r.SensitiveFileNotes)
            );
        var timed = 0;
        for (var i = 0; i < 400; i++)
        {
            var policy = p with
            {
                ExpiresAt = now.AddMinutes(random.Next(-5, 600)),
                IssuedAt = now.AddMinutes(random.Next(-600, 5)),
                SensitiveFiles = random.Next(2) == 0 ? new() : new() { Enabled = true, Rules = [rule] },
            };
            var modules = new[] { "installed", "proxy", "users", "processes", SensitiveFiles.Module }
                .Where(_ => random.Next(4) != 0)
                .Select(m => new ModuleResult(m, "machine", random.Next(6) == 0 ? "Failed" : "Complete", At(300)))
                .ToArray();
            Evidence[] evidence =
            [
                .. random.Next(2) == 0 ? [violation with { CollectedAt = At(300) }] : Array.Empty<Evidence>(),
                .. random.Next(3) == 0 ? [sensitiveHit with { CollectedAt = At(2000) }] : Array.Empty<Evidence>(),
            ];
            var snapshot = clean with { CollectedAt = At(30), Modules = modules, Evidence = evidence };
            var report = ReportEngine.Evaluate(policy, snapshot, now);
            // The evidence the report names as failing is what judging each piece on its own finds.
            var alone = Enumerable
                .Range(0, evidence.Length)
                .Where(j =>
                    ReportEngine.Evaluate(policy, snapshot with { Evidence = [evidence[j]] }, now).Verdict
                    == Verdict.FAIL
                );
            Eq(string.Join(",", alone), string.Join(",", report.ConfirmedEvidence));
            if (report.ValidUntil is not { } until)
                continue;
            timed++;
            Yes(until > now);
            var expected = Key(report);
            foreach (var at in new[] { now + (until - now) / 2, until.AddTicks(-1) })
                Eq(expected, Key(ReportEngine.Evaluate(policy, snapshot, at)));
        }
        Yes(timed > 300);
    }
);
Console.WriteLine($"Core tests: {passed} passed, {failed} failed");
return failed == 0 ? 0 : 1;
