import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { CoverageGuide, DeviceGuide, OverviewGuide } from "../src/components";
import type { DeviceSummary, ModuleResult, Report } from "../src/types";

const device: DeviceSummary = {
  id: "fixture-device",
  hostName: "TEST-PC",
  lastHeartbeat: "2026-10-14T05:52:02Z",
  onlineState: "Online",
  currentVerdict: "FAIL",
  lastVerdict: "FAIL",
  lastScan: "2026-10-14T05:52:04Z",
  targetPolicyVersion: 1,
  policyApplied: false,
  protectionStatus: "审计模式",
  violationCount: 3,
  simulated: false,
  note: "",
  policyName: "",
  agentVersion: "",
  agentOutdated: false,
  network: null,
  sourceAddress: "",
  agentUnsupported: false,
  archivedAt: null,
};

describe("plain-language result explanation", () => {
  it("shows the confirmed failures before technical details", () => {
    render(<DeviceGuide device={device} />);
    expect(screen.getByText("检查未通过")).toBeTruthy();
    expect(screen.getByText("3 个违规对象")).toBeTruthy();
    expect(screen.getByText(/只要安装即视为违规/)).toBeTruthy();
  });

  it("does not turn an offline historical failure into a pass", () => {
    const offline = { ...device, onlineState: "Offline", currentVerdict: "UNKNOWN" as const };
    render(<OverviewGuide devices={[offline]} />);
    expect(screen.getByText(/当前没有在线终端，无法给出检查结论/)).toBeTruthy();
    expect(screen.getByText(/上次检查未通过/)).toBeTruthy();
    expect(screen.getByText(/客户端服务正在运行/)).toBeTruthy();
  });

  it("explains coverage gaps without treating them as new violations", () => {
    const modules: ModuleResult[] = [
      {
        module: "installed",
        scope: "machine",
        status: "Complete",
        collectedAt: "2026-10-14T05:52:04Z",
        error: null,
      },
      {
        module: "extensions",
        scope: "user-1",
        status: "Error",
        collectedAt: "2026-10-14T05:52:04Z",
        error: "JsonReaderException; inspection incomplete",
      },
      {
        module: "proxy",
        scope: "user-2",
        status: "Unknown",
        collectedAt: "2026-10-14T05:52:04Z",
        error: "User hive not loaded",
      },
    ];
    render(<CoverageGuide modules={modules} />);
    expect(screen.getByText(/1 项读取失败，1 项未覆盖/)).toBeTruthy();
    expect(screen.getByText(/并不表示发现了新的违规/)).toBeTruthy();
  });
});

describe("user scope labels", () => {
  it("names accounts when the snapshot knows them and falls back to the SID", async () => {
    const { scopeLabel } = await import("../src/components");
    const users = [{ sid: "S-1-5-21-1-2-3-1001", name: "kaiyu" }];
    expect(scopeLabel("S-1-5-21-1-2-3-1001", users)).toBe("用户 kaiyu");
    expect(scopeLabel("S-1-5-21-1-2-3-1006", users)).toBe("用户 S-1-5-21-1-2-3-1006");
    expect(scopeLabel("machine", users)).toBe("整机");
    expect(scopeLabel("drive:D", users)).toBe("D 盘");
  });
});

describe("sensitive file report", () => {
  it("lists names that matched and says an incomplete scan proves nothing", async () => {
    const { ReportFindings } = await import("../src/components");
    const at = "2026-10-14T05:52:04Z";
    const report: Report = {
      verdict: "PASS",
      summary: "检查通过",
      reasons: [],
      coverageGaps: [],
      sensitiveFileNotes: ["敏感文件：D 盘 命中过多，仅列出部分"],
      policyName: "默认策略",
      policyVersion: 1,
      violationCount: 0,
      evidenceCount: 0,
      protectionStatus: "审计模式",
      snapshot: {
        schemaVersion: 1,
        deviceId: "d",
        hostName: "TEST-PC",
        platform: "Windows",
        simulated: false,
        collectedAt: at,
        policyVersion: 2,
        controls: [],
        users: [{ sid: "S-1-5-21-1-2-3-1001", name: "kaiyu" }],
        modules: [
          {
            module: "sensitive-files",
            scope: "drive:D",
            status: "Truncated",
            collectedAt: at,
            error: null,
          },
        ],
        evidence: [
          {
            productId: "rule-1",
            productName: "机密文件",
            kind: "SensitiveFile",
            objectKey: "D:\\资料\\机密名单.xlsx",
            source: "drive:D",
            summary: "文件名包含“机密”（规则：机密文件）",
            userSid: "S-1-5-21-1-2-3-1001",
            confirmed: true,
            collectedAt: null,
          },
        ],
      },
    };
    render(<ReportFindings report={report} />);
    expect(screen.getByText("1 条")).toBeTruthy();
    expect(screen.getByText("D:\\资料\\机密名单.xlsx")).toBeTruthy();
    expect(screen.getByText("敏感文件：D 盘 命中过多，仅列出部分")).toBeTruthy();
    expect(screen.getAllByText("D 盘").length).toBeGreaterThan(0);
    expect(screen.getAllByText("用户 kaiyu").length).toBeGreaterThan(0);
  });
});
