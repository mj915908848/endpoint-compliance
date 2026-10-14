import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { CoverageGuide, DeviceGuide, OverviewGuide } from "../src/components";
import type { DeviceSummary, ModuleResult } from "../src/types";

const device: DeviceSummary = {
  id: "fixture-device",
  hostName: "TEST-PC",
  lastHeartbeat: "2026-10-14T05:52:02Z",
  onlineState: "Online",
  currentVerdict: "FAIL",
  lastVerdict: "FAIL",
  lastScan: "2026-10-14T05:52:04Z",
  targetPolicyVersion: 1,
  appliedPolicyVersion: 0,
  protectionStatus: "审计模式",
  violationCount: 3,
  simulated: false,
};

describe("plain-language result explanation", () => {
  it("shows the confirmed failures before technical details", () => {
    render(<DeviceGuide device={device} />);
    expect(screen.getByText(/本次检查不通过：发现 3 个违规对象/)).toBeTruthy();
    expect(screen.getByText(/安装也不允许/)).toBeTruthy();
  });

  it("does not turn an offline historical failure into a pass", () => {
    const offline = { ...device, onlineState: "Offline", currentVerdict: "UNKNOWN" as const };
    render(<OverviewGuide devices={[offline]} />);
    expect(screen.getByText(/当前没有在线检查结论/)).toBeTruthy();
    expect(screen.getByText(/上次检查不通过/)).toBeTruthy();
    expect(screen.getByText(/重新运行“本机采集试用.bat”/)).toBeTruthy();
  });

  it("explains coverage gaps without treating them as new violations", () => {
    const modules: ModuleResult[] = [
      { module: "installed", scope: "machine", status: "Complete", collectedAt: "2026-10-14T05:52:04Z", error: null },
      { module: "extensions", scope: "user-1", status: "Error", collectedAt: "2026-10-14T05:52:04Z", error: "JsonReaderException; inspection incomplete" },
      { module: "proxy", scope: "user-2", status: "Unknown", collectedAt: "2026-10-14T05:52:04Z", error: "User hive not loaded" },
    ];
    render(<CoverageGuide modules={modules} />);
    expect(screen.getByText(/1 项读取失败，1 项未能覆盖/)).toBeTruthy();
    expect(screen.getByText(/不代表新发现违规/)).toBeTruthy();
  });
});
