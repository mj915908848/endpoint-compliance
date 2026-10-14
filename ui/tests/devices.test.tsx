import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, useLocation } from "react-router";
import { afterEach, describe, expect, it, vi } from "vitest";
import { App } from "../src/App";
import { Providers } from "../src/providers";
import type { DeviceSummary, Report, Snapshot } from "../src/types";

const device: DeviceSummary = {
  id: "dev-1",
  hostName: "OLD-PC",
  lastHeartbeat: "2026-10-14T05:52:02Z",
  onlineState: "Offline",
  currentVerdict: "UNKNOWN",
  lastVerdict: "UNKNOWN",
  lastScan: null,
  targetPolicyVersion: 1,
  appliedPolicyVersion: 1,
  protectionStatus: "审计模式",
  violationCount: 0,
  simulated: false,
};

function stubApi(roles: string[]) {
  const calls: string[] = [];
  let deleted = false;
  vi.stubGlobal("fetch", async (url: string, options: RequestInit) => {
    calls.push(`${options.method ?? "GET"} ${url}`);
    const json = (status: number, body: unknown) =>
      new Response(JSON.stringify(body), {
        status,
        headers: { "Content-Type": "application/json" },
      });
    if (url === "/api/me") return json(200, { username: "admin", roles, csrfToken: "t" });
    if (url === "/api/devices") return json(200, deleted ? [] : [device]);
    if (url === "/api/devices/dev-1" && options.method === "DELETE") {
      deleted = true;
      return json(200, { deleted: "dev-1" });
    }
    if (url === "/api/devices/dev-1" && !deleted)
      return json(200, { device, snapshot: null, controls: [], pendingCommands: 0 });
    if (url === "/api/alerts") return json(200, []);
    return json(404, { error: "Device not found" });
  });
  return calls;
}

function Location() {
  return <output data-testid="location">{useLocation().pathname}</output>;
}

const renderAt = (path: string) =>
  render(
    <Providers>
      <MemoryRouter initialEntries={[path]}>
        <App />
        <Location />
      </MemoryRouter>
    </Providers>,
  );

afterEach(() => vi.unstubAllGlobals());

describe("deleting a device", () => {
  it("asks for confirmation, deletes it and returns to the list", async () => {
    const calls = stubApi(["Reader", "Operator"]);
    renderAt("/devices/dev-1");
    await userEvent.click(await screen.findByRole("button", { name: /删除终端/ }));
    expect((await screen.findAllByText("删除终端 OLD-PC？")).length).toBeGreaterThan(0);
    expect(calls).not.toContain("DELETE /api/devices/dev-1");
    await userEvent.click(screen.getByRole("button", { name: "删除" }));
    await waitFor(() => expect(calls).toContain("DELETE /api/devices/dev-1"));
    await waitFor(() => expect(screen.getByTestId("location").textContent).toBe("/devices"));
  });

  it("is not offered to read-only accounts", async () => {
    stubApi(["Reader"]);
    renderAt("/devices/dev-1");
    expect(await screen.findByText("OLD-PC")).toBeTruthy();
    expect(screen.queryByRole("button", { name: /删除终端/ })).toBeNull();
  });
});

describe("device detail", () => {
  it("states the verdict once and lists only the problems and their evidence", async () => {
    const failing: DeviceSummary = {
      ...device,
      onlineState: "Online",
      currentVerdict: "FAIL",
      lastVerdict: "FAIL",
      lastScan: "2026-10-14T05:52:04Z",
      violationCount: 1,
    };
    const snapshot: Snapshot = {
      schemaVersion: 1,
      deviceId: "dev-1",
      hostName: "OLD-PC",
      platform: "Windows",
      simulated: false,
      collectedAt: "2026-10-14T05:52:04Z",
      policyVersion: 1,
      evidence: [
        {
          productId: "cursor",
          productName: "Cursor",
          kind: "Installation",
          objectKey: "app:cursor",
          source: "registry",
          summary: "Cursor 已安装",
          userSid: null,
          confirmed: true,
        },
      ],
      modules: [
        {
          module: "installed",
          scope: "machine",
          status: "Complete",
          collectedAt: "2026-10-14T05:52:04Z",
          error: null,
        },
      ],
      controls: [],
    };
    const report: Report = {
      verdict: "FAIL",
      summary: "不通过：发现 1 个违规对象",
      reasons: ["Cursor：已安装（整机）"],
      coverageGaps: [],
      violationCount: 1,
      evidenceCount: 1,
      protectionStatus: "审计模式",
      snapshot,
    };
    vi.stubGlobal("fetch", async (url: string) => {
      const json = (body: unknown) =>
        new Response(JSON.stringify(body), { headers: { "Content-Type": "application/json" } });
      if (url === "/api/me") return json({ username: "admin", roles: ["Reader"], csrfToken: "t" });
      if (url === "/api/devices/dev-1")
        return json({ device: failing, snapshot, controls: [], pendingCommands: 0 });
      if (url === "/api/devices/dev-1/report") return json(report);
      return json([]);
    });
    renderAt("/devices/dev-1");
    expect(await screen.findByText("Cursor：已安装（整机）")).toBeTruthy();
    expect(screen.getAllByText(/发现 1 个违规对象/)).toHaveLength(1);
    expect(screen.getByText("软件安装与运行（1）")).toBeTruthy();
    expect(screen.getByText("未发现代理设置。")).toBeTruthy();
    expect(screen.getByRole("tab", { name: "检查覆盖（1/1）" })).toBeTruthy();
    expect(screen.queryByRole("tab", { name: /全部证据/ })).toBeNull();
  });
});

describe("device notes", () => {
  it("lets an operator note who uses the device", async () => {
    let note = "";
    const puts: unknown[] = [];
    vi.stubGlobal("fetch", async (url: string, options: RequestInit) => {
      const json = (body: unknown) =>
        new Response(JSON.stringify(body), { headers: { "Content-Type": "application/json" } });
      if (url === "/api/me")
        return json({ username: "admin", roles: ["Reader", "Operator"], csrfToken: "t" });
      if (url === "/api/devices/dev-1/note") {
        puts.push(JSON.parse(options.body as string));
        note = "张三 · 研发部";
        return json({ ...device, note });
      }
      if (url === "/api/devices/dev-1")
        return json({
          device: { ...device, note },
          snapshot: null,
          controls: [],
          pendingCommands: 0,
        });
      return json([]);
    });
    renderAt("/devices/dev-1");
    await userEvent.click(await screen.findByRole("button", { name: /添加备注/ }));
    await userEvent.type(screen.getByLabelText("终端备注"), "张三 · 研发部");
    await userEvent.click(screen.getByRole("button", { name: "保存" }));
    await waitFor(() => expect(puts).toEqual([{ note: "张三 · 研发部" }]));
    expect(await screen.findByText("备注：张三 · 研发部")).toBeTruthy();
  });
});

describe("alert center", () => {
  const alert = (id: string, deviceId: string, hostName: string, type: string, state = "Open") => ({
    id,
    deviceId,
    hostName,
    type,
    objectKey: id,
    summary: `${hostName} ${type} ${id}`,
    state,
    lastSequence: 1,
    firstSeen: "2026-10-14T05:00:00Z",
    lastSeen: "2026-10-14T05:00:00Z",
    acknowledged: false,
  });

  it("puts violating devices first, grouped per device with their notes", async () => {
    vi.stubGlobal("fetch", async (url: string) => {
      const json = (body: unknown) =>
        new Response(JSON.stringify(body), { headers: { "Content-Type": "application/json" } });
      if (url === "/api/me") return json({ username: "admin", roles: ["Reader"], csrfToken: "t" });
      if (url === "/api/devices")
        return json([
          { ...device, id: "a", hostName: "PC-A", note: "张三" },
          { ...device, id: "b", hostName: "PC-B" },
        ]);
      if (url === "/api/alerts")
        return json([
          alert("1", "b", "PC-B", "Violation"),
          alert("2", "a", "PC-A", "Violation"),
          alert("3", "a", "PC-A", "Violation"),
          alert("4", "a", "PC-A", "Offline"),
          alert("5", "b", "PC-B", "Violation", "Resolved"),
        ]);
      return json([]);
    });
    renderAt("/alerts");
    expect(await screen.findByText("违规设备（2 台）")).toBeTruthy();
    const cards = screen.getAllByLabelText(/^违规设备 /);
    expect(cards.map((c) => c.getAttribute("aria-label"))).toEqual([
      "违规设备 PC-A",
      "违规设备 PC-B",
    ]);
    expect(within(cards[0]).getByText("张三")).toBeTruthy();
    expect(within(cards[0]).getByText("2 项违规")).toBeTruthy();
    // Other alerts list only what is not shown above: the offline alert, not the resolved violation.
    expect(screen.getByText("其他告警（1）")).toBeTruthy();
    expect(screen.getByText(/PC-A（张三）/)).toBeTruthy();
    await userEvent.click(within(cards[0]).getByRole("button", { name: "查看终端" }));
    await waitFor(() => expect(screen.getByTestId("location").textContent).toBe("/devices/a"));
  });
});
