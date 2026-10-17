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
  policyApplied: true,
  protectionStatus: "审计模式",
  violationCount: 0,
  simulated: false,
  note: "",
  policyName: "",
  agentVersion: "",
  agentOutdated: false,
  network: null,
  sourceAddress: "",
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

  it("shows the client version and flags one older than the server", async () => {
    Object.assign(device, { agentVersion: "0.2.7", agentOutdated: true });
    try {
      stubApi(["Reader"]);
      renderAt("/devices/dev-1");
      expect(await screen.findByText("客户端 0.2.7 · 待升级")).toBeTruthy();
    } finally {
      Object.assign(device, { agentVersion: undefined, agentOutdated: undefined });
    }
  });

  it("is not offered to read-only accounts", async () => {
    stubApi(["Reader"]);
    renderAt("/devices/dev-1");
    expect(await screen.findByText("OLD-PC")).toBeTruthy();
    expect(screen.queryByRole("button", { name: /删除终端/ })).toBeNull();
  });
});

describe("device list", () => {
  it("shows each device's IP and MAC, finds it by either, and counts the online ones", async () => {
    const online: DeviceSummary = {
      ...device,
      id: "dev-2",
      hostName: "NEW-PC",
      onlineState: "Online",
      currentVerdict: "PASS",
      network: [
        {
          name: "以太网",
          mac: "00-11-22-33-44-55",
          addresses: ["10.0.0.5", "fd00::5"],
          primary: true,
        },
      ],
    };
    vi.stubGlobal(
      "fetch",
      async (url: string) =>
        new Response(
          JSON.stringify(
            url === "/api/me"
              ? { username: "admin", roles: ["Reader"], csrfToken: "t" }
              : url === "/api/devices"
                ? [device, online]
                : [],
          ),
          { status: 200, headers: { "Content-Type": "application/json" } },
        ),
    );
    renderAt("/devices");
    expect(await screen.findByText(/10\.0\.0\.5 · 00-11-22-33-44-55/)).toBeTruthy();
    expect(screen.getByText("在线").closest(".ant-tag")).toBeTruthy();
    expect(screen.getByText(/共\s*2\s*台/)).toBeTruthy();
    await userEvent.type(screen.getByLabelText("搜索设备"), "00:11:22");
    await waitFor(() => expect(screen.queryByText("OLD-PC")).toBeNull());
    expect(screen.getByText("NEW-PC")).toBeTruthy();
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
          collectedAt: null,
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
      users: [],
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
      sensitiveFileNotes: [],
      policyName: "默认策略",
      policyVersion: 1,
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
    await userEvent.click(
      await screen.findByRole("button", { name: /添加备注/ }, { timeout: 5000 }),
    );
    await userEvent.type(screen.getByLabelText("终端备注"), "张三 · 研发部");
    await userEvent.click(screen.getByRole("button", { name: "保存" }));
    await waitFor(() => expect(puts).toEqual([{ note: "张三 · 研发部" }]));
    expect(await screen.findByText("备注：张三 · 研发部")).toBeTruthy();
  });
});

describe("alert center", () => {
  const alert = (
    id: string,
    deviceId: string,
    hostName: string,
    type: string,
    state = "Open",
    lastSeen = "2026-10-14T05:00:00Z",
  ) => ({
    id,
    deviceId,
    hostName,
    type,
    objectKey: id,
    summary: `${hostName} ${type} ${id}`,
    state,
    lastSequence: 1,
    firstSeen: "2026-10-14T05:00:00Z",
    lastSeen,
    acknowledged: false,
  });

  it("groups violations and sensitive files per device, newest first", async () => {
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
          alert("1", "b", "PC-B", "Violation", "Open", "2026-10-14T05:00:00Z"),
          alert("2", "a", "PC-A", "Violation", "Open", "2026-10-14T06:00:00Z"),
          alert("3", "a", "PC-A", "Violation", "Open", "2026-10-14T04:00:00Z"),
          alert("4", "a", "PC-A", "Offline", "Open", "2026-10-14T03:00:00Z"),
          alert("5", "b", "PC-B", "Violation", "Resolved"),
          alert("6", "b", "PC-B", "SensitiveFile", "Open", "2026-10-14T07:00:00Z"),
          alert("7", "b", "PC-B", "SensitiveFile", "Open", "2026-10-14T08:00:00Z"),
          alert("8", "a", "PC-A", "Clue", "Open", "2026-10-14T09:00:00Z"),
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
    // Newest alert first within a device.
    expect(
      within(cards[0])
        .getAllByRole("listitem")
        .map((li) => li.textContent?.slice(0, 18)),
    ).toEqual(["PC-A Violation 2首次", "PC-A Violation 3首次"]);
    const sensitive = screen.getAllByLabelText(/^敏感文件 /);
    expect(screen.getByText("敏感文件（1 台）")).toBeTruthy();
    expect(within(sensitive[0]).getByText("2 个敏感文件")).toBeTruthy();
    // Other alerts list only what is not shown above, newest first; not the resolved violation.
    expect(screen.getByText("其他告警（2）")).toBeTruthy();
    const others = screen.getAllByText(/^PC-A (Clue|Offline)/).map((e) => e.textContent);
    expect(others).toEqual(["PC-A Clue 8", "PC-A Offline 4"]);
    await userEvent.click(within(cards[0]).getByRole("button", { name: "查看终端" }));
    await waitFor(() => expect(screen.getByTestId("location").textContent).toBe("/devices/a"));
  });
});
