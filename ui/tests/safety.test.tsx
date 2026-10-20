import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, it, expect, vi } from "vitest";
import { AgentVersion, DeviceState, DeviceTable, AlertRow, Login } from "../src/components";
import type { DeviceSummary } from "../src/types";
// Explicit fixtures only: these are synthetic records, never runtime demonstration data.
const deviceFixture: DeviceSummary = {
  id: "fixture-1",
  hostName: "Fixture",
  lastHeartbeat: null,
  onlineState: "Offline",
  currentVerdict: "UNKNOWN",
  lastVerdict: "PASS",
  lastScan: "2026-10-13T00:00:00Z",
  targetPolicyVersion: 1,
  policyApplied: true,
  protectionStatus: "Audit only",
  violationCount: 0,
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
const alertFixture = {
  id: "fixture-alert",
  deviceId: "fixture-1",
  hostName: "Fixture",
  type: "Violation",
  objectKey: "cursor",
  summary: "安装仍存在",
  state: "Active",
  lastSequence: 9,
  firstSeen: "2026-10-13T00:00:00Z",
  lastSeen: "2026-10-13T00:00:00Z",
  acknowledged: false,
};
describe("safety boundaries", () => {
  it("marks a client below the supported minimum more strongly than an outdated one", () => {
    const { rerender } = render(
      <AgentVersion device={{ ...deviceFixture, agentVersion: "0.2.8", agentOutdated: true }} />,
    );
    expect(screen.getByText("客户端 0.2.8 · 待升级")).toBeTruthy();
    rerender(
      <AgentVersion
        device={{
          ...deviceFixture,
          agentVersion: "0.1.9",
          agentOutdated: true,
          agentUnsupported: true,
        }}
      />,
    );
    expect(screen.getByText("客户端 0.1.9 · 不受支持")).toBeTruthy();
  });

  it("offline historical PASS is explicitly historical and current remains unknown", () => {
    render(<DeviceTable devices={[deviceFixture]} onSelect={() => {}} />);
    expect(screen.getByText("无法判断")).toBeTruthy();
    expect(screen.getByText(/上次结论：通过/)).toBeTruthy();
    expect(screen.getByRole("img", { name: "失联" })).toBeTruthy();
    expect(screen.queryByText("通过")).toBeNull();
  });
  it("never presents an offline PASS as a current pass even if the payload is inconsistent", () => {
    render(<DeviceState device={{ ...deviceFixture, currentVerdict: "PASS" }} />);
    expect(screen.getByText("无法判断")).toBeTruthy();
    expect(screen.getByText(/上次结论：通过/)).toBeTruthy();
  });
  it("acknowledging does not locally resolve a technical incident", async () => {
    const user = userEvent.setup();
    const acknowledge = vi.fn().mockResolvedValue(undefined);
    const { container } = render(<AlertRow alert={alertFixture} onAck={acknowledge} />);
    await user.click(screen.getByRole("button", { name: "确认" }));
    await waitFor(() => expect(screen.getByText("已确认")).toBeTruthy());
    expect(acknowledge).toHaveBeenCalledWith([alertFixture.id]);
    // Acknowledging records that someone has seen it; only new scan evidence resolves it.
    expect(container.querySelector(".alert-row-resolved")).toBeNull();
  });
  it("reader cannot acknowledge", () => {
    render(<AlertRow alert={alertFixture} />);
    expect(screen.queryByRole("button", { name: "确认" })).toBeNull();
  });
  it("server Resolved state is shown as technical recovery, separate from acknowledgment", () => {
    const { container } = render(
      <AlertRow
        alert={{ ...alertFixture, state: "Resolved", acknowledged: false }}
        onAck={async () => {}}
      />,
    );
    expect(container.querySelector(".alert-row-resolved")).toBeTruthy();
    // Nothing left to acknowledge, and it is not shown as acknowledged either.
    expect(screen.queryByRole("button", { name: "确认" })).toBeNull();
    expect(screen.queryByText("已确认")).toBeNull();
  });
  it("rejected authentication is visible and password stays masked", async () => {
    const user = userEvent.setup();
    render(
      <Login
        onLogin={async () => {
          throw new Error("账号或密码不正确");
        }}
      />,
    );
    await user.type(screen.getByLabelText("管理员账号"), "auditor");
    const password = screen.getByLabelText("密码");
    expect(password.getAttribute("type")).toBe("password");
    await user.type(password, "fixture-password");
    await user.click(screen.getByRole("button", { name: /登\s*录/ }));
    expect(await screen.findByRole("alert")).toBeTruthy();
    expect(screen.getByText("账号或密码不正确")).toBeTruthy();
  });
});
