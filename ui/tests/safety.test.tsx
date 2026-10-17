import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, it, expect, vi } from "vitest";
import { DeviceState, AlertCard, Login } from "../src/components";
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
  it("offline historical PASS is explicitly historical and current remains unknown", () => {
    render(<DeviceState device={deviceFixture} />);
    expect(screen.getByText("无法判断")).toBeTruthy();
    expect(screen.getByText(/上次结论：通过/)).toBeTruthy();
    expect(screen.getByText("失联")).toBeTruthy();
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
    render(<AlertCard alert={alertFixture} canAck onAck={acknowledge} />);
    await user.click(screen.getByRole("button", { name: "确认已阅" }));
    await waitFor(() => expect(screen.getByText("已确认")).toBeTruthy());
    // Acknowledging records that someone has seen it; only new scan evidence resolves it.
    expect(screen.getByText("未恢复")).toBeTruthy();
  });
  it("reader cannot acknowledge", () => {
    render(<AlertCard alert={alertFixture} canAck={false} onAck={async () => {}} />);
    expect(screen.queryByRole("button", { name: "确认已阅" })).toBeNull();
  });
  it("server Resolved state is shown as technical recovery, separate from acknowledgment", () => {
    render(
      <AlertCard
        alert={{ ...alertFixture, state: "Resolved", acknowledged: false }}
        canAck={false}
        onAck={async () => {}}
      />,
    );
    expect(screen.getByText("已恢复")).toBeTruthy();
    expect(screen.getByText("待确认")).toBeTruthy();
    expect(screen.queryByText("未恢复")).toBeNull();
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
