import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { exceptionState, ExceptionsPage } from "../src/pages/Exceptions";
import { Providers } from "../src/providers";
import type { StoredException } from "../src/types";

const session = (roles: string[]) => ({
  username: "admin",
  roles,
  csrfToken: "t",
  idleMinutes: 0,
  twoFactor: false,
  twoFactorRequired: false,
});

const request: StoredException = {
  id: "r-1",
  deviceId: "d1",
  hostName: "PC-01",
  note: "张三",
  group: "研发部",
  kind: "Product",
  target: "clash",
  label: "Clash",
  reason: "联调海外接口",
  days: 7,
  requestedBy: "CORP\\zhang",
  requestedAt: "2026-10-28T02:00:00Z",
  status: "Pending",
  decidedBy: "",
  decidedAt: null,
  expiresAt: null,
  decisionNote: "",
};
const granted: StoredException = {
  ...request,
  id: "x-1",
  kind: "Usb",
  target: "USBSTOR\\DISK&VEN_KINGSTON&PROD_IRONKEY\\IK0042&0",
  label: "Kingston IronKey",
  status: "Approved",
  decidedBy: "admin",
  decidedAt: "2026-10-28T03:00:00Z",
  expiresAt: "2099-01-01T00:00:00Z",
};

afterEach(() => vi.unstubAllGlobals());

function stub() {
  const calls: { url: string; method?: string; body?: unknown }[] = [];
  vi.stubGlobal("fetch", async (url: string, options: RequestInit = {}) => {
    calls.push({
      url,
      method: options.method,
      body: options.body ? JSON.parse(options.body as string) : undefined,
    });
    const json = (b: unknown) =>
      new Response(JSON.stringify(b), { headers: { "Content-Type": "application/json" } });
    if (options.method === "POST") return json({ ...request, status: "Approved" });
    return json(url === "/api/exceptions" ? [request, granted] : []);
  });
  return calls;
}

describe("exception approval", () => {
  it("names each state, with approved exceptions ending by themselves", () => {
    const now = Date.parse("2026-10-28T04:00:00Z");
    expect(exceptionState(request, now)[0]).toBe("待审批");
    expect(exceptionState(granted, now)[0]).toBe("生效中");
    expect(exceptionState({ ...granted, expiresAt: "2026-10-28T03:30:00Z" }, now)[0]).toBe(
      "已到期",
    );
    expect(exceptionState({ ...granted, status: "Revoked" }, now)[0]).toBe("已撤销");
    expect(exceptionState({ ...request, status: "Rejected" }, now)[0]).toBe("已驳回");
  });

  it("approves a pending request for the days chosen, and revokes an exception in force", async () => {
    const calls = stub();
    const openDevice = vi.fn();
    render(
      <Providers>
        <ExceptionsPage session={session(["Reader", "Publisher"])} openDevice={openDevice} />
      </Providers>,
    );
    expect(await screen.findByText("联调海外接口")).toBeTruthy();
    // Pending requests first; the exception in force is under its own view.
    expect(screen.queryByText("Kingston IronKey")).toBeNull();
    await userEvent.click(screen.getByRole("button", { name: "批准" }));
    const dialog = await screen.findByRole("dialog");
    const days = within(dialog).getByLabelText("有效天数");
    await userEvent.clear(days);
    await userEvent.type(days, "3");
    await userEvent.type(within(dialog).getByLabelText("说明"), "项目结束后收回");
    await userEvent.click(within(dialog).getByRole("button", { name: "批准" }));
    await waitFor(() =>
      expect(calls.find((c) => c.method === "POST")).toEqual({
        url: "/api/exceptions/r-1/approve",
        method: "POST",
        body: { days: 3, note: "项目结束后收回" },
      }),
    );

    await userEvent.click(screen.getByText("生效中"));
    expect(await screen.findByText("Kingston IronKey")).toBeTruthy();
    await userEvent.click(screen.getByRole("button", { name: "撤销" }));
    const revoke = await screen.findByRole("dialog", { name: "撤销例外" });
    expect(within(revoke).getByText(/撤销后终端恢复按策略管控/)).toBeTruthy();
    await userEvent.click(within(revoke).getByRole("button", { name: "撤销" }));
    await waitFor(() =>
      expect(calls.some((c) => c.url === "/api/exceptions/x-1/revoke")).toBe(true),
    );

    await userEvent.click(screen.getByText("PC-01（张三）"));
    expect(openDevice).toHaveBeenCalledWith("d1");
  });

  it("lets readers see requests without deciding them", async () => {
    stub();
    render(
      <Providers>
        <ExceptionsPage session={session(["Reader"])} openDevice={() => {}} />
      </Providers>,
    );
    expect(await screen.findByText("联调海外接口")).toBeTruthy();
    expect(screen.getByText(/审批需要“发布人”角色/)).toBeTruthy();
    expect(screen.queryByRole("button", { name: "批准" })).toBeNull();
    expect(screen.queryByRole("button", { name: /新增例外/ })).toBeNull();
  });
});
