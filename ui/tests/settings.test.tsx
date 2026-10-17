import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { PasswordDialog } from "../src/components";
import { SystemPage } from "../src/pages/System";
import { Providers } from "../src/providers";
import type { AppSettings } from "../src/types";

const session = {
  username: "admin",
  roles: ["Reader", "Operator", "Publisher"],
  csrfToken: "t",
  idleMinutes: 0,
};
const settings: AppSettings = {
  notifications: {
    enabled: false,
    channel: "WeCom",
    webhookUrl: "",
    hasSecret: false,
    types: ["Violation", "SensitiveFile", "Health"],
    consoleUrl: "",
  },
  lastNotification: null,
  auditRetentionDays: 0,
};

type Call = { url: string; method?: string; body?: unknown };

function stub(reply: (call: Call) => unknown) {
  const calls: Call[] = [];
  vi.stubGlobal("fetch", async (url: string, options: RequestInit = {}) => {
    const call = {
      url,
      method: options.method,
      body: options.body ? JSON.parse(options.body as string) : undefined,
    };
    calls.push(call);
    const result = reply(call);
    if (result instanceof Response) return result;
    return new Response(JSON.stringify(result), {
      headers: { "Content-Type": "application/json" },
    });
  });
  return calls;
}

afterEach(() => vi.unstubAllGlobals());

describe("system settings", () => {
  it("saves a robot for chosen alert types and the audit retention", async () => {
    const calls = stub((c) =>
      c.url === "/api/settings"
        ? settings
        : c.url === "/api/status"
          ? { mode: "Production", storage: "Postgres", networkCapabilities: [], policyKeyId: "k" }
          : c.url === "/api/client-packages"
            ? []
            : c.url === "/api/settings/signing-key"
              ? { keyId: "k", rotation: null }
              : { ok: true },
    );
    render(
      <Providers>
        <SystemPage session={session} />
      </Providers>,
    );
    await userEvent.click(await screen.findByLabelText("推送新告警"));
    await userEvent.type(
      screen.getByLabelText("机器人地址"),
      "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=k",
    );
    await userEvent.click(screen.getByLabelText("设备失联"));
    expect(screen.getByText(/员工下班关机/)).toBeTruthy();
    await userEvent.click(screen.getAllByRole("button", { name: "保存" })[0]);
    await waitFor(() =>
      expect(calls.find((c) => c.method === "PUT")?.body).toEqual({
        enabled: true,
        channel: "WeCom",
        webhookUrl: "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=k",
        secret: null,
        types: ["Violation", "SensitiveFile", "Health", "Offline"],
        consoleUrl: window.location.origin,
      }),
    );

    await userEvent.click(screen.getByLabelText("审计记录保留期限"));
    await userEvent.click(await screen.findByTitle("1 年"));
    await userEvent.click(screen.getAllByRole("button", { name: "保存" })[1]);
    await waitFor(() =>
      expect(calls.some((c) => c.url === "/api/settings/audit-retention")).toBe(true),
    );
    expect(calls.find((c) => c.url === "/api/settings/audit-retention")?.body).toEqual({
      days: 365,
    });
  });

  it("shows operators the saved robot masked and the audit retention without a way to change it", async () => {
    stub((c) =>
      c.url === "/api/settings"
        ? {
            ...settings,
            notifications: {
              ...settings.notifications,
              webhookUrl: "https://qyapi.weixin.qq.com/****abcd",
            },
          }
        : c.url === "/api/client-packages"
          ? []
          : { mode: "Production", storage: "Postgres", networkCapabilities: [], policyKeyId: "k" },
    );
    render(
      <Providers>
        <SystemPage session={{ ...session, roles: ["Reader", "Operator"] }} />
      </Providers>,
    );
    expect(await screen.findByText("只有发布人可以修改")).toBeTruthy();
    expect(screen.getByText(/不修改就保留原地址/)).toBeTruthy();
  });

  it("hides the settings from accounts that only read", async () => {
    stub(() => ({
      mode: "Production",
      storage: "Postgres",
      networkCapabilities: [],
      policyKeyId: "k",
    }));
    render(
      <Providers>
        <SystemPage session={{ ...session, roles: ["Reader"] }} />
      </Providers>,
    );
    expect(await screen.findByText("运行环境")).toBeTruthy();
    expect(screen.queryByText("告警推送")).toBeNull();
  });
});

describe("password", () => {
  it("checks the confirmation and shows why the server refused", async () => {
    const calls = stub(
      () =>
        new Response(JSON.stringify({ error: "当前密码不正确" }), {
          status: 400,
          headers: { "Content-Type": "application/json" },
        }),
    );
    render(
      <Providers>
        <PasswordDialog session={session} open onClose={() => {}} />
      </Providers>,
    );
    await userEvent.type(screen.getByLabelText("当前密码"), "old-password");
    await userEvent.type(screen.getByLabelText("新密码"), "a-new-password-123");
    await userEvent.type(screen.getByLabelText("确认新密码"), "different-password");
    await userEvent.click(screen.getByRole("button", { name: "修改" }));
    expect(await screen.findByText("两次输入的新密码不一致")).toBeTruthy();
    expect(calls).toHaveLength(0);

    await userEvent.clear(screen.getByLabelText("确认新密码"));
    await userEvent.type(screen.getByLabelText("确认新密码"), "a-new-password-123");
    await userEvent.click(screen.getByRole("button", { name: "修改" }));
    expect(await screen.findByText("当前密码不正确")).toBeTruthy();
    expect(calls[0].body).toEqual({
      currentPassword: "old-password",
      newPassword: "a-new-password-123",
    });
  });
});
