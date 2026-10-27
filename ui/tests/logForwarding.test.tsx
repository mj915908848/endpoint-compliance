import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { LogForwardingPanel } from "../src/components";
import { Providers } from "../src/providers";
import type { LogForwardingView, Session } from "../src/types";

const session: Session = {
  username: "admin",
  roles: ["Reader", "Admin"],
  csrfToken: "t",
  idleMinutes: 0,
  twoFactor: true,
  twoFactorRequired: false,
};

const view: LogForwardingView = {
  settings: {
    enabled: false,
    host: "",
    port: 514,
    protocol: "Udp",
    format: "Json",
    facility: 16,
    alerts: true,
    audit: true,
    caCertificate: "",
  },
  last: null,
};

type Call = { url: string; method?: string; body?: unknown };

afterEach(() => vi.unstubAllGlobals());

describe("log forwarding", () => {
  it("saves a TLS server with an internal CA and sends a test message", async () => {
    const calls: Call[] = [];
    let saved = view;
    vi.stubGlobal("fetch", async (url: string, options: RequestInit = {}) => {
      const body = options.body ? JSON.parse(options.body as string) : undefined;
      calls.push({ url, method: options.method, body });
      const json = (b: unknown) =>
        new Response(JSON.stringify(b), { headers: { "Content-Type": "application/json" } });
      if (options.method === "PUT") {
        saved = { settings: body, last: null };
        return json({ ok: true });
      }
      if (url.endsWith("/test")) return json({ ok: false, error: "连接日志服务器超时" });
      return json(saved);
    });
    render(
      <Providers>
        <LogForwardingPanel session={session} />
      </Providers>,
    );
    await userEvent.click(await screen.findByLabelText("发送到日志服务器"));
    await userEvent.type(screen.getByLabelText("服务器地址"), "siem.example.local");
    await userEvent.click(screen.getByLabelText("协议"));
    await userEvent.click(await screen.findByTitle(/TLS 加密/));
    // The usual port follows the protocol unless it was changed by hand.
    expect((screen.getByLabelText("端口") as HTMLInputElement).value).toBe("6514");
    await userEvent.type(
      screen.getByLabelText("信任的 CA 证书（可选）"),
      "-----BEGIN CERTIFICATE-----",
    );
    await userEvent.click(screen.getByRole("checkbox", { name: /审计记录/ }));
    await userEvent.click(screen.getByRole("button", { name: "保存" }));
    await waitFor(() =>
      expect(calls.find((c) => c.method === "PUT")?.body).toEqual({
        enabled: true,
        host: "siem.example.local",
        port: 6514,
        protocol: "Tls",
        format: "Json",
        facility: 16,
        caCertificate: "-----BEGIN CERTIFICATE-----",
        alerts: true,
        audit: false,
      }),
    );
    await userEvent.click(await screen.findByRole("button", { name: "发送测试消息" }));
    expect(await screen.findByText("测试消息发送失败：连接日志服务器超时")).toBeTruthy();
  });
});
