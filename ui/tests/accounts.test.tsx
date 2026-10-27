import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { afterEach, describe, expect, it, vi } from "vitest";
import { App } from "../src/App";
import { AccountsPanel } from "../src/components";
import { Providers } from "../src/providers";
import type { Session, UsersView } from "../src/types";

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
    return new Response(JSON.stringify(result ?? []), {
      headers: { "Content-Type": "application/json" },
    });
  });
  return calls;
}

const error = (status: number, message: string) =>
  new Response(JSON.stringify({ error: message }), {
    status,
    headers: { "Content-Type": "application/json" },
  });

const session: Session = {
  username: "admin",
  roles: ["Reader", "Operator", "Publisher", "Admin"],
  csrfToken: "t",
  idleMinutes: 0,
  twoFactor: false,
  twoFactorRequired: false,
};

const renderApp = () =>
  render(
    <Providers>
      <MemoryRouter initialEntries={["/"]}>
        <App />
      </MemoryRouter>
    </Providers>,
  );

afterEach(() => vi.unstubAllGlobals());

describe("two-step sign-in", () => {
  it("asks for the authenticator code once the password is right", async () => {
    const calls = stub((c) => {
      if (c.url === "/api/me") return error(401, "Login required");
      if (c.url === "/api/auth/login")
        return (c.body as { code?: string }).code === "123456"
          ? { ...session, twoFactor: true }
          : error(401, "TwoFactorRequired");
      return [];
    });
    renderApp();
    await userEvent.type(await screen.findByLabelText("管理员账号"), "admin");
    await userEvent.type(screen.getByLabelText("密码"), "test-admin-password-long");
    await userEvent.click(screen.getByRole("button", { name: "登录" }));
    await userEvent.type(await screen.findByLabelText("验证码"), "123456");
    expect(screen.queryByText("登录失败")).toBeNull();
    await userEvent.click(screen.getByRole("button", { name: "验证并登录" }));
    expect(await screen.findByRole("link", { name: /告警中心/ })).toBeTruthy();
    expect(calls.filter((c) => c.url === "/api/auth/login").at(-1)?.body).toEqual({
      username: "admin",
      password: "test-admin-password-long",
      code: "123456",
    });
  });

  it("makes an account set it up first when everyone must use it", async () => {
    let enabled = false;
    const calls = stub((c) => {
      if (c.url === "/api/me") return { ...session, twoFactorRequired: true, twoFactor: enabled };
      if (c.url === "/api/auth/two-factor/setup")
        return {
          secret: "JBSWY3DPEHPK3PXP",
          uri: "otpauth://totp/x:admin?secret=JBSWY3DPEHPK3PXP",
        };
      if (c.url === "/api/auth/two-factor/enable") {
        enabled = true;
        return { ok: true };
      }
      return [];
    });
    renderApp();
    expect(await screen.findByText("请先启用两步验证")).toBeTruthy();
    expect(screen.queryByRole("link", { name: /告警中心/ })).toBeNull();
    await userEvent.click(screen.getByRole("button", { name: "开始设置" }));
    expect(await screen.findByText("JBSWY3DPEHPK3PXP")).toBeTruthy();
    await userEvent.type(screen.getByLabelText("验证码"), "654321");
    await userEvent.click(screen.getByRole("button", { name: "启用" }));
    expect(await screen.findByRole("link", { name: /告警中心/ })).toBeTruthy();
    expect(calls.find((c) => c.url === "/api/auth/two-factor/enable")?.body).toEqual({
      code: "654321",
    });
  });
});

describe("accounts", () => {
  const view: UsersView = {
    requireTwoFactor: false,
    users: [
      {
        username: "admin",
        roles: ["Reader", "Operator", "Publisher", "Admin"],
        twoFactor: true,
        disabled: false,
        lastLoginAt: "2026-10-27T00:00:00Z",
      },
      {
        username: "zhang",
        roles: ["Reader", "Reviewer"],
        twoFactor: false,
        disabled: false,
        lastLoginAt: null,
      },
    ],
  };

  it("creates accounts, changes roles keeping older ones and disables an account", async () => {
    const calls = stub((c) => (c.url === "/api/users" && c.method === "GET" ? view : { ok: true }));
    render(
      <Providers>
        <AccountsPanel session={session} />
      </Providers>,
    );
    expect(await screen.findByText("从未登录")).toBeTruthy();
    expect(screen.getByText("当前账号")).toBeTruthy();

    await userEvent.click(screen.getByRole("button", { name: /新建账号/ }));
    let dialog = screen.getAllByRole("dialog").at(-1)!;
    await userEvent.type(within(dialog).getByLabelText("账号名"), "li");
    await userEvent.type(within(dialog).getByLabelText("初始密码"), "li-initial-password");
    await userEvent.click(within(dialog).getByRole("checkbox", { name: /操作员/ }));
    await userEvent.click(within(dialog).getByRole("button", { name: "创建" }));
    await waitFor(() =>
      expect(calls.find((c) => c.method === "POST" && c.url === "/api/users")?.body).toEqual({
        username: "li",
        password: "li-initial-password",
        roles: ["Reader", "Operator"],
      }),
    );

    const row = screen.getByText("zhang").closest("tr")!;
    await userEvent.click(within(row).getByRole("button", { name: "修改角色" }));
    dialog = screen.getAllByRole("dialog").at(-1)!;
    await userEvent.click(within(dialog).getByRole("checkbox", { name: /账号管理员/ }));
    await userEvent.click(within(dialog).getByRole("button", { name: "保存" }));
    await waitFor(() =>
      expect(calls.find((c) => c.url === "/api/users/zhang/roles")?.body).toEqual({
        roles: ["Reviewer", "Reader", "Admin"],
      }),
    );

    await userEvent.click(within(row).getByRole("button", { name: "停用" }));
    const pop = await screen.findByRole("tooltip");
    await userEvent.click(within(pop).getByRole("button", { name: "停用" }));
    await waitFor(() =>
      expect(calls.some((c) => c.method === "POST" && c.url === "/api/users/zhang/disable")).toBe(
        true,
      ),
    );
    // The signed-in account cannot reset or disable itself here.
    const mine = screen.getByText("当前账号").closest("tr")!;
    expect(within(mine).queryByRole("button", { name: "停用" })).toBeNull();
  });
});
