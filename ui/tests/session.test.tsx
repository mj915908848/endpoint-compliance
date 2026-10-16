import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { afterEach, describe, expect, it, vi } from "vitest";
import { App } from "../src/App";
import { Providers } from "../src/providers";

// The server ends the session once `expired` is set; every list is empty until then.
function stubApi(idleMinutes: number) {
  const state = { expired: false, calls: [] as string[], idle: [] as string[] };
  vi.stubGlobal("fetch", async (url: string, options: RequestInit) => {
    state.calls.push(`${options.method ?? "GET"} ${url}`);
    state.idle.push(new Headers(options.headers).get("X-Idle-Seconds") ?? "");
    const json = (status: number, body: unknown) =>
      new Response(JSON.stringify(body), {
        status,
        headers: { "Content-Type": "application/json" },
      });
    if (state.expired) return json(401, { error: "Session expired" });
    if (url === "/api/me")
      return json(200, { username: "admin", roles: ["Reader"], csrfToken: "t", idleMinutes });
    if (url === "/api/auth/logout") return json(200, { ok: true });
    return json(200, []);
  });
  return state;
}

const renderApp = () =>
  render(
    <Providers>
      <MemoryRouter initialEntries={["/"]}>
        <App />
      </MemoryRouter>
    </Providers>,
  );

afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
  localStorage.clear();
});

describe("management session", () => {
  it("returns to the login screen when the server no longer accepts the session", async () => {
    const api = stubApi(0);
    renderApp();
    const alerts = await screen.findByRole("link", { name: /告警中心/ });
    expect(api.idle.every((s) => /^\d+$/.test(s))).toBe(true);
    api.expired = true;
    await userEvent.click(alerts);
    expect(await screen.findByText("登录已过期，请重新登录。")).toBeTruthy();
    expect(screen.getByRole("button", { name: "登录" })).toBeTruthy();
  });

  it("warns in the last minute and signs out after the idle minutes", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    const api = stubApi(2);
    renderApp();
    await screen.findByRole("link", { name: /告警中心/ });
    await act(async () => {
      vi.advanceTimersByTime(65_000);
    });
    expect(screen.getByText(/2 分钟未操作将自动退出/)).toBeTruthy();
    // Using the page puts the warning away.
    await act(async () => {
      window.dispatchEvent(new Event("keydown"));
      vi.advanceTimersByTime(5_000);
    });
    expect(screen.queryByText(/2 分钟未操作将自动退出/)).toBeNull();
    await act(async () => {
      vi.advanceTimersByTime(125_000);
    });
    await waitFor(() => expect(screen.getByText("2 分钟未操作，已自动退出。")).toBeTruthy());
    expect(api.calls).toContain("POST /api/auth/logout");
  });
});
