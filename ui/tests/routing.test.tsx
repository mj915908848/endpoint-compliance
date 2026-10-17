import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, useLocation } from "react-router";
import { afterEach, describe, expect, it, vi } from "vitest";
import { App } from "../src/App";
import { Providers } from "../src/providers";

const session = {
  username: "admin",
  roles: ["Reader", "Operator"],
  csrfToken: "t",
  idleMinutes: 0,
};

// Logged in; every list is empty and device lookups fail, which is enough to render each page shell.
function stubApi(loggedIn = true) {
  const calls: string[] = [];
  vi.stubGlobal("fetch", async (url: string, options: RequestInit) => {
    calls.push(`${options.method ?? "GET"} ${url}`);
    const json = (status: number, body: unknown) =>
      new Response(JSON.stringify(body), {
        status,
        headers: { "Content-Type": "application/json" },
      });
    if (url === "/api/me")
      return loggedIn ? json(200, session) : json(401, { error: "Login required" });
    if (url === "/api/auth/login") return json(200, session);
    if (url === "/api/devices" || url === "/api/alerts") return json(200, []);
    return json(404, { error: "Device not found" });
  });
  return calls;
}

function Location() {
  return <output data-testid="location">{useLocation().pathname}</output>;
}

function renderAt(path: string) {
  return render(
    <Providers>
      <MemoryRouter initialEntries={[path]}>
        <App />
        <Location />
      </MemoryRouter>
    </Providers>,
  );
}

const location = () => screen.getByTestId("location").textContent;

afterEach(() => vi.unstubAllGlobals());

describe("URL routing", () => {
  it("opens a device detail page directly from its URL", async () => {
    const calls = stubApi();
    renderAt("/devices/dev-1");
    expect(await screen.findByText("返回终端列表")).toBeTruthy();
    await waitFor(() => expect(calls).toContain("GET /api/devices/dev-1"));
    expect(screen.getByRole("link", { name: /终端设备/ }).className).toContain("active");
  });

  it("navigates with the sidebar and highlights the current page", async () => {
    const calls = stubApi();
    renderAt("/");
    await userEvent.click(await screen.findByRole("link", { name: /告警中心/ }));
    expect(location()).toBe("/alerts");
    expect(screen.getByRole("link", { name: /告警中心/ }).className).toContain("active");
    expect(screen.getByRole("link", { name: /总览/ }).className).not.toContain("active");
    await waitFor(() => expect(calls).toContain("GET /api/alerts"));
  });

  it("returns from a device to the device list", async () => {
    stubApi();
    renderAt("/devices/dev-1");
    await userEvent.click(await screen.findByText("返回终端列表"));
    expect(location()).toBe("/devices");
  });

  it("redirects unknown paths to the overview", async () => {
    stubApi();
    renderAt("/no-such-page");
    await waitFor(() => expect(location()).toBe("/"));
  });

  it("keeps the requested URL through login", async () => {
    stubApi(false);
    renderAt("/devices/dev-1");
    await userEvent.type(await screen.findByLabelText(/用户名|账号/), "admin");
    await userEvent.type(screen.getByLabelText(/密码/), "test-admin-password-long");
    await userEvent.click(screen.getByRole("button", { name: /登录/ }));
    expect(await screen.findByText("返回终端列表")).toBeTruthy();
    expect(location()).toBe("/devices/dev-1");
  });
});
