import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { afterEach, describe, expect, it, vi } from "vitest";
import { App } from "../src/App";
import { Providers } from "../src/providers";

const alert = (id: string, type: string, state = "Open") => ({
  id,
  deviceId: "a",
  hostName: "PC-A",
  type,
  objectKey: id,
  summary: `PC-A ${type} ${id}`,
  state,
  lastSequence: 1,
  firstSeen: "2026-10-14T05:00:00Z",
  lastSeen: "2026-10-14T05:00:00Z",
  acknowledged: false,
});

const json = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });

// An operator with the given alerts; `answer` handles any other request.
function stubApi(alerts: unknown[], answer: (url: string) => Response) {
  const calls: string[] = [];
  vi.stubGlobal("fetch", async (url: string, options: RequestInit) => {
    calls.push(`${options.method ?? "GET"} ${url}`);
    if (url === "/api/me")
      return json(200, { username: "admin", roles: ["Reader", "Operator"], csrfToken: "t" });
    if (url === "/api/devices") return json(200, []);
    if (url === "/api/alerts") return json(200, alerts);
    return answer(url);
  });
  return calls;
}

const renderAlerts = () =>
  render(
    <Providers>
      <MemoryRouter initialEntries={["/alerts"]}>
        <App />
      </MemoryRouter>
    </Providers>,
  );

afterEach(() => vi.unstubAllGlobals());

describe("alert center", () => {
  it("confirms the rest when one confirmation fails, then refreshes and says how many failed", async () => {
    const calls = stubApi(
      [alert("1", "Violation"), alert("2", "Violation"), alert("3", "Violation")],
      (url) =>
        url === "/api/alerts/2/ack" ? json(500, { error: "数据库忙" }) : json(200, { ok: true }),
    );
    renderAlerts();
    fireEvent.click(await screen.findByText("全部确认已阅"));
    expect(await screen.findByText(/已确认 2 条，1 条失败/)).toBeTruthy();
    expect(calls.filter((c) => c.startsWith("POST"))).toEqual([
      "POST /api/alerts/1/ack",
      "POST /api/alerts/2/ack",
      "POST /api/alerts/3/ack",
    ]);
    await waitFor(() => expect(calls.filter((c) => c === "GET /api/alerts").length).toBe(2));
  });

  it("starts older resolved alerts where the server's list ends, and says when loading fails", async () => {
    const calls = stubApi([alert("1", "Health", "Resolved")], () =>
      json(500, { error: "数据库忙" }),
    );
    renderAlerts();
    fireEvent.click(await screen.findByText("已恢复"));
    fireEvent.click(await screen.findByText("加载 30 天前恢复的告警"));
    expect(await screen.findByText(/加载更早的已恢复告警失败/)).toBeTruthy();
    // No browser-clock cursor on the first page.
    expect(calls).toContain("GET /api/alerts/resolved?limit=100");
  });
});
