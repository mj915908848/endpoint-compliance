import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { afterEach, describe, expect, it, vi } from "vitest";
import * as api from "../src/api";
import { periodOf, ReportsPage } from "../src/pages/Reports";
import { Providers } from "../src/providers";
import type { PeriodReport } from "../src/types";

const report: PeriodReport = {
  from: "2026-10-01",
  to: "2026-10-28",
  generatedAt: "2026-10-28T08:00:00Z",
  start: { devices: 4, pass: 2, fail: 2, unknown: 0 },
  end: { devices: 4, pass: 3, fail: 1, unknown: 0 },
  days: [{ date: "2026-10-28", pass: 3, fail: 1, unknown: 0 }],
  groups: [
    { group: "研发部", devices: 2, pass: 1, fail: 1, unknown: 0 },
    { group: "", devices: 2, pass: 2, fail: 0, unknown: 0 },
  ],
  issues: [{ type: "Violation", subject: "Clash", devices: 2, alerts: 3 }],
  alertTypes: [{ type: "Violation", opened: 3, devices: 2 }],
  lingering: [
    {
      deviceId: "d1",
      hostName: "PC-01",
      note: "张三",
      group: "研发部",
      since: "2026-10-18T08:00:00Z",
      violationCount: 2,
    },
  ],
};

afterEach(() => vi.restoreAllMocks());

describe("compliance reports", () => {
  it("counts weeks from Monday and months from the 1st", () => {
    // Wednesday 2026-10-28.
    const today = new Date(2026, 9, 28);
    expect(periodOf("last7", today)).toEqual({ from: "2026-10-22", to: "2026-10-28" });
    expect(periodOf("thisWeek", today)).toEqual({ from: "2026-10-26", to: "2026-10-28" });
    expect(periodOf("lastWeek", today)).toEqual({ from: "2026-10-19", to: "2026-10-25" });
    expect(periodOf("thisMonth", today)).toEqual({ from: "2026-10-01", to: "2026-10-28" });
    expect(periodOf("lastMonth", today)).toEqual({ from: "2026-09-01", to: "2026-09-30" });
    // A Sunday belongs to the week that started the Monday before.
    expect(periodOf("thisWeek", new Date(2026, 10, 1))).toEqual({
      from: "2026-10-26",
      to: "2026-11-01",
    });
  });

  it("shows the period's figures, switches periods and downloads the report", async () => {
    const urls: string[] = [];
    vi.stubGlobal("fetch", async (url: string) => {
      urls.push(url);
      return new Response(JSON.stringify(report), {
        headers: { "Content-Type": "application/json" },
      });
    });
    const download = vi.spyOn(api, "downloadFile").mockResolvedValue();
    const openDevice = vi.fn();
    render(
      <Providers>
        <MemoryRouter initialEntries={["/reports?from=2026-10-01&to=2026-10-28"]}>
          <ReportsPage openDevice={openDevice} />
        </MemoryRouter>
      </Providers>,
    );
    expect(await screen.findByText("75%")).toBeTruthy();
    expect(screen.getByText("较期初上升 25 个百分点")).toBeTruthy();
    expect(screen.getByText("未分组")).toBeTruthy();
    expect(screen.getByText("Clash")).toBeTruthy();
    expect(screen.getByText("10 天，超期")).toBeTruthy();
    expect(screen.getByText("1 台超过 7 天未整改")).toBeTruthy();
    expect(urls[0]).toMatch(
      /^\/api\/reports\/compliance\?from=2026-10-01&to=2026-10-28&offset=-?\d+$/,
    );

    await userEvent.click(screen.getByText("PC-01（张三）"));
    expect(openDevice).toHaveBeenCalledWith("d1");

    await userEvent.click(screen.getByRole("button", { name: /下载 Markdown/ }));
    expect(download).toHaveBeenCalledWith(
      expect.stringMatching(/^\/api\/reports\/compliance\.md\?from=2026-10-01&to=2026-10-28/),
      "终端合规报表-2026-10-01至2026-10-28.md",
      "报表",
    );

    await userEvent.click(screen.getByText("上月"));
    const last = periodOf("lastMonth");
    await waitFor(() =>
      expect(urls.some((u) => u.includes(`from=${last.from}&to=${last.to}`))).toBe(true),
    );
  });
});
