import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { VerdictHistory, VerdictTrendChart } from "../src/components";

describe("verdict trend", () => {
  it("draws one bar per day and summarizes today for screen readers", () => {
    const { container } = render(
      <VerdictTrendChart
        days={[
          { date: "2026-10-16", pass: 1, fail: 1, unknown: 0 },
          { date: "2026-10-17", pass: 2, fail: 0, unknown: 1 },
        ]}
      />,
    );
    expect(container.querySelectorAll("svg > g")).toHaveLength(2);
    expect(screen.getByRole("img").getAttribute("aria-label")).toContain(
      "今天通过 2 台，不通过 0 台，无法判断 1 台",
    );
  });

  it("says so when nothing was recorded yet", () => {
    render(<VerdictTrendChart days={[{ date: "2026-10-17", pass: 0, fail: 0, unknown: 0 }]} />);
    expect(screen.getByText("暂无历史结论")).toBeTruthy();
  });

  it("lists a device's changes newest first", () => {
    const { container } = render(
      <VerdictHistory
        changes={[
          {
            deviceId: "d",
            at: "2026-10-16T01:00:00Z",
            verdict: "PASS",
            violationCount: 0,
            policyVersion: 3,
          },
          {
            deviceId: "d",
            at: "2026-10-17T01:00:00Z",
            verdict: "FAIL",
            violationCount: 2,
            policyVersion: 3,
          },
        ]}
      />,
    );
    const items = screen.getAllByText(/策略 v3/);
    expect(items).toHaveLength(2);
    expect(screen.getByText("2 个违规对象")).toBeTruthy();
    const tags = [...container.querySelectorAll(".ant-tag")].map((t) => t.textContent);
    expect(tags).toEqual(["不通过", "通过"]);
  });
});
