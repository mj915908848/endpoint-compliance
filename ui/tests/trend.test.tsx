import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { ComplianceRateChart, VerdictHistory, VerdictTrendChart } from "../src/components";

describe("verdict trend", () => {
  const day = (n: number, pass: number, fail = 0, unknown = 0) => ({
    date: `2026-10-${String(n).padStart(2, "0")}`,
    pass,
    fail,
    unknown,
  });

  it("draws one bar per day from the first recorded one and summarizes today for screen readers", () => {
    const days = [
      day(1, 0),
      day(2, 0),
      ...[3, 4, 5, 6, 7, 8].map((n) => day(n, 1, 1)),
      day(9, 2, 0, 1),
    ];
    const { container } = render(<VerdictTrendChart days={days} />);
    expect(container.querySelectorAll("svg > g")).toHaveLength(7);
    expect(screen.getByRole("img").getAttribute("aria-label")).toContain(
      "今天通过 2 台，不通过 0 台，无法判断 1 台",
    );
  });

  it("draws the share passing each day from the first recorded one", () => {
    const days = [day(1, 0), ...[2, 3, 4, 5, 6, 7].map((n) => day(n, 1, 1)), day(8, 3, 0, 1)];
    render(<ComplianceRateChart days={days} />);
    expect(screen.getByRole("img").getAttribute("aria-label")).toBe(
      "近 7 天合规率，从 50% 到今天 75%",
    );
  });

  it("sums up a few recorded days in a line instead of a chart", () => {
    const { container } = render(
      <VerdictTrendChart days={[day(16, 0), day(17, 1, 1), day(18, 2, 0, 1)]} />,
    );
    expect(container.querySelector("svg")).toBeNull();
    expect(
      screen.getByText(
        /已记录 2 天。今天通过 2 台，不通过 0 台，无法判断 1 台。满 7 天后显示趋势图/,
      ),
    ).toBeTruthy();
  });

  it("says so when nothing was recorded yet", () => {
    render(<VerdictTrendChart days={[day(17, 0)]} />);
    expect(screen.getByText(/暂无历史结论/)).toBeTruthy();
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
