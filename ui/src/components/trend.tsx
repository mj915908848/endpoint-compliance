import { Flex, Space, Timeline, Typography } from "antd";
import type { TrendDay, VerdictChange } from "../types";
import { Empty, time, VerdictTag } from "./common";

const series = [
  { key: "fail", label: "不通过", color: "var(--danger)" },
  { key: "unknown", label: "无法判断", color: "var(--warning)" },
  { key: "pass", label: "通过", color: "var(--good)" },
] as const;

/** The browser's time zone as minutes east of UTC, which the trend API counts days in. */
/** Fewer recorded days than this are summed up in a line; a handful of bars says nothing about a trend. */
const MinTrendDays = 7;

export const trendOffset = () => -new Date().getTimezoneOffset();

/**
 * One stacked bar per day: devices that failed at the bottom, then unknown, then passed. Counts are each device's
 * stored verdict at the end of the day, whether or not it was online.
 */
export function VerdictTrendChart({
  days: all,
  endLabel = "今天",
}: {
  days: TrendDay[];
  /** What the last day is called under the chart. */
  endLabel?: string;
}) {
  // Days before the first recorded verdict are left out rather than drawn as empty bars.
  const first = all.findIndex((d) => d.pass + d.fail + d.unknown > 0);
  if (first < 0)
    return (
      <Typography.Text type="secondary">暂无历史结论，终端完成检查后开始记录。</Typography.Text>
    );
  const days = all.slice(first);
  const today = days[days.length - 1];
  if (days.length < MinTrendDays)
    return (
      <Typography.Text type="secondary">
        已记录 {days.length} 天。今天通过 {today.pass} 台，不通过 {today.fail} 台，无法判断{" "}
        {today.unknown} 台。满 {MinTrendDays} 天后显示趋势图。
      </Typography.Text>
    );
  const max = Math.max(1, ...days.map((d) => d.pass + d.fail + d.unknown));
  const width = 640,
    height = 96,
    gap = 2,
    bar = width / days.length - gap;
  return (
    <Space orientation="vertical" size={6} style={{ width: "100%" }}>
      <svg
        viewBox={`0 0 ${width} ${height}`}
        width="100%"
        height={height}
        preserveAspectRatio="none"
        role="img"
        aria-label={`近 ${days.length} 天合规趋势；今天通过 ${today.pass} 台，不通过 ${today.fail} 台，无法判断 ${today.unknown} 台`}
      >
        {days.map((d, i) => {
          let y = height;
          return (
            <g key={d.date}>
              <title>{`${d.date}：通过 ${d.pass}，不通过 ${d.fail}，无法判断 ${d.unknown}`}</title>
              <rect x={i * (bar + gap)} y={0} width={bar} height={height} fill="var(--track)" />
              {series.map((s) => {
                const h = (d[s.key] / max) * height;
                y -= h;
                return h > 0 ? (
                  <rect
                    key={s.key}
                    x={i * (bar + gap)}
                    y={y}
                    width={bar}
                    height={h}
                    fill={s.color}
                  />
                ) : null;
              })}
            </g>
          );
        })}
      </svg>
      <Flex justify="space-between" className="trend-axis">
        <span>{days[0].date.slice(5)}</span>
        <span>{endLabel}</span>
      </Flex>
      <Space size={16} wrap>
        {series.map((s) => (
          <Typography.Text key={s.key} type="secondary" style={{ fontSize: 12 }}>
            <span className="legend-dot" style={{ background: s.color }} />
            {s.label}
          </Typography.Text>
        ))}
        <Typography.Text type="secondary" style={{ fontSize: 12 }}>
          每天按当天结束时的结论计数，失联终端按其最后结论计
        </Typography.Text>
      </Space>
    </Space>
  );
}

/** Share of devices that passed at the end of each day, as a line with its area filled in. */
export function ComplianceRateChart({ days: all }: { days: TrendDay[] }) {
  const first = all.findIndex((d) => d.pass + d.fail + d.unknown > 0);
  if (first < 0)
    return (
      <Typography.Text type="secondary">暂无历史结论，终端完成检查后开始记录。</Typography.Text>
    );
  const days = all.slice(first);
  const rate = (d: TrendDay) => {
    const total = d.pass + d.fail + d.unknown;
    return total ? d.pass / total : 0;
  };
  const today = days[days.length - 1];
  if (days.length < MinTrendDays)
    return (
      <Typography.Text type="secondary">
        已记录 {days.length} 天，今天合规率 {Math.round(rate(today) * 100)}%。满 {MinTrendDays}{" "}
        天后显示趋势图。
      </Typography.Text>
    );
  const width = 600,
    height = 150,
    step = width / (days.length - 1);
  const points = days.map(
    (d, i) => `${(i * step).toFixed(1)},${(height - rate(d) * height).toFixed(1)}`,
  );
  const line = `M${points.join(" L")}`;
  return (
    <div className="rate-chart">
      <div className="rate-chart-axis trend-axis" aria-hidden="true">
        <span>100%</span>
        <span>50%</span>
        <span>0%</span>
      </div>
      <div className="rate-chart-plot">
        <svg
          viewBox={`0 0 ${width} ${height}`}
          width="100%"
          height={height}
          preserveAspectRatio="none"
          role="img"
          aria-label={`近 ${days.length} 天合规率，从 ${Math.round(rate(days[0]) * 100)}% 到今天 ${Math.round(rate(today) * 100)}%`}
        >
          {[0, 0.5, 1].map((y) => (
            <line
              key={y}
              x1={0}
              x2={width}
              y1={y * height}
              y2={y * height}
              stroke="var(--line)"
              vectorEffect="non-scaling-stroke"
            />
          ))}
          <path
            d={`${line} L${width},${height} L0,${height} Z`}
            fill="var(--primary)"
            opacity={0.08}
          />
          <path
            d={line}
            fill="none"
            stroke="var(--primary)"
            strokeWidth={2.2}
            strokeLinejoin="round"
            vectorEffect="non-scaling-stroke"
          />
          {days.map((d, i) => (
            <rect
              key={d.date}
              x={i * step - step / 2}
              y={0}
              width={step}
              height={height}
              fill="transparent"
            >
              <title>{`${d.date}：合规率 ${Math.round(rate(d) * 100)}%（通过 ${d.pass}，不通过 ${d.fail}，无法判断 ${d.unknown}）`}</title>
            </rect>
          ))}
        </svg>
        <Flex justify="space-between" className="trend-axis">
          <span>{days[0].date.slice(5)}</span>
          <span>今天</span>
        </Flex>
      </div>
    </div>
  );
}

/** A device's verdict changes, newest first. */
export function VerdictHistory({ changes }: { changes: VerdictChange[] }) {
  if (changes.length === 0) return <Empty title="暂无结论变化记录" />;
  return (
    <Timeline
      items={[...changes].reverse().map((c) => ({
        key: c.at,
        children: (
          <Space size={8} wrap>
            <span>{time(c.at)}</span>
            <VerdictTag verdict={c.verdict} />
            {c.violationCount > 0 && <span>{c.violationCount} 个违规对象</span>}
            <Typography.Text type="secondary">策略 v{c.policyVersion}</Typography.Text>
          </Space>
        ),
      }))}
    />
  );
}
