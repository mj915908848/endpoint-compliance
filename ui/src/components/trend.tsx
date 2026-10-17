import { Space, Timeline, Typography } from "antd";
import type { TrendDay, VerdictChange } from "../types";
import { Empty, time, VerdictTag } from "./common";

const series = [
  { key: "fail", label: "不通过", color: "var(--danger)" },
  { key: "unknown", label: "无法判断", color: "var(--warning)" },
  { key: "pass", label: "通过", color: "var(--good)" },
] as const;

/** The browser's time zone as minutes east of UTC, which the trend API counts days in. */
export const trendOffset = () => -new Date().getTimezoneOffset();

/**
 * One stacked bar per day: devices that failed at the bottom, then unknown, then passed. Counts are each device's
 * stored verdict at the end of the day, whether or not it was online.
 */
export function VerdictTrendChart({ days }: { days: TrendDay[] }) {
  const max = Math.max(1, ...days.map((d) => d.pass + d.fail + d.unknown));
  if (days.every((d) => d.pass + d.fail + d.unknown === 0))
    return <Empty title="暂无历史结论">终端完成检查后开始记录。</Empty>;
  const width = 640,
    height = 160,
    gap = 2,
    bar = width / days.length - gap;
  const today = days[days.length - 1];
  return (
    <Space orientation="vertical" size={8} style={{ width: "100%" }}>
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
      <Space size={16} wrap>
        {series.map((s) => (
          <Typography.Text key={s.key} type="secondary" style={{ fontSize: 12 }}>
            <span className="legend-dot" style={{ background: s.color }} />
            {s.label}
          </Typography.Text>
        ))}
        <Typography.Text type="secondary" style={{ fontSize: 12 }}>
          {days[0].date} 至 {today.date}，每天按当天结束时的结论计数，失联终端按其最后结论计
        </Typography.Text>
      </Space>
    </Space>
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
