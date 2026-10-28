import { useState } from "react";
import { useSearchParams } from "react-router";
import { App, Button, Col, Flex, Input, Row, Segmented, Space, Table, Tag, Typography } from "antd";
import { DownloadOutlined, PrinterOutlined } from "@ant-design/icons";
import { downloadFile } from "../api";
import {
  alertTypeLabel,
  deviceName,
  Empty,
  errorText,
  Fresh,
  Metric,
  PageHeading,
  Panel,
  time,
  trendOffset,
  UpdatedAt,
  VerdictTrendChart,
} from "../components";
import { useResource } from "../useResource";
import type { LingeringDevice, PeriodReport, ReportGroup, ReportIssue } from "../types";

/** Failing this many days or more counts as not dealt with, as on the server. */
export const LINGERING_DAYS = 7;

export type PeriodKind = "last7" | "thisWeek" | "lastWeek" | "thisMonth" | "lastMonth";

const periodLabels: Record<PeriodKind, string> = {
  last7: "最近 7 天",
  thisWeek: "本周",
  lastWeek: "上周",
  thisMonth: "本月",
  lastMonth: "上月",
};

/** A local date as yyyy-MM-dd. */
export const isoDay = (d: Date) =>
  `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;

/** The days a period covers, weeks starting on Monday, in the browser's time zone. */
export function periodOf(kind: PeriodKind, today = new Date()): { from: string; to: string } {
  const day = (offset: number, base = today) =>
    new Date(base.getFullYear(), base.getMonth(), base.getDate() + offset);
  const monday = day(-((today.getDay() + 6) % 7));
  switch (kind) {
    case "last7":
      return { from: isoDay(day(-6)), to: isoDay(today) };
    case "thisWeek":
      return { from: isoDay(monday), to: isoDay(today) };
    case "lastWeek":
      return { from: isoDay(day(-7, monday)), to: isoDay(day(-1, monday)) };
    case "thisMonth":
      return {
        from: isoDay(new Date(today.getFullYear(), today.getMonth(), 1)),
        to: isoDay(today),
      };
    case "lastMonth":
      return {
        from: isoDay(new Date(today.getFullYear(), today.getMonth() - 1, 1)),
        to: isoDay(new Date(today.getFullYear(), today.getMonth(), 0)),
      };
  }
}

const rate = (pass: number, devices: number) =>
  devices === 0 ? "—" : `${(Math.round((pass / devices) * 1000) / 10).toString()}%`;

const groupName = (g: string) => g || "未分组";

/** How the compliance rate moved from the start of the period to its end. */
function rateChange(r: PeriodReport) {
  if (!r.start.devices || !r.end.devices) return "期初没有结论";
  const points = (r.end.pass / r.end.devices - r.start.pass / r.start.devices) * 100;
  if (Math.abs(points) < 0.05) return "与期初持平";
  return `较期初${points > 0 ? "上升" : "下降"} ${Math.abs(Math.round(points * 10) / 10)} 个百分点`;
}

const daysSince = (at: string, now: string) =>
  Math.floor((Date.parse(now) - Date.parse(at)) / 86_400_000);

/**
 * Compliance over a period: verdicts at its end and each day, groups by compliance, the problems alerts were raised
 * for, and devices still failing. Printed or saved as PDF from the browser, or downloaded as Markdown.
 */
export function ReportsPage({ openDevice }: { openDevice: (id: string) => void }) {
  const { message } = App.useApp();
  const [params, setParams] = useSearchParams();
  const initial = periodOf("thisMonth");
  const from = params.get("from") ?? initial.from,
    to = params.get("to") ?? initial.to;
  const kind = (Object.keys(periodLabels) as PeriodKind[]).find((k) => {
    const p = periodOf(k);
    return p.from === from && p.to === to;
  });
  const [exporting, setExporting] = useState(false);
  const query = `from=${from}&to=${to}&offset=${trendOffset()}`;
  const report = useResource<PeriodReport>(`/api/reports/compliance?${query}`);
  const r = report.data;
  const today = isoDay(new Date());

  const choose = (next: { from: string; to: string }) => setParams(next, { replace: true });

  async function exportMarkdown() {
    setExporting(true);
    try {
      await downloadFile(
        `/api/reports/compliance.md?${query}`,
        `终端合规报表-${from}至${to}.md`,
        "报表",
      );
    } catch (e) {
      void message.error(errorText(e));
    } finally {
      setExporting(false);
    }
  }

  return (
    <>
      <PageHeading
        title="合规报表"
        description={`${from === to ? from : `${from} 至 ${to}`}。按每天结束时各终端的结论统计，可打印、另存为 PDF 或下载 Markdown。`}
        extra={<UpdatedAt at={report.updatedAt} refreshing={report.refreshing} />}
        action={
          <Space className="no-print">
            <Button icon={<PrinterOutlined />} onClick={() => window.print()} disabled={!r}>
              打印 / 存为 PDF
            </Button>
            <Button
              icon={<DownloadOutlined />}
              loading={exporting}
              onClick={exportMarkdown}
              disabled={!r}
            >
              下载 Markdown
            </Button>
          </Space>
        }
      />
      <Flex className="no-print report-period" gap={12} wrap align="center">
        <Segmented<string>
          aria-label="时间段"
          value={kind ?? "custom"}
          onChange={(v) => v !== "custom" && choose(periodOf(v as PeriodKind))}
          options={[
            ...(Object.keys(periodLabels) as PeriodKind[]).map((k) => ({
              value: k,
              label: periodLabels[k],
            })),
            { value: "custom", label: "自定义", disabled: true },
          ]}
        />
        <Space.Compact>
          <Input
            type="date"
            aria-label="开始日期"
            value={from}
            max={to}
            onChange={(e) => e.target.value && choose({ from: e.target.value, to })}
          />
          <Input
            type="date"
            aria-label="结束日期"
            value={to}
            min={from}
            max={today}
            onChange={(e) => e.target.value && choose({ from, to: e.target.value })}
          />
        </Space.Compact>
      </Flex>
      <Fresh error={report.error} loading={report.loading}>
        {r && <ReportBody report={r} today={today} openDevice={openDevice} />}
      </Fresh>
    </>
  );
}

function ReportBody({
  report: r,
  today,
  openDevice,
}: {
  report: PeriodReport;
  today: string;
  openDevice: (id: string) => void;
}) {
  const overdue = r.lingering.filter(
    (d) => daysSince(d.since, r.generatedAt) >= LINGERING_DAYS,
  ).length;
  return (
    <Space className="report-body" orientation="vertical" size={16} style={{ width: "100%" }}>
      <Row gutter={[16, 16]}>
        <Col xs={12} lg={6}>
          <Metric
            label="期末合规率"
            value={rate(r.end.pass, r.end.devices)}
            tone="neutral"
            caption={rateChange(r)}
          />
        </Col>
        <Col xs={12} lg={6}>
          <Metric label="通过" value={r.end.pass} tone="good" caption={`共 ${r.end.devices} 台`} />
        </Col>
        <Col xs={12} lg={6}>
          <Metric
            label="不通过"
            value={r.end.fail}
            tone="danger"
            caption={overdue ? `${overdue} 台超过 ${LINGERING_DAYS} 天未整改` : "没有超期未整改"}
          />
        </Col>
        <Col xs={12} lg={6}>
          <Metric
            label="无法判断"
            value={r.end.unknown}
            tone="warning"
            caption="检查不完整或已失联"
          />
        </Col>
      </Row>
      <Panel title="每日趋势">
        <VerdictTrendChart days={r.days} endLabel={r.to === today ? "今天" : r.to.slice(5)} />
      </Panel>
      <Row gutter={[16, 16]}>
        <Col xs={24} xl={12}>
          <Panel title="分组排名">
            <GroupTable groups={r.groups} />
          </Panel>
        </Col>
        <Col xs={24} xl={12}>
          <Panel title="最常见的问题">
            <IssueTable issues={r.issues} />
          </Panel>
        </Col>
      </Row>
      <Panel title={`长期未整改（${r.lingering.length}）`}>
        <LingeringTable devices={r.lingering} now={r.generatedAt} openDevice={openDevice} />
      </Panel>
      <Panel title="期间新增告警">
        {r.alertTypes.length ? (
          <Space size={[24, 8]} wrap>
            {r.alertTypes.map((t) => (
              <span key={t.type}>
                {alertTypeLabel(t.type)} <Typography.Text strong>{t.opened}</Typography.Text> 条
                <Typography.Text type="secondary">（{t.devices} 台）</Typography.Text>
              </span>
            ))}
          </Space>
        ) : (
          <Typography.Text type="secondary">期间没有新增告警。</Typography.Text>
        )}
      </Panel>
      <Typography.Text type="secondary" style={{ fontSize: 12 }}>
        生成于 {time(r.generatedAt)}
        。分组按终端现在所在的分组统计；归档的终端不计入；告警统计包含期间任何时候未恢复的告警，超过保留期限被清理的不计入。
      </Typography.Text>
    </Space>
  );
}

function GroupTable({ groups }: { groups: ReportGroup[] }) {
  if (!groups.length) return <Empty title="期末没有终端结论" />;
  return (
    <Table<ReportGroup>
      size="small"
      rowKey="group"
      dataSource={groups}
      pagination={false}
      scroll={{ x: 420 }}
      columns={[
        { title: "分组", key: "group", render: (_, g) => groupName(g.group) },
        { title: "终端", dataIndex: "devices", width: 64 },
        { title: "通过", dataIndex: "pass", width: 64 },
        {
          title: "不通过",
          key: "fail",
          width: 72,
          render: (_, g) =>
            g.fail ? <Typography.Text type="danger">{g.fail}</Typography.Text> : 0,
        },
        { title: "无法判断", dataIndex: "unknown", width: 84 },
        { title: "合规率", key: "rate", width: 80, render: (_, g) => rate(g.pass, g.devices) },
      ]}
    />
  );
}

function IssueTable({ issues }: { issues: ReportIssue[] }) {
  if (!issues.length)
    return <Empty title="期间没有违规、基线、敏感文件、防篡改、设备健康或拦截告警" />;
  return (
    <Table<ReportIssue>
      size="small"
      rowKey={(i) => i.type + "|" + i.subject}
      dataSource={issues}
      pagination={false}
      scroll={{ x: 420 }}
      columns={[
        { title: "问题", dataIndex: "subject" },
        {
          title: "类型",
          key: "type",
          width: 110,
          render: (_, i) => <Tag>{alertTypeLabel(i.type)}</Tag>,
        },
        { title: "涉及终端", key: "devices", width: 84, render: (_, i) => `${i.devices} 台` },
        { title: "告警", key: "alerts", width: 64, render: (_, i) => `${i.alerts} 条` },
      ]}
    />
  );
}

function LingeringTable({
  devices,
  now,
  openDevice,
}: {
  devices: LingeringDevice[];
  now: string;
  openDevice: (id: string) => void;
}) {
  if (!devices.length) return <Empty title="目前没有不通过的终端" />;
  return (
    <Table<LingeringDevice>
      size="small"
      rowKey="deviceId"
      dataSource={devices}
      pagination={{ pageSize: 20, hideOnSinglePage: true, showSizeChanger: false }}
      scroll={{ x: 560 }}
      columns={[
        {
          title: "终端",
          key: "device",
          render: (_, d) => (
            <Typography.Link onClick={() => openDevice(d.deviceId)}>
              {deviceName(d)}
            </Typography.Link>
          ),
        },
        { title: "分组", key: "group", width: 120, render: (_, d) => groupName(d.group) },
        { title: "开始不通过", key: "since", width: 170, render: (_, d) => time(d.since) },
        {
          title: "持续",
          key: "days",
          width: 110,
          render: (_, d) => {
            const days = daysSince(d.since, now);
            return days >= LINGERING_DAYS ? (
              <Tag color="red">{days} 天，超期</Tag>
            ) : (
              `${days < 1 ? "不到 1" : days} 天`
            );
          },
        },
        { title: "违规对象", dataIndex: "violationCount", width: 84 },
      ]}
    />
  );
}
