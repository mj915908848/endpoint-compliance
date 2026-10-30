import { useMemo, type ReactNode } from "react";
import { Button, Card, Col, Row, Space } from "antd";
import { RightOutlined } from "@ant-design/icons";
import { useResource } from "../useResource";
import {
  ComplianceRateChart,
  DeviceAlertRow,
  DeviceTable,
  Empty,
  Fresh,
  groupByDevice,
  Metric,
  OverviewGuide,
  PageHeading,
  Panel,
  trendOffset,
  UpdatedAt,
} from "../components";
import type { Alert, DeviceSummary, StoredException, TrendDay } from "../types";

/** The share of all devices that pass now, drawn as a ring. */
function ComplianceRing({ pass, total }: { pass: number; total: number }) {
  const percent = total ? Math.round((pass / total) * 100) : 0;
  return (
    <div className="summary-rate">
      <svg width="76" height="76" viewBox="0 0 36 36" role="img" aria-label={`合规率 ${percent}%`}>
        <circle cx="18" cy="18" r="15.9" fill="none" stroke="var(--track)" strokeWidth="3.4" />
        {percent > 0 && (
          <circle
            cx="18"
            cy="18"
            r="15.9"
            fill="none"
            stroke="var(--primary)"
            strokeWidth="3.4"
            strokeDasharray={`${percent} 100`}
            strokeLinecap="round"
            transform="rotate(-90 18 18)"
          />
        )}
      </svg>
      <div>
        <div className="summary-rate-label">合规率</div>
        <div className="summary-rate-value">
          {percent}
          <small>%</small>
        </div>
        <div className="summary-rate-caption">
          {total} 台终端中 {pass} 台通过
        </div>
      </div>
    </div>
  );
}

/** One line of the to-do card: a count in a tinted tile, what it counts, and where it leads. */
function TodoRow({
  count,
  tone,
  title,
  caption,
  onClick,
}: {
  count: number;
  tone: "danger" | "warning" | "primary";
  title: string;
  caption: ReactNode;
  onClick: () => void;
}) {
  return (
    <button type="button" className="todo-row" onClick={onClick}>
      <span className={`todo-count todo-${tone}`}>{count}</span>
      <span className="todo-text">
        <strong>{title}</strong>
        <span>{caption}</span>
      </span>
      <RightOutlined className="todo-arrow" />
    </button>
  );
}

export function Overview({
  openDevice,
  openDevices,
  openAlerts,
  openExceptions,
}: {
  openDevice: (id: string) => void;
  /** The device list, filtered as in its status menu. */
  openDevices: (filter: string) => void;
  openAlerts: () => void;
  openExceptions: () => void;
}) {
  const devices = useResource<DeviceSummary[]>("/api/devices"),
    alerts = useResource<Alert[]>("/api/alerts"),
    exceptions = useResource<StoredException[]>("/api/exceptions"),
    trend = useResource<TrendDay[]>(`/api/devices/trend?days=30&offset=${trendOffset()}`);
  const stats = useMemo(() => {
    const all = devices.data ?? [];
    const online = all.filter((d) => d.onlineState === "Online");
    return {
      total: all.length,
      pass: online.filter((d) => d.currentVerdict === "PASS").length,
      fail: online.filter((d) => d.currentVerdict === "FAIL").length,
      unknown: online.filter((d) => d.currentVerdict === "UNKNOWN").length,
      offline: all.length - online.length,
    };
  }, [devices.data]);
  const attention = (devices.data ?? []).filter(
    (d) => d.currentVerdict !== "PASS" || d.onlineState !== "Online",
  );
  const openAlertList = (alerts.data ?? []).filter((a) => a.state !== "Resolved");
  const openByDevice = groupByDevice(openAlertList, devices.data ?? []);
  const pending = (exceptions.data ?? []).filter((x) => x.status === "Pending");
  return (
    <>
      <PageHeading
        title="总览"
        description={
          <>
            {stats.total} 台终端 · 失联终端单独统计，其上次结论仅作历史参考{" "}
            <UpdatedAt at={devices.updatedAt} refreshing={devices.refreshing} />
          </>
        }
        action={
          openByDevice.length > 0 && (
            <Button type="primary" onClick={openAlerts}>
              处理 {openByDevice.length} 台终端的告警
            </Button>
          )
        }
      />
      <Fresh error={devices.error} loading={devices.loading}>
        <Space orientation="vertical" size={16} style={{ width: "100%" }}>
          <OverviewGuide devices={devices.data ?? []} />
          <Card className="panel summary">
            <ComplianceRing pass={stats.pass} total={stats.total} />
            <div className="summary-metrics">
              <Metric
                label="通过"
                value={stats.pass}
                tone="good"
                caption="在线且全部检查通过"
                onClick={() => openDevices("PASS")}
              />
              <Metric
                label="不通过"
                value={stats.fail}
                tone="danger"
                caption="存在确认违规"
                onClick={() => openDevices("FAIL")}
              />
              <Metric
                label="无法判断"
                onClick={() => openDevices("UNKNOWN")}
                value={stats.unknown}
                tone="warning"
                caption="检查不完整或防护未验证"
              />
              <Metric
                label="失联 / 疑似失联"
                onClick={() => openDevices("offline")}
                value={stats.offline}
                tone="neutral"
                caption="不计入当前通过"
              />
            </div>
          </Card>
          <Row gutter={[16, 16]}>
            <Col xs={24} xl={16}>
              <Panel title="近 30 天合规率">
                <Fresh error={trend.error} loading={trend.loading}>
                  {trend.data && <ComplianceRateChart days={trend.data} />}
                </Fresh>
              </Panel>
            </Col>
            <Col xs={24} xl={8}>
              <Panel title="待处理">
                <TodoRow
                  count={openByDevice.length}
                  tone="danger"
                  title="未恢复的告警"
                  caption={
                    openByDevice.length ? `${openAlertList.length} 条告警` : "没有未恢复的告警"
                  }
                  onClick={openAlerts}
                />
                {!exceptions.error && (
                  <TodoRow
                    count={pending.length}
                    tone="warning"
                    title="待审批的例外"
                    caption={
                      pending.length
                        ? `${pending[0].requestedBy || pending[0].hostName} 申请 ${pending[0].label}`
                        : "没有待审批的申请"
                    }
                    onClick={openExceptions}
                  />
                )}
                <TodoRow
                  count={attention.length}
                  tone="primary"
                  title="需要关注的终端"
                  caption="未通过、无法判断或不在线"
                  onClick={() => openDevices("attention")}
                />
              </Panel>
            </Col>
          </Row>
          <Row gutter={[16, 16]}>
            <Col xs={24} xl={12}>
              <Panel
                title={`需要关注的终端（${attention.length}）`}
                actions={
                  attention.length > 0 && (
                    <Button
                      type="link"
                      onClick={() => openDevices("attention")}
                      style={{ paddingInline: 0 }}
                    >
                      查看全部
                    </Button>
                  )
                }
              >
                <DeviceTable
                  devices={attention.slice(0, 8)}
                  onSelect={openDevice}
                  pageSize={false}
                  compact
                />
              </Panel>
            </Col>
            <Col xs={24} xl={12}>
              <Panel
                title={
                  openByDevice.length ? `未恢复告警（${openByDevice.length} 台终端）` : "未恢复告警"
                }
                actions={
                  <Button type="link" onClick={openAlerts} style={{ paddingInline: 0 }}>
                    查看全部
                  </Button>
                }
              >
                <Fresh error={alerts.error} loading={alerts.loading}>
                  {openByDevice.length === 0 ? (
                    <Empty title="当前没有未恢复的告警" />
                  ) : (
                    <>
                      {openByDevice.slice(0, 7).map((d) => (
                        <DeviceAlertRow
                          key={d.id}
                          device={d}
                          onOpen={() => openDevice(d.id)}
                          compact
                        />
                      ))}
                      {openByDevice.length > 7 && (
                        <Button type="link" onClick={openAlerts} style={{ paddingInline: 0 }}>
                          还有 {openByDevice.length - 7} 台终端有未恢复告警
                        </Button>
                      )}
                    </>
                  )}
                </Fresh>
              </Panel>
            </Col>
          </Row>
        </Space>
      </Fresh>
    </>
  );
}
