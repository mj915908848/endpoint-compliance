import { useMemo } from "react";
import { useResource } from "../useResource";
import {
  Badge,
  Empty,
  OverviewGuide,
  time,
  Panel,
  Fresh,
  Metric,
  PageHeading,
  DeviceTable,
} from "../components";
import type { Alert, DeviceSummary } from "../types";

export function Overview({
  openDevice,
  openAlerts,
  revision,
}: {
  openDevice: (id: string) => void;
  openAlerts: () => void;
  revision: number;
}) {
  const devices = useResource<DeviceSummary[]>("/api/devices", revision),
    alerts = useResource<Alert[]>("/api/alerts", revision);
  const stats = useMemo(() => {
    const all = devices.data ?? [];
    return {
      pass: all.filter((d) => d.onlineState === "Online" && d.currentVerdict === "PASS").length,
      fail: all.filter((d) => d.onlineState === "Online" && d.currentVerdict === "FAIL").length,
      unknown: all.filter((d) => d.onlineState === "Online" && d.currentVerdict === "UNKNOWN")
        .length,
      offline: all.filter((d) => d.onlineState !== "Online").length,
    };
  }, [devices.data]);
  return (
    <>
      <PageHeading
        kicker="OPERATIONS / OVERVIEW"
        title="终端合规总览"
        description="以管理端当前事实为准。失联设备单列，上次结论只作为历史记录。"
      />
      <Fresh error={devices.error} loading={devices.loading}>
        <OverviewGuide devices={devices.data ?? []} />
        <div className="metric-grid">
          <Metric label="当前范围内通过" value={stats.pass} tone="good" caption="仅当前在线终端" />
          <Metric label="当前不通过" value={stats.fail} tone="danger" caption="确认违规证据" />
          <Metric
            label="无法判断"
            value={stats.unknown}
            tone="warning"
            caption="检查或执行能力不足"
          />
          <Metric
            label="失联 / 疑似失联"
            value={stats.offline}
            tone="neutral"
            caption="历史通过不计入当前通过"
          />
        </div>
        <div className="overview-grid">
          <Panel eyebrow="DEVICE FLEET" title="需要关注的终端">
            <DeviceTable
              devices={(devices.data ?? [])
                .filter((d) => d.currentVerdict !== "PASS" || d.onlineState !== "Online")
                .slice(0, 8)}
              onSelect={openDevice}
            />
            {devices.data?.length === 0 && null}
          </Panel>
          <Panel
            eyebrow="ALERTS"
            title="未恢复告警"
            actions={
              <button className="link-button" onClick={openAlerts}>
                查看全部 →
              </button>
            }
          >
            <Fresh error={alerts.error} loading={alerts.loading}>
              {(alerts.data ?? []).filter((a) => a.state !== "Resolved").slice(0, 5).length ===
              0 ? (
                <Empty title="当前没有持续告警" />
              ) : (
                <div className="compact-list">
                  {(alerts.data ?? [])
                    .filter((a) => a.state !== "Resolved")
                    .slice(0, 5)
                    .map((a) => (
                      <div className="compact-alert" key={a.id}>
                        <Badge tone={a.type === "Violation" ? "danger" : "warning"}>
                          {a.type === "Violation"
                            ? "确认违规"
                            : a.type === "BlockedAttempt"
                              ? "已阻止尝试"
                              : a.type === "Offline"
                                ? "失联"
                                : "健康与线索"}
                        </Badge>
                        <strong>{a.summary}</strong>
                        <small>
                          {a.hostName} · {time(a.lastSeen)} {a.acknowledged ? "· 已确认" : ""}
                        </small>
                      </div>
                    ))}
                </div>
              )}
            </Fresh>
          </Panel>
        </div>
      </Fresh>
    </>
  );
}
