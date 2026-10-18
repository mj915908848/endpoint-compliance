import { useState } from "react";
import { Button, Segmented } from "antd";
import {
  AlertRow,
  bySeverity,
  DeviceAlertRow,
  Empty,
  groupByDevice,
  Panel,
  alertTone,
} from "../components";
import type { Alert, DeviceSummary } from "../types";

export const variant = () => new URLSearchParams(location.search).get("v");

const name = (a: Alert, devices: DeviceSummary[]) => {
  const note = devices.find((d) => d.id === a.deviceId)?.note;
  return note ? `${a.hostName} · ${note}` : a.hostName;
};

const kind = (a: Alert) =>
  a.state === "Resolved"
    ? "resolved"
    : a.type === "Violation"
      ? "violation"
      : a.type === "SensitiveFile"
        ? "sensitive"
        : "other";

export function AlertsA({
  alerts,
  devices,
  openDevice,
  ack,
}: {
  alerts: Alert[];
  devices: DeviceSummary[];
  openDevice: (id: string) => void;
  ack?: (ids: string[]) => Promise<void>;
}) {
  const [filter, setFilter] = useState("open");
  const n = (k: string) => alerts.filter((a) => kind(a) === k).length;
  const open = alerts.filter((a) => a.state !== "Resolved");
  const shown = (filter === "open" ? open : alerts.filter((a) => kind(a) === filter)).sort(bySeverity);
  const unacked = shown.filter((a) => !a.acknowledged && a.state !== "Resolved").map((a) => a.id);
  return (
    <Panel
      title={
        <Segmented
          value={filter}
          onChange={setFilter}
          options={[
            { value: "open", label: `未恢复 ${open.length}` },
            { value: "violation", label: `违规 ${n("violation")}` },
            { value: "sensitive", label: `敏感文件 ${n("sensitive")}` },
            { value: "other", label: `失联与健康 ${n("other")}` },
            { value: "resolved", label: "已恢复" },
          ]}
        />
      }
      actions={
        ack && unacked.length > 0 ? (
          <Button onClick={() => ack(unacked)}>全部确认（{unacked.length}）</Button>
        ) : null
      }
    >
      {shown.length ? (
        shown.map((a) => (
          <AlertRow
            key={a.id}
            alert={a}
            device={name(a, devices)}
            onOpen={() => openDevice(a.deviceId)}
            onAck={ack}
          />
        ))
      ) : (
        <Empty title="没有符合条件的告警" />
      )}
    </Panel>
  );
}

export function OverviewAlertsA({
  alerts,
  devices,
  openDevice,
  openAlerts,
}: {
  alerts: Alert[];
  devices: DeviceSummary[];
  openDevice: (id: string) => void;
  openAlerts: () => void;
}) {
  const open = alerts.filter((a) => a.state !== "Resolved").sort(bySeverity);
  return (
    <Panel
      title={`未恢复告警（${open.length}）`}
      actions={
        <Button type="link" onClick={openAlerts} style={{ paddingInline: 0 }}>
          查看全部
        </Button>
      }
    >
      {open.length === 0 ? (
        <Empty title="当前没有未恢复的告警" />
      ) : (
        <div className="overview-alerts">
          {open.slice(0, 7).map((a) => (
            <AlertRow
              key={a.id}
              alert={a}
              device={name(a, devices)}
              onOpen={() => openDevice(a.deviceId)}
              stacked
            />
          ))}
          {open.length > 7 && (
            <Button type="link" onClick={openAlerts} style={{ paddingInline: 0, marginTop: 8 }}>
              还有 {open.length - 7} 项
            </Button>
          )}
        </div>
      )}
    </Panel>
  );
}

const worst = (alerts: Alert[]) => {
  const t = alertTone([...alerts].sort(bySeverity)[0]);
  return t === "danger" ? 0 : t === "warning" ? 1 : 2;
};

export function AlertsB({
  alerts,
  devices,
  openDevice,
  ack,
}: {
  alerts: Alert[];
  devices: DeviceSummary[];
  openDevice: (id: string) => void;
  ack?: (ids: string[]) => Promise<void>;
}) {
  const open = alerts.filter((a) => a.state !== "Resolved");
  const groups = groupByDevice(open, devices).sort((x, y) => worst(x.alerts) - worst(y.alerts));
  const resolved = alerts.filter((a) => a.state === "Resolved").sort(bySeverity);
  return (
    <>
      <Panel title={`未恢复（${groups.length} 台终端，${open.length} 项）`}>
        {groups.length ? (
          groups.map((d) => (
            <DeviceAlertRow key={d.id} device={d} onOpen={() => openDevice(d.id)} onAck={ack} />
          ))
        ) : (
          <Empty title="当前没有未恢复的告警" />
        )}
      </Panel>
      <Panel title={`近 30 天已恢复（${resolved.length}）`}>
        {resolved.map((a) => (
          <AlertRow key={a.id} alert={a} device={name(a, devices)} onOpen={() => openDevice(a.deviceId)} />
        ))}
      </Panel>
    </>
  );
}

export function OverviewAlertsB({
  alerts,
  devices,
  openDevice,
  openAlerts,
}: {
  alerts: Alert[];
  devices: DeviceSummary[];
  openDevice: (id: string) => void;
  openAlerts: () => void;
}) {
  const open = alerts.filter((a) => a.state !== "Resolved");
  const groups = groupByDevice(open, devices).sort((x, y) => worst(x.alerts) - worst(y.alerts));
  return (
    <Panel
      title={`未恢复告警（${groups.length} 台终端）`}
      actions={
        <Button type="link" onClick={openAlerts} style={{ paddingInline: 0 }}>
          查看全部
        </Button>
      }
    >
      {groups.length === 0 ? (
        <Empty title="当前没有未恢复的告警" />
      ) : (
        groups
          .slice(0, 7)
          .map((d) => <DeviceAlertRow key={d.id} device={d} onOpen={() => openDevice(d.id)} collapsed />)
      )}
    </Panel>
  );
}
