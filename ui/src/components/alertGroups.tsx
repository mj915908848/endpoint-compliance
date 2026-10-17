import { useState } from "react";
import { App, Button, Card, Flex, Space, Tag, Typography } from "antd";
import type { Alert, DeviceSummary } from "../types";
import { errorText, time } from "./common";
import { alertTypeLabel } from "./labels";

export interface DeviceAlerts {
  id: string;
  hostName: string;
  note?: string;
  alerts: Alert[];
  lastSeen: string;
}

// Compared as instants: the text form can differ in offset or fraction digits.
const ms = (at: string) => Date.parse(at);
const newestFirst = (x: { lastSeen: string }, y: { lastSeen: string }) =>
  ms(y.lastSeen) - ms(x.lastSeen);

/** Alerts grouped by device; the device with the newest alert first, and newest first within a device. */
export function groupByDevice(alerts: Alert[], devices: DeviceSummary[]): DeviceAlerts[] {
  const byId = new Map<string, DeviceAlerts>();
  for (const a of alerts) {
    const group = byId.get(a.deviceId) ?? {
      id: a.deviceId,
      hostName: a.hostName,
      note: devices.find((d) => d.id === a.deviceId)?.note,
      alerts: [],
      lastSeen: a.lastSeen,
    };
    group.alerts.push(a);
    if (ms(a.lastSeen) > ms(group.lastSeen)) group.lastSeen = a.lastSeen;
    byId.set(a.deviceId, group);
  }
  const groups = [...byId.values()].sort(newestFirst);
  for (const g of groups) g.alerts.sort(newestFirst);
  return groups;
}

export const sortNewestFirst = (alerts: Alert[]) => [...alerts].sort(newestFirst);

const tone = (a: Alert) =>
  a.state === "Resolved" ? "default" : a.type === "Violation" ? "error" : "warning";

/**
 * One device and its alerts. `count` names what is counted ("项违规"). The compact form (overview) shows each
 * alert's type and at most `limit` alerts; `onAck` is left out when the account cannot acknowledge.
 */
export function DeviceAlertCard({
  device: d,
  label,
  count,
  danger,
  onOpen,
  onAck,
  compact,
  limit,
}: {
  device: DeviceAlerts;
  /** Accessible name prefix, e.g. "违规设备". */
  label: string;
  count: string;
  danger?: boolean;
  onOpen: () => void;
  onAck?: (ids: string[]) => Promise<void>;
  compact?: boolean;
  limit?: number;
}) {
  const { message } = App.useApp();
  const [busy, setBusy] = useState(false);
  const unacked = d.alerts.filter((a) => !a.acknowledged).map((a) => a.id);
  const shown = limit ? d.alerts.slice(0, limit) : d.alerts;
  async function ackAll() {
    setBusy(true);
    try {
      await onAck!(unacked);
    } catch (e) {
      message.error(errorText(e));
    } finally {
      setBusy(false);
    }
  }
  return (
    <Card
      size="small"
      className={danger ? "alert-group alert-group-danger" : "alert-group"}
      aria-label={`${label} ${d.hostName}`}
    >
      <Flex justify="space-between" align="start" gap={12} wrap>
        <Space orientation="vertical" size={2}>
          <Space size={8} wrap align="baseline">
            <Typography.Text strong style={{ fontSize: compact ? 14 : 16 }}>
              {d.hostName}
            </Typography.Text>
            {d.note ? (
              <Typography.Text>{d.note}</Typography.Text>
            ) : (
              !compact && <Typography.Text type="secondary">未填写备注</Typography.Text>
            )}
            <Tag color={danger ? "error" : "warning"} variant="solid">
              {d.alerts.length} {count}
            </Tag>
          </Space>
          <Typography.Text type="secondary" style={{ fontSize: 12 }}>
            最近发现 {time(d.lastSeen)}
            {unacked.length ? ` · ${unacked.length} 项待确认` : " · 均已确认"}
          </Typography.Text>
        </Space>
        {compact ? (
          <Button type="link" size="small" onClick={onOpen}>
            查看终端
          </Button>
        ) : (
          <Space wrap>
            <Button type="primary" onClick={onOpen}>
              查看终端
            </Button>
            {onAck && unacked.length > 0 && (
              <Button loading={busy} onClick={ackAll}>
                全部确认已阅
              </Button>
            )}
          </Space>
        )}
      </Flex>
      <ul className="alert-group-list">
        {shown.map((a) => (
          <li key={a.id}>
            {compact && (
              <Tag color={tone(a)} style={{ marginInlineEnd: 6 }}>
                {alertTypeLabel(a.type)}
              </Tag>
            )}
            <Typography.Text>{a.summary}</Typography.Text>
            <Typography.Text type="secondary" style={{ fontSize: 12, marginLeft: 8 }}>
              {compact ? time(a.lastSeen) : `首次发现 ${time(a.firstSeen)}`}
              {a.acknowledged && " · 已确认"}
            </Typography.Text>
          </li>
        ))}
        {shown.length < d.alerts.length && (
          <li className="alert-group-more">
            <Typography.Text type="secondary">
              还有 {d.alerts.length - shown.length} 项，查看终端了解全部
            </Typography.Text>
          </li>
        )}
      </ul>
    </Card>
  );
}
