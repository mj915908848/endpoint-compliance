import { useEffect, useState } from "react";
import { App, Button, Typography } from "antd";
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

/** Violations first, then sensitive files, then the rest; newest first within each. */
const rank = (a: Pick<Alert, "type" | "state">) =>
  a.state === "Resolved" ? 9 : a.type === "Violation" ? 0 : a.type === "SensitiveFile" ? 1 : 2;
export const bySeverity = (x: Alert, y: Alert) =>
  rank(x) - rank(y) || ms(y.lastSeen) - ms(x.lastSeen);

/**
 * Alerts grouped by device: devices with violations first, then sensitive files, then the rest, each newest first;
 * within a device the same order.
 */
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
  const groups = [...byId.values()];
  for (const g of groups) g.alerts.sort(bySeverity);
  return groups.sort(
    (x, y) => rank(x.alerts[0]) - rank(y.alerts[0]) || ms(y.lastSeen) - ms(x.lastSeen),
  );
}

/** "8 分钟前" within a day, otherwise the date and time without seconds. */
export function sinceText(at: string, now = Date.now()) {
  const minutes = Math.round((now - ms(at)) / 60000);
  if (minutes < 1) return "刚刚";
  if (minutes < 60) return `${minutes} 分钟前`;
  if (minutes < 24 * 60) return `${Math.floor(minutes / 60)} 小时前`;
  return new Date(at).toLocaleString("zh-CN", {
    month: "numeric",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    hour12: false,
  });
}

type Tone = "danger" | "warning" | "neutral";

/** Red for violations, amber for what needs a look, grey for the rest and for anything recovered. */
const tone = (a: Pick<Alert, "type" | "state">): Tone =>
  a.state === "Resolved"
    ? "neutral"
    : a.type === "Violation"
      ? "danger"
      : a.type === "Offline" || a.type === "BlockedAttempt"
        ? "neutral"
        : "warning";

function TypeLabel({ alert, count }: { alert: Pick<Alert, "type" | "state">; count?: number }) {
  return (
    <span className={`alert-type alert-type-${tone(alert)}`}>
      <span className="alert-type-dot" />
      {alertTypeLabel(alert.type)}
      {count !== undefined && ` ${count}`}
    </span>
  );
}

/** Acknowledges `ids`; failures are shown as a message, and the list refreshes either way. */
function AckButton({
  ids,
  onAck,
  label,
  onDone,
}: {
  ids: string[];
  onAck: (ids: string[]) => Promise<void>;
  label: string;
  onDone?: () => void;
}) {
  const { message } = App.useApp();
  const [busy, setBusy] = useState(false);
  return (
    <Button
      type="link"
      size="small"
      loading={busy}
      className="alert-ack"
      onClick={async () => {
        setBusy(true);
        try {
          await onAck(ids);
          onDone?.();
        } catch (err) {
          message.error(errorText(err));
        } finally {
          setBusy(false);
        }
      }}
    >
      {label}
    </Button>
  );
}

/**
 * One alert on one line: its type, what was found, the device unless the row sits under it, and when. `onAck` is
 * left out when the account cannot acknowledge; acknowledging only records that someone has seen it.
 */
export function AlertRow({
  alert: a,
  device,
  onOpen,
  onAck,
}: {
  alert: Alert;
  /** The device's name, shown as a link to it; left out under a device's own row. */
  device?: string;
  onOpen?: () => void;
  onAck?: (ids: string[]) => Promise<void>;
}) {
  const [acked, setAcked] = useState(a.acknowledged);
  useEffect(() => setAcked(a.acknowledged), [a.id, a.acknowledged]);
  const resolved = a.state === "Resolved";
  return (
    <div className={resolved ? "alert-row alert-row-resolved" : "alert-row"}>
      <TypeLabel alert={a} />
      <div className="alert-row-main">
        <Typography.Text className="alert-row-summary" ellipsis={{ tooltip: a.summary }}>
          {a.summary}
        </Typography.Text>
        {device && (
          <button type="button" className="alert-row-device" onClick={onOpen}>
            {device}
          </button>
        )}
      </div>
      <span
        className="alert-row-time"
        title={`首次发现 ${time(a.firstSeen)}，最近发现 ${time(a.lastSeen)}`}
      >
        {sinceText(a.lastSeen)}
      </span>
      <span className="alert-row-action">
        {acked ? (
          <span className="alert-row-quiet">已确认</span>
        ) : onAck && !resolved ? (
          <AckButton ids={[a.id]} onAck={onAck} label="确认" onDone={() => setAcked(true)} />
        ) : null}
      </span>
    </div>
  );
}

/**
 * One device and what is open on it: how many of each type, the newest, and (unless `compact`, as on the overview)
 * each alert underneath.
 */
export function DeviceAlertRow({
  device: d,
  onOpen,
  onAck,
  compact,
}: {
  device: DeviceAlerts;
  onOpen: () => void;
  onAck?: (ids: string[]) => Promise<void>;
  compact?: boolean;
}) {
  const unacked = d.alerts.filter((a) => !a.acknowledged).map((a) => a.id);
  const counts = new Map<string, number>();
  for (const a of d.alerts) counts.set(a.type, (counts.get(a.type) ?? 0) + 1);
  return (
    <section
      className={`device-alerts device-alerts-${tone(d.alerts[0])}`}
      aria-label={`${d.hostName} 的告警`}
    >
      <div className="device-alerts-head">
        <div className="device-alerts-name">
          <button type="button" className="device-alerts-host" onClick={onOpen}>
            {d.hostName}
          </button>
          {d.note && <span className="device-alerts-note">{d.note}</span>}
        </div>
        <div className="device-alerts-counts">
          {[...counts].map(([type, n]) => (
            <TypeLabel key={type} alert={{ type, state: "Active" }} count={n} />
          ))}
        </div>
        <span className="alert-row-time">{sinceText(d.lastSeen)}</span>
        <span className="alert-row-action">
          {!compact && onAck && unacked.length > 0 ? (
            <AckButton ids={unacked} onAck={onAck} label={`全部确认（${unacked.length}）`} />
          ) : (
            <span className="alert-row-quiet">
              {unacked.length ? `${unacked.length} 项待确认` : "均已确认"}
            </span>
          )}
        </span>
      </div>
      {!compact && (
        <div className="device-alerts-items">
          {d.alerts.map((a) => (
            <AlertRow key={a.id} alert={a} onAck={onAck} />
          ))}
        </div>
      )}
    </section>
  );
}
