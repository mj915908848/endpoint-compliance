import { useState } from "react";
import { App, Button, Typography } from "antd";
import type { Alert } from "../types";
import { errorText, time } from "./common";
import { alertTypeLabel } from "./labels";
import type { DeviceAlerts } from "./alertGroups";

/** "8 分钟前" within a day, otherwise the date and time without seconds. */
export function sinceText(at: string, now = Date.now()) {
  const minutes = Math.round((now - Date.parse(at)) / 60000);
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

export type AlertTone = "danger" | "warning" | "neutral";

export const alertTone = (a: Alert): AlertTone =>
  a.state === "Resolved"
    ? "neutral"
    : a.type === "Violation"
      ? "danger"
      : a.type === "Offline" || a.type === "BlockedAttempt"
        ? "neutral"
        : "warning";

/** Violations first, then sensitive files, then the rest; newest first within each. */
const rank = (a: Alert) =>
  a.state === "Resolved" ? 9 : a.type === "Violation" ? 0 : a.type === "SensitiveFile" ? 1 : 2;
export const bySeverity = (x: Alert, y: Alert) =>
  rank(x) - rank(y) || Date.parse(y.lastSeen) - Date.parse(x.lastSeen);

export function TypeLabel({ alert }: { alert: Alert }) {
  return (
    <span className={`alert-type alert-type-${alertTone(alert)}`}>
      <span className="alert-type-dot" />
      {alertTypeLabel(alert.type)}
    </span>
  );
}

function AckLink({ ids, onAck, label }: { ids: string[]; onAck: (ids: string[]) => Promise<void>; label: string }) {
  const { message } = App.useApp();
  const [busy, setBusy] = useState(false);
  return (
    <Button
      type="link"
      size="small"
      loading={busy}
      className="alert-ack"
      onClick={async (e) => {
        e.stopPropagation();
        setBusy(true);
        try {
          await onAck(ids);
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

/** One alert on one line: type, what was found, on which device, when. */
export function AlertRow({
  alert: a,
  device,
  onOpen,
  onAck,
  showDevice = true,
  stacked,
}: {
  alert: Alert;
  device?: string;
  onOpen?: () => void;
  onAck?: (ids: string[]) => Promise<void>;
  showDevice?: boolean;
  /** The device on a line of its own under what was found, for narrow columns. */
  stacked?: boolean;
}) {
  return (
    <div
      className={`alert-row${a.state === "Resolved" ? " alert-row-resolved" : ""}${stacked ? " alert-row-stacked" : ""}`}
    >
      <TypeLabel alert={a} />
      <div className="alert-row-main">
        <Typography.Text className="alert-row-summary" ellipsis={{ tooltip: a.summary }}>
          {a.summary}
        </Typography.Text>
        {showDevice && (
          <button type="button" className="alert-row-device" onClick={onOpen}>
            {device ?? a.hostName}
          </button>
        )}
      </div>
      <span className="alert-row-time" title={`首次发现 ${time(a.firstSeen)}，最近发现 ${time(a.lastSeen)}`}>
        {sinceText(a.lastSeen)}
      </span>
      {!stacked && (
      <span className="alert-row-action">
        {a.acknowledged ? (
          <span className="alert-row-acked">已确认</span>
        ) : onAck && a.state !== "Resolved" ? (
          <AckLink ids={[a.id]} onAck={onAck} label="确认" />
        ) : null}
      </span>
      )}
    </div>
  );
}

const counts = (alerts: Alert[]) => {
  const by = new Map<string, number>();
  for (const a of alerts) by.set(a.type, (by.get(a.type) ?? 0) + 1);
  return [...by.entries()].sort(
    ([x], [y]) => bySeverity({ type: x } as Alert, { type: y } as Alert) || x.localeCompare(y),
  );
};

/** One device with what is open on it; its alerts listed underneath unless `collapsed`. */
export function DeviceAlertRow({
  device: d,
  onOpen,
  onAck,
  collapsed,
}: {
  device: DeviceAlerts;
  onOpen: () => void;
  onAck?: (ids: string[]) => Promise<void>;
  collapsed?: boolean;
}) {
  const unacked = d.alerts.filter((a) => !a.acknowledged).map((a) => a.id);
  const worst = alertTone([...d.alerts].sort(bySeverity)[0]);
  return (
    <div className={`device-alerts device-alerts-${worst}`}>
      <div className="device-alerts-head" onClick={onOpen} role="button" tabIndex={0}>
        <div className="device-alerts-name">
          <Typography.Text strong>{d.hostName}</Typography.Text>
          {d.note && <span className="device-alerts-note">{d.note}</span>}
        </div>
        <div className="device-alerts-counts">
          {counts(d.alerts).map(([type, n]) => (
            <span key={type} className={`alert-type alert-type-${alertTone({ type, state: "Active" } as Alert)}`}>
              <span className="alert-type-dot" />
              {alertTypeLabel(type)} {n}
            </span>
          ))}
        </div>
        <span className="alert-row-time">{sinceText(d.lastSeen)}</span>
        <span className="alert-row-action">
          {onAck && unacked.length > 0 ? (
            <AckLink ids={unacked} onAck={onAck} label={`确认 ${unacked.length} 项`} />
          ) : (
            <span className="alert-row-acked">{unacked.length ? `${unacked.length} 项待确认` : "均已确认"}</span>
          )}
        </span>
      </div>
      {!collapsed && (
        <div className="device-alerts-items">
          {[...d.alerts].sort(bySeverity).map((a) => (
            <AlertRow key={a.id} alert={a} showDevice={false} onAck={onAck} />
          ))}
        </div>
      )}
    </div>
  );
}
