import { useMemo, useState } from "react";
import { App, Button, Space, Typography } from "antd";
import { request } from "../api";
import { useResource, useRefresh } from "../useResource";
import {
  AlertRow,
  bySeverity,
  DeviceAlertRow,
  deviceName,
  Empty,
  errorText,
  Fresh,
  groupByDevice,
  PageHeading,
  Panel,
  UpdatedAt,
} from "../components";
import { role } from "../session";
import type { Alert, DeviceSummary, Session } from "../types";

/** The alert list holds alerts resolved in the last 30 days; older ones are fetched a page at a time. */
const PAGE = 100;

export function Alerts({
  session,
  openDevice,
}: {
  session: Session;
  openDevice: (id: string) => void;
}) {
  const refresh = useRefresh();
  const { message } = App.useApp();
  const data = useResource<Alert[]>("/api/alerts"),
    devices = useResource<DeviceSummary[]>("/api/devices");
  const [older, setOlder] = useState<Alert[]>([]);
  const [olderDone, setOlderDone] = useState(false);
  const [olderLoading, setOlderLoading] = useState(false);
  const canAck = role(session, "Operator");
  const all = useMemo(() => data.data ?? [], [data.data]);
  const open = all.filter((a) => a.state !== "Resolved");
  const groups = useMemo(
    () =>
      groupByDevice(
        all.filter((a) => a.state !== "Resolved"),
        devices.data ?? [],
      ),
    [all, devices.data],
  );
  const notes = new Map((devices.data ?? []).map((d) => [d.id, d.note]));
  const resolved = [...all.filter((a) => a.state === "Resolved"), ...older].sort(bySeverity);
  const loadOlder = async () => {
    const last = older.at(-1);
    // After the last page; the first page starts where the list above ends, which the server works out by its own
    // clock (the browser's may be off).
    const cursor = last
      ? `before=${encodeURIComponent(last.lastSeen)}&beforeId=${encodeURIComponent(last.id)}&`
      : "";
    setOlderLoading(true);
    try {
      const page = await request<Alert[]>(`/api/alerts/resolved?${cursor}limit=${PAGE}`);
      const known = new Set(resolved.map((a) => a.id));
      setOlder((o) => [...o, ...page.filter((a) => !known.has(a.id))]);
      if (page.length < PAGE) setOlderDone(true);
    } catch (e) {
      message.error(`加载更早的已恢复告警失败：${errorText(e)}`);
    } finally {
      setOlderLoading(false);
    }
  };
  // One failure must not leave the rest unconfirmed, and the list always shows the outcome.
  const ack = async (ids: string[]) => {
    const failed: unknown[] = [];
    for (const id of ids)
      try {
        await request(`/api/alerts/${encodeURIComponent(id)}/ack`, {
          method: "POST",
          body: {},
          csrfToken: session.csrfToken,
        });
      } catch (e) {
        failed.push(e);
      }
    refresh();
    if (failed.length)
      throw new Error(
        ids.length === 1
          ? errorText(failed[0])
          : `已确认 ${ids.length - failed.length} 条，${failed.length} 条失败：${errorText(failed[0])}`,
      );
  };
  const name = (a: Alert) => deviceName({ hostName: a.hostName, note: notes.get(a.deviceId) });

  return (
    <>
      <PageHeading
        title="告警中心"
        description="“确认”只记录管理员已知悉；告警是否恢复，以终端新的检查结果为准。"
        extra={<UpdatedAt at={data.updatedAt} refreshing={data.refreshing} />}
        action={<Button onClick={refresh}>刷新</Button>}
      />
      <Fresh error={data.error} loading={data.loading}>
        <Space orientation="vertical" size={16} style={{ width: "100%" }}>
          <Panel
            title={
              groups.length
                ? `未恢复（${groups.length} 台终端，${open.length} 项）`
                : "未恢复"
            }
          >
            {groups.length ? (
              groups.map((d) => (
                <DeviceAlertRow
                  key={d.id}
                  device={d}
                  onOpen={() => openDevice(d.id)}
                  onAck={canAck ? ack : undefined}
                />
              ))
            ) : (
              <Empty title="当前没有未恢复的告警" />
            )}
          </Panel>
          <Panel title={olderDone || older.length ? `已恢复（${resolved.length} 项）` : `近 30 天已恢复（${resolved.length} 项）`}>
            {resolved.length ? (
              resolved.map((a) => (
                <AlertRow
                  key={a.id}
                  alert={a}
                  device={name(a)}
                  onOpen={() => openDevice(a.deviceId)}
                />
              ))
            ) : (
              <Empty title="近 30 天没有恢复的告警" />
            )}
            <div style={{ marginTop: 16, textAlign: "center" }}>
              {olderDone ? (
                <Typography.Text type="secondary">
                  已显示全部已恢复告警（恢复超过保留期的会自动清理，默认 180 天）
                </Typography.Text>
              ) : (
                <Button loading={olderLoading} onClick={loadOlder}>
                  {older.length ? "继续加载更早的已恢复告警" : "加载 30 天前恢复的告警"}
                </Button>
              )}
            </div>
          </Panel>
        </Space>
      </Fresh>
    </>
  );
}
