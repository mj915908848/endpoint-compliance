import { useMemo, useState } from "react";
import { Alert as Notice, Button, Segmented, Space, Typography } from "antd";
import { CloseCircleFilled, FileSearchOutlined } from "@ant-design/icons";
import { request } from "../api";
import { useResource, useRefresh } from "../useResource";
import {
  AlertCard,
  DeviceAlertCard,
  type DeviceAlerts,
  Empty,
  Fresh,
  groupByDevice,
  PageHeading,
  Panel,
  sortNewestFirst,
  UpdatedAt,
} from "../components";
import { role } from "../session";
import type { Alert, DeviceSummary, Session } from "../types";

/** Unresolved violations and sensitive files are listed per device; everything else is a single list. */
const grouped = (a: Alert) =>
  a.state !== "Resolved" && (a.type === "Violation" || a.type === "SensitiveFile");

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
  const data = useResource<Alert[]>("/api/alerts"),
    devices = useResource<DeviceSummary[]>("/api/devices");
  const [filter, setFilter] = useState("active");
  const [older, setOlder] = useState<Alert[]>([]);
  const [olderDone, setOlderDone] = useState(false);
  const [olderLoading, setOlderLoading] = useState(false);
  const canAck = role(session, "Operator");
  const all = useMemo(() => data.data ?? [], [data.data]);
  const groups = useMemo(() => {
    const list = devices.data ?? [];
    return {
      violating: groupByDevice(
        all.filter((a) => grouped(a) && a.type === "Violation"),
        list,
      ),
      sensitive: groupByDevice(
        all.filter((a) => grouped(a) && a.type === "SensitiveFile"),
        list,
      ),
    };
  }, [all, devices.data]);
  const notes = new Map((devices.data ?? []).map((d) => [d.id, d.note]));
  const others = sortNewestFirst(
    [...all, ...(filter === "active" ? [] : older)].filter(
      (a) =>
        !grouped(a) &&
        (filter === "all" ||
          (filter === "active" ? a.state !== "Resolved" : a.state === "Resolved")),
    ),
  );
  const loadOlder = async () => {
    const resolved = [...all, ...older].filter((a) => a.state === "Resolved");
    const last = older.at(-1);
    // Start just before the 30-day window the list covers, or after the last page.
    const before = last?.lastSeen ?? new Date(Date.now() - 30 * 86_400_000).toISOString();
    setOlderLoading(true);
    try {
      const page = await request<Alert[]>(
        `/api/alerts/resolved?before=${encodeURIComponent(before)}&beforeId=${encodeURIComponent(last?.id ?? "")}&limit=${PAGE}`,
      );
      const known = new Set(resolved.map((a) => a.id));
      setOlder((o) => [...o, ...page.filter((a) => !known.has(a.id))]);
      if (page.length < PAGE) setOlderDone(true);
    } finally {
      setOlderLoading(false);
    }
  };
  const ack = (id: string) =>
    request(`/api/alerts/${encodeURIComponent(id)}/ack`, {
      method: "POST",
      body: {},
      csrfToken: session.csrfToken,
    });

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
          {groups.violating.length ? (
            <DeviceGroups
              icon={<CloseCircleFilled style={{ color: "var(--danger)" }} />}
              title="违规设备"
              label="违规设备"
              count="项违规"
              danger
              groups={groups.violating}
              canAck={canAck}
              openDevice={openDevice}
              ack={ack}
              refresh={refresh}
            />
          ) : (
            <Notice type="success" showIcon title="当前没有违规设备" />
          )}
          {groups.sensitive.length > 0 && (
            <DeviceGroups
              icon={<FileSearchOutlined style={{ color: "var(--warning)" }} />}
              title="敏感文件"
              label="敏感文件"
              count="个敏感文件"
              groups={groups.sensitive}
              canAck={canAck}
              openDevice={openDevice}
              ack={ack}
              refresh={refresh}
            />
          )}
          <Panel
            title={`其他告警（${others.length}）`}
            actions={
              <Segmented
                aria-label="告警筛选"
                value={filter}
                onChange={setFilter}
                options={[
                  { value: "active", label: "未恢复" },
                  { value: "recovered", label: "已恢复" },
                  { value: "all", label: "全部" },
                ]}
              />
            }
          >
            {others.length ? (
              <Space orientation="vertical" size={12} style={{ width: "100%" }}>
                {others.map((a) => (
                  <AlertCard
                    key={a.id}
                    alert={a}
                    note={notes.get(a.deviceId)}
                    canAck={canAck}
                    onAck={async (id) => {
                      await ack(id);
                      refresh();
                    }}
                  />
                ))}
              </Space>
            ) : (
              <Empty title="没有符合条件的告警" />
            )}
            {filter !== "active" && (
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
            )}
          </Panel>
        </Space>
      </Fresh>
    </>
  );
}

function DeviceGroups({
  icon,
  title,
  label,
  count,
  danger,
  groups,
  canAck,
  openDevice,
  ack,
  refresh,
}: {
  icon: React.ReactNode;
  title: string;
  label: string;
  count: string;
  danger?: boolean;
  groups: DeviceAlerts[];
  canAck: boolean;
  openDevice: (id: string) => void;
  ack: (id: string) => Promise<unknown>;
  refresh: () => void;
}) {
  return (
    <Panel
      title={
        <Space>
          {icon}
          {`${title}（${groups.length} 台）`}
        </Space>
      }
    >
      <Space orientation="vertical" size={12} style={{ width: "100%" }}>
        {groups.map((d) => (
          <DeviceAlertCard
            key={d.id}
            device={d}
            label={label}
            count={count}
            danger={danger}
            onOpen={() => openDevice(d.id)}
            onAck={
              canAck
                ? async (ids) => {
                    for (const id of ids) await ack(id);
                    refresh();
                  }
                : undefined
            }
          />
        ))}
      </Space>
    </Panel>
  );
}
