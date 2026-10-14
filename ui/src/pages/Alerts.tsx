import { useMemo, useState } from "react";
import { Alert as Notice, App, Button, Card, Flex, Segmented, Space, Tag, Typography } from "antd";
import { CloseCircleFilled } from "@ant-design/icons";
import { request } from "../api";
import { useResource, useRefresh } from "../useResource";
import {
  AlertCard,
  Empty,
  errorText,
  Fresh,
  PageHeading,
  Panel,
  time,
  UpdatedAt,
} from "../components";
import { role } from "../session";
import type { Alert, DeviceSummary, Session } from "../types";

interface ViolatingDevice {
  id: string;
  hostName: string;
  note?: string;
  alerts: Alert[];
  lastSeen: string;
}

/** Unresolved violations grouped by device, the device with the most violations first. */
function violatingDevices(alerts: Alert[], devices: DeviceSummary[]): ViolatingDevice[] {
  const byId = new Map<string, ViolatingDevice>();
  for (const a of alerts) {
    if (a.type !== "Violation" || a.state === "Resolved") continue;
    const group = byId.get(a.deviceId) ?? {
      id: a.deviceId,
      hostName: a.hostName,
      note: devices.find((d) => d.id === a.deviceId)?.note,
      alerts: [],
      lastSeen: a.lastSeen,
    };
    group.alerts.push(a);
    if (a.lastSeen > group.lastSeen) group.lastSeen = a.lastSeen;
    byId.set(a.deviceId, group);
  }
  return [...byId.values()].sort(
    (x, y) => y.alerts.length - x.alerts.length || y.lastSeen.localeCompare(x.lastSeen),
  );
}

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
  const canAck = role(session, "Operator");
  const all = useMemo(() => data.data ?? [], [data.data]);
  const violating = useMemo(() => violatingDevices(all, devices.data ?? []), [all, devices.data]);
  const notes = new Map((devices.data ?? []).map((d) => [d.id, d.note]));
  // Unresolved violations are already listed per device above.
  const others = all.filter(
    (a) =>
      !(a.type === "Violation" && a.state !== "Resolved") &&
      (filter === "all" || (filter === "active" ? a.state !== "Resolved" : a.state === "Resolved")),
  );
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
          {violating.length ? (
            <Panel
              title={
                <Space>
                  <CloseCircleFilled style={{ color: "var(--danger)" }} />
                  {`违规设备（${violating.length} 台）`}
                </Space>
              }
            >
              <Space orientation="vertical" size={12} style={{ width: "100%" }}>
                {violating.map((d) => (
                  <ViolationCard
                    key={d.id}
                    device={d}
                    canAck={canAck}
                    onOpen={() => openDevice(d.id)}
                    onAck={async (ids) => {
                      for (const id of ids) await ack(id);
                      refresh();
                    }}
                  />
                ))}
              </Space>
            </Panel>
          ) : (
            <Notice type="success" showIcon title="当前没有违规设备" />
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
          </Panel>
        </Space>
      </Fresh>
    </>
  );
}

function ViolationCard({
  device: d,
  canAck,
  onOpen,
  onAck,
}: {
  device: ViolatingDevice;
  canAck: boolean;
  onOpen: () => void;
  onAck: (ids: string[]) => Promise<void>;
}) {
  const { message } = App.useApp();
  const [busy, setBusy] = useState(false);
  const unacked = d.alerts.filter((a) => !a.acknowledged).map((a) => a.id);
  async function ackAll() {
    setBusy(true);
    try {
      await onAck(unacked);
    } catch (e) {
      message.error(errorText(e));
    } finally {
      setBusy(false);
    }
  }
  return (
    <Card size="small" className="violation-card" aria-label={`违规设备 ${d.hostName}`}>
      <Flex justify="space-between" align="start" gap={16} wrap>
        <Space orientation="vertical" size={2}>
          <Space size={8} wrap align="baseline">
            <Typography.Text strong style={{ fontSize: 16 }}>
              {d.hostName}
            </Typography.Text>
            {d.note ? (
              <Typography.Text>{d.note}</Typography.Text>
            ) : (
              <Typography.Text type="secondary">未填写备注</Typography.Text>
            )}
            <Tag color="error" variant="solid">
              {d.alerts.length} 项违规
            </Tag>
          </Space>
          <Typography.Text type="secondary" style={{ fontSize: 12 }}>
            最近发现 {time(d.lastSeen)}
            {unacked.length ? ` · ${unacked.length} 项待确认` : " · 均已确认"}
          </Typography.Text>
        </Space>
        <Space wrap>
          <Button type="primary" onClick={onOpen}>
            查看终端
          </Button>
          {canAck && unacked.length > 0 && (
            <Button loading={busy} onClick={ackAll}>
              全部确认已阅
            </Button>
          )}
        </Space>
      </Flex>
      <ul className="violation-list">
        {d.alerts.map((a) => (
          <li key={a.id}>
            <Typography.Text>{a.summary}</Typography.Text>
            <Typography.Text type="secondary" style={{ fontSize: 12, marginLeft: 8 }}>
              首次发现 {time(a.firstSeen)}
              {a.acknowledged && " · 已确认"}
            </Typography.Text>
          </li>
        ))}
      </ul>
    </Card>
  );
}
