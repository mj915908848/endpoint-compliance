import { Button, Space, Table, Typography, type TableColumnsType } from "antd";
import { AgentVersion, DeviceState, Empty, NetworkLine, time } from "./common";
import type { DeviceSummary } from "../types";

export function DeviceTable({
  devices,
  onSelect,
  pageSize = 20,
  compact = false,
}: {
  devices: DeviceSummary[];
  onSelect: (id: string) => void;
  pageSize?: number | false;
  /** Narrow layout for dashboards: host, state and last scan only. */
  compact?: boolean;
}) {
  const columns: TableColumnsType<DeviceSummary> = [
    {
      title: "终端",
      key: "host",
      render: (_, d) => (
        <Space orientation="vertical" size={0}>
          <Typography.Text strong>{d.hostName}</Typography.Text>
          {d.note && <Typography.Text>{d.note}</Typography.Text>}
          {d.network?.length ? (
            <NetworkLine device={d} />
          ) : (
            !compact && (
              <Typography.Text type="secondary" className="mono" style={{ fontSize: 12 }}>
                {d.id}
              </Typography.Text>
            )
          )}
        </Space>
      ),
    },
    { title: "在线状态 / 检查结论", key: "state", render: (_, d) => <DeviceState device={d} /> },
    {
      title: "策略与防护",
      key: "policy",
      render: (_, d) => (
        <Space orientation="vertical" size={0}>
          <span>
            {d.policyName && `${d.policyName} `}v{d.targetPolicyVersion}
            {d.policyApplied ? " · 已应用" : " · 终端尚未应用"}
          </span>
          <Typography.Text type="secondary" style={{ fontSize: 12 }}>
            {d.protectionStatus || "状态未知"}
          </Typography.Text>
        </Space>
      ),
    },
    {
      title: "最近检查",
      key: "scan",
      render: (_, d) => (
        <Space orientation="vertical" size={0}>
          <span>{time(d.lastScan)}</span>
          {!compact && (
            <Typography.Text type="secondary" style={{ fontSize: 12 }}>
              心跳 {time(d.lastHeartbeat)}
            </Typography.Text>
          )}
          {!compact && (
            <Typography.Text type="secondary" style={{ fontSize: 12 }}>
              <AgentVersion device={d} />
            </Typography.Text>
          )}
        </Space>
      ),
    },
    {
      title: "",
      key: "open",
      width: 90,
      render: (_, d) => (
        <Button
          type="link"
          onClick={(e) => {
            e.stopPropagation();
            onSelect(d.id);
          }}
        >
          查看详情
        </Button>
      ),
    },
  ];
  const hidden = compact ? ["policy", "open"] : [];
  return (
    <Table<DeviceSummary>
      rowKey="id"
      dataSource={devices}
      size="middle"
      scroll={compact ? undefined : { x: 720 }}
      pagination={pageSize ? { pageSize, hideOnSinglePage: true } : false}
      locale={{
        emptyText: (
          <Empty title="暂无终端">使用一次性登记码登记终端，终端首次上报后将显示在此处。</Empty>
        ),
      }}
      rowClassName={(d) => (d.onlineState === "Online" ? "" : "device-away")}
      onRow={(d) => ({ onClick: () => onSelect(d.id), style: { cursor: "pointer" } })}
      columns={columns.filter((c) => !hidden.includes(String(c.key)))}
    />
  );
}
