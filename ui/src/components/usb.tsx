import { Table, Tag, Typography } from "antd";
import type { ColumnsType } from "antd/es/table";
import type { UsbEventRow } from "../types";
import { deviceName, time } from "./common";
import { usbEventLabel } from "./labels";

const usbEventColor: Record<string, string> = {
  UsbConnected: "blue",
  UsbRemoved: "default",
  UsbBlocked: "red",
};

export function UsbEventTag({ type }: { type: string }) {
  return <Tag color={usbEventColor[type]}>{usbEventLabel(type)}</Tag>;
}

/**
 * USB disks plugged in, removed and blocked. The instance id can be copied into the policy's allowed devices; with
 * `openDevice` the rows also say which device.
 */
export function UsbEventTable({
  rows,
  openDevice,
}: {
  rows: UsbEventRow[];
  openDevice?: (id: string) => void;
}) {
  const columns: ColumnsType<UsbEventRow> = [
    { title: "时间", dataIndex: "at", width: 170, render: time },
    ...(openDevice
      ? [
          {
            title: "终端",
            key: "device",
            width: 180,
            render: (_: unknown, r: UsbEventRow) => (
              <Typography.Link onClick={() => openDevice(r.deviceId)}>
                {deviceName(r)}
              </Typography.Link>
            ),
          },
        ]
      : []),
    {
      title: "事件",
      dataIndex: "type",
      width: 90,
      render: (t: string) => <UsbEventTag type={t} />,
    },
    { title: "设备", dataIndex: "detail" },
    {
      title: "设备实例 ID",
      dataIndex: "instanceId",
      width: 300,
      render: (v: string) => (
        <Typography.Text
          copyable={{ text: v, tooltips: ["复制", "已复制"] }}
          style={{ fontSize: 12 }}
        >
          {v}
        </Typography.Text>
      ),
    },
  ];
  return (
    <Table<UsbEventRow>
      size="middle"
      rowKey={(r) => `${r.deviceId}\n${r.at}\n${r.type}\n${r.instanceId}`}
      dataSource={rows}
      locale={{ emptyText: "这段时间没有 U 盘或移动硬盘接入" }}
      pagination={{ pageSize: 50, hideOnSinglePage: true }}
      scroll={{ x: openDevice ? 1100 : 900 }}
      columns={columns}
    />
  );
}
