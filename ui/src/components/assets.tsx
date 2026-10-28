import { useMemo, useState } from "react";
import { Descriptions, Input, Space, Table, Tag, Typography } from "antd";
import type { AssetInventory, DeviceInventory, InstalledProgram, InventoryChange } from "../types";
import { Empty, time } from "./common";
import { inventoryChangeLabel } from "./labels";

/** A size as people say it: 16 GB, 476 GB, 1.8 TB (powers of 1024), the way the server writes it too. */
export function bytes(value: number) {
  if (value <= 0) return "";
  const gb = value / 1024 ** 3;
  if (gb >= 1000) return `${(gb / 1024).toFixed(1).replace(/\.0$/, "")} TB`;
  if (gb >= 10) return `${Math.round(gb)} GB`;
  return `${gb.toFixed(1).replace(/\.0$/, "")} GB`;
}

export const systemText = (os: AssetInventory["operatingSystem"]) =>
  [os.name, os.displayVersion, os.version].filter(Boolean).join(" ");

export const scopeText = (scope: string) => (scope === "machine" ? "所有用户" : scope);

const changeColor: Record<string, string> = {
  SoftwareInstalled: "blue",
  SoftwareRemoved: "default",
  SoftwareUpdated: "cyan",
  HardwareChanged: "orange",
  SystemUpdated: "purple",
};

export function ChangeTag({ kind }: { kind: string }) {
  return <Tag color={changeColor[kind]}>{inventoryChangeLabel(kind)}</Tag>;
}

/** Programs on one device, searchable by name or publisher. */
export function SoftwareList({ software }: { software: InstalledProgram[] }) {
  const [search, setSearch] = useState("");
  const shown = useMemo(() => {
    const q = search.trim().toLowerCase();
    return q
      ? software.filter(
          (p) => p.name.toLowerCase().includes(q) || p.publisher.toLowerCase().includes(q),
        )
      : software;
  }, [software, search]);
  return (
    <Space orientation="vertical" size={12} style={{ width: "100%" }}>
      <Input.Search
        allowClear
        aria-label="搜索软件"
        placeholder="按软件名称或发布者搜索"
        style={{ maxWidth: 320 }}
        onChange={(e) => setSearch(e.target.value)}
      />
      <Table<InstalledProgram>
        size="small"
        rowKey={(p) => `${p.name}\n${p.version}\n${p.scope}`}
        dataSource={shown}
        pagination={{ pageSize: 20, hideOnSinglePage: true, showSizeChanger: false }}
        scroll={{ x: 640 }}
        columns={[
          { title: "软件名称", dataIndex: "name" },
          { title: "版本", dataIndex: "version", width: 140 },
          { title: "发布者", dataIndex: "publisher", width: 200 },
          { title: "安装给", dataIndex: "scope", width: 120, render: scopeText },
          { title: "安装日期", dataIndex: "installedOn", width: 110 },
        ]}
      />
    </Space>
  );
}

export function ChangeList({ changes }: { changes: InventoryChange[] }) {
  if (!changes.length)
    return (
      <Empty title="暂无变更">
        资产信息有变化时（安装或卸载软件、系统更新、更换硬件）在这里记录。
      </Empty>
    );
  return (
    <Table<InventoryChange>
      size="small"
      rowKey={(c) => `${c.at}\n${c.kind}\n${c.subject}\n${c.detail}`}
      dataSource={changes}
      pagination={{ pageSize: 20, hideOnSinglePage: true, showSizeChanger: false }}
      scroll={{ x: 640 }}
      columns={[
        { title: "时间", dataIndex: "at", width: 170, render: time },
        {
          title: "类型",
          dataIndex: "kind",
          width: 110,
          render: (k: string) => <ChangeTag kind={k} />,
        },
        { title: "对象", dataIndex: "subject", width: 220 },
        { title: "详情", dataIndex: "detail" },
      ]}
    />
  );
}

/** One device's hardware, system, programs and what changed, as its client last reported them. */
export function InventoryView({ data }: { data: DeviceInventory }) {
  const inv = data.inventory;
  if (!inv)
    return (
      <Empty title="暂无资产信息">
        客户端升级到支持资产清单的版本后，在下次完整检查时上报硬件、系统和已安装软件。
      </Empty>
    );
  const h = inv.hardware,
    os = inv.operatingSystem;
  return (
    <Space orientation="vertical" size={20} style={{ width: "100%" }}>
      <Descriptions
        size="small"
        bordered
        column={{ xs: 1, md: 2 }}
        items={[
          {
            label: "厂商与型号",
            children: [h.manufacturer, h.model].filter(Boolean).join(" ") || "未知",
          },
          {
            label: "序列号",
            children: h.serialNumber ? <span className="mono">{h.serialNumber}</span> : "未读到",
          },
          {
            label: "处理器",
            children: h.processor
              ? `${h.processor}${h.cores ? `（${h.cores} 核 ${h.logicalProcessors} 线程）` : ""}`
              : "未知",
          },
          { label: "内存", children: bytes(h.memoryBytes) || "未知" },
          {
            label: "硬盘",
            children: inv.disks.length
              ? inv.disks.map((d, i) => (
                  <div key={i}>
                    {[d.model, d.mediaType, d.busType, bytes(d.sizeBytes)]
                      .filter(Boolean)
                      .join(" · ")}
                  </div>
                ))
              : "未知",
          },
          {
            label: "分区",
            children: inv.volumes.length
              ? inv.volumes.map((v) => (
                  <div key={v.name}>
                    {v.name} 剩余 {bytes(v.freeBytes) || "0 GB"} / 共 {bytes(v.sizeBytes)}
                    {v.label && <span className="muted">（{v.label}）</span>}
                  </div>
                ))
              : "未知",
          },
          { label: "操作系统", children: systemText(os) || "未知" },
          { label: "系统位数", children: os.architecture || "未知" },
          { label: "系统安装时间", children: os.installedAt ? time(os.installedAt) : "未知" },
          { label: "最近开机", children: os.lastBootAt ? time(os.lastBootAt) : "未知" },
          { label: "BIOS 版本", children: h.biosVersion || "未知" },
          {
            label: "采集时间",
            children: (
              <>
                {time(inv.collectedAt)}
                {data.receivedAt && (
                  <Typography.Text type="secondary">
                    （管理端收到于 {time(data.receivedAt)}）
                  </Typography.Text>
                )}
              </>
            ),
          },
        ]}
      />
      <div>
        <Typography.Title level={5}>已安装软件（{inv.software.length}）</Typography.Title>
        <SoftwareList software={inv.software} />
      </div>
      <div>
        <Typography.Title level={5}>资产变更</Typography.Title>
        <ChangeList changes={data.changes} />
      </div>
    </Space>
  );
}
