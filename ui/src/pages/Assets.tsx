import { useMemo, useState } from "react";
import { App, Button, Input, Modal, Select, Space, Table, Tabs, Tag, Typography } from "antd";
import { DownloadOutlined } from "@ant-design/icons";
import { downloadFile } from "../api";
import { useRefresh, useResource } from "../useResource";
import {
  bytes,
  ChangeTag,
  deviceName,
  Empty,
  errorText,
  Fresh,
  inventoryChangeLabel,
  PageHeading,
  scopeText,
  systemText,
  time,
  UpdatedAt,
} from "../components";
import type { AssetRow, InventoryChangeRow, SoftwareInstall, SoftwareSummary } from "../types";

const stamp = () => {
  const d = new Date();
  return `${d.getFullYear()}${String(d.getMonth() + 1).padStart(2, "0")}${String(d.getDate()).padStart(2, "0")}`;
};

const includes = (q: string, ...values: string[]) =>
  values.some((v) => v.toLowerCase().includes(q));

/** Hardware, software and their changes across all devices in use, from what their clients report. */
export function AssetsPage({ openDevice }: { openDevice: (id: string) => void }) {
  const { message } = App.useApp();
  const refresh = useRefresh();
  const [tab, setTab] = useState("hardware");
  const [exporting, setExporting] = useState(false);
  const assets = useResource<AssetRow[]>("/api/assets");

  async function exportCsv() {
    setExporting(true);
    try {
      if (tab === "software")
        await downloadFile(
          "/api/assets/software/export.csv",
          `软件清单-${stamp()}.csv`,
          "软件清单",
        );
      else await downloadFile("/api/assets/export.csv", `硬件资产-${stamp()}.csv`, "硬件资产");
    } catch (e) {
      void message.error(errorText(e));
    } finally {
      setExporting(false);
    }
  }

  return (
    <>
      <PageHeading
        title="资产清单"
        description="终端客户端在完整检查后上报硬件、系统和已安装软件；有变化时记录下来。"
        extra={<UpdatedAt at={assets.updatedAt} refreshing={assets.refreshing} />}
        action={
          <Space>
            {tab !== "changes" && (
              <Button icon={<DownloadOutlined />} loading={exporting} onClick={exportCsv}>
                {tab === "software" ? "导出软件清单" : "导出硬件资产"}
              </Button>
            )}
            <Button onClick={refresh}>刷新</Button>
          </Space>
        }
      />
      <div className="panel tabs-panel">
        <Tabs
          activeKey={tab}
          onChange={setTab}
          items={[
            {
              key: "hardware",
              label: `硬件（${assets.lastData?.length ?? 0}）`,
              children: (
                <Fresh
                  error={assets.error && !assets.lastData ? assets.error : null}
                  loading={assets.loading}
                >
                  <HardwareTable rows={assets.lastData ?? []} openDevice={openDevice} />
                </Fresh>
              ),
            },
            { key: "software", label: "软件", children: <SoftwareTab openDevice={openDevice} /> },
            { key: "changes", label: "变更记录", children: <ChangesTab openDevice={openDevice} /> },
          ]}
        />
      </div>
    </>
  );
}

function DeviceCell({
  row,
  openDevice,
}: {
  row: { deviceId: string; hostName: string; note: string };
  openDevice: (id: string) => void;
}) {
  return (
    <Typography.Link onClick={() => openDevice(row.deviceId)}>{deviceName(row)}</Typography.Link>
  );
}

function HardwareTable({
  rows,
  openDevice,
}: {
  rows: AssetRow[];
  openDevice: (id: string) => void;
}) {
  const [search, setSearch] = useState("");
  const shown = useMemo(() => {
    const q = search.trim().toLowerCase();
    return q
      ? rows.filter((r) =>
          includes(
            q,
            r.hostName,
            r.note,
            r.group,
            r.hardware.manufacturer,
            r.hardware.model,
            r.hardware.serialNumber,
            r.hardware.processor,
            systemText(r.operatingSystem),
          ),
        )
      : rows;
  }, [rows, search]);
  if (!rows.length)
    return (
      <Empty title="暂无资产信息">
        终端客户端升级到支持资产清单的版本后，在下次完整检查时上报。
      </Empty>
    );
  return (
    <Space orientation="vertical" size={12} style={{ width: "100%" }}>
      <Input.Search
        allowClear
        aria-label="搜索硬件"
        placeholder="按计算机名、备注、型号、序列号或系统搜索"
        style={{ maxWidth: 360 }}
        onChange={(e) => setSearch(e.target.value)}
      />
      <Table<AssetRow>
        size="middle"
        rowKey="deviceId"
        dataSource={shown}
        pagination={{ pageSize: 50, hideOnSinglePage: true }}
        scroll={{ x: 1310 }}
        columns={[
          {
            title: "终端",
            key: "device",
            fixed: "left",
            width: 150,
            render: (_, r) => (
              <Space orientation="vertical" size={0}>
                <DeviceCell row={r} openDevice={openDevice} />
                {r.group && <Typography.Text type="secondary">{r.group}</Typography.Text>}
              </Space>
            ),
          },
          {
            title: "型号",
            key: "model",
            width: 180,
            render: (_, r) => [r.hardware.manufacturer, r.hardware.model].filter(Boolean).join(" "),
          },
          {
            title: "序列号",
            key: "serial",
            width: 140,
            render: (_, r) => <span className="mono">{r.hardware.serialNumber}</span>,
          },
          { title: "处理器", key: "cpu", width: 200, render: (_, r) => r.hardware.processor },
          {
            title: "内存",
            key: "memory",
            width: 90,
            sorter: (a, b) => a.hardware.memoryBytes - b.hardware.memoryBytes,
            render: (_, r) => bytes(r.hardware.memoryBytes),
          },
          {
            title: "硬盘",
            key: "disks",
            width: 110,
            render: (_, r) =>
              r.disks.map((d, i) => (
                <div key={i}>{[d.mediaType, bytes(d.sizeBytes)].filter(Boolean).join(" ")}</div>
              )),
          },
          {
            title: "操作系统",
            key: "os",
            width: 190,
            render: (_, r) => (
              <Space orientation="vertical" size={0}>
                <span>{r.operatingSystem.name}</span>
                <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                  {[r.operatingSystem.displayVersion, r.operatingSystem.version]
                    .filter(Boolean)
                    .join(" ")}
                </Typography.Text>
              </Space>
            ),
          },
          {
            title: "软件数",
            dataIndex: "softwareCount",
            width: 80,
            sorter: (a, b) => a.softwareCount - b.softwareCount,
          },
          { title: "采集时间", dataIndex: "collectedAt", width: 170, render: time },
        ]}
      />
    </Space>
  );
}

function SoftwareTab({ openDevice }: { openDevice: (id: string) => void }) {
  const software = useResource<SoftwareSummary[]>("/api/assets/software");
  const [search, setSearch] = useState("");
  const [open, setOpen] = useState<SoftwareSummary | null>(null);
  const rows = software.lastData ?? [];
  const shown = useMemo(() => {
    const q = search.trim().toLowerCase();
    return q ? rows.filter((s) => includes(q, s.name, s.publisher)) : rows;
  }, [rows, search]);
  return (
    <Fresh
      error={software.error && !software.lastData ? software.error : null}
      loading={software.loading}
    >
      {!rows.length ? (
        <Empty title="暂无软件信息" />
      ) : (
        <Space orientation="vertical" size={12} style={{ width: "100%" }}>
          <Space wrap>
            <Input.Search
              allowClear
              aria-label="搜索软件"
              placeholder="按软件名称或发布者搜索"
              style={{ width: 320 }}
              onChange={(e) => setSearch(e.target.value)}
            />
            <Typography.Text type="secondary">
              共 {shown.length} 个软件，点击名称查看装在哪些终端上
            </Typography.Text>
          </Space>
          <Table<SoftwareSummary>
            size="middle"
            rowKey="name"
            dataSource={shown}
            pagination={{ pageSize: 50, hideOnSinglePage: true }}
            scroll={{ x: 760 }}
            columns={[
              {
                title: "软件名称",
                dataIndex: "name",
                render: (name: string, s) => (
                  <Typography.Link onClick={() => setOpen(s)}>{name}</Typography.Link>
                ),
              },
              { title: "发布者", dataIndex: "publisher", width: 220 },
              {
                title: "安装终端数",
                dataIndex: "devices",
                width: 110,
                sorter: (a, b) => a.devices - b.devices,
              },
              {
                title: "版本",
                key: "versions",
                width: 300,
                render: (_, s) => (
                  <Space size={4} wrap>
                    {s.versions.slice(0, 3).map((v) => (
                      <Tag key={v.version}>
                        {v.version || "未知版本"} · {v.devices} 台
                      </Tag>
                    ))}
                    {s.versions.length > 3 && (
                      <Typography.Text type="secondary">
                        等 {s.versions.length} 个版本
                      </Typography.Text>
                    )}
                  </Space>
                ),
              },
            ]}
          />
        </Space>
      )}
      <Modal
        title={open ? `安装了“${open.name}”的终端` : ""}
        open={!!open}
        onCancel={() => setOpen(null)}
        footer={null}
        width={760}
        destroyOnHidden
      >
        {open && (
          <Installs
            name={open.name}
            openDevice={(id) => {
              setOpen(null);
              openDevice(id);
            }}
          />
        )}
      </Modal>
    </Fresh>
  );
}

function Installs({ name, openDevice }: { name: string; openDevice: (id: string) => void }) {
  const installs = useResource<SoftwareInstall[]>(
    `/api/assets/software/devices?name=${encodeURIComponent(name)}`,
  );
  return (
    <Fresh error={installs.error} loading={installs.loading}>
      <Table<SoftwareInstall>
        size="small"
        rowKey={(r) => `${r.deviceId}\n${r.version}\n${r.scope}`}
        dataSource={installs.data ?? []}
        pagination={{ pageSize: 20, hideOnSinglePage: true, showSizeChanger: false }}
        columns={[
          {
            title: "终端",
            key: "device",
            render: (_, r) => <DeviceCell row={r} openDevice={openDevice} />,
          },
          { title: "分组", dataIndex: "group", width: 110 },
          { title: "版本", dataIndex: "version", width: 130 },
          { title: "安装给", dataIndex: "scope", width: 110, render: scopeText },
          { title: "安装日期", dataIndex: "installedOn", width: 110 },
        ]}
      />
    </Fresh>
  );
}

function ChangesTab({ openDevice }: { openDevice: (id: string) => void }) {
  const [days, setDays] = useState(30);
  const [kind, setKind] = useState<string | null>(null);
  const changes = useResource<InventoryChangeRow[]>(`/api/assets/changes?days=${days}`);
  const rows = (changes.lastData ?? []).filter((c) => !kind || c.kind === kind);
  return (
    <Space orientation="vertical" size={12} style={{ width: "100%" }}>
      <Space wrap>
        <Select
          aria-label="时间范围"
          value={days}
          onChange={setDays}
          style={{ width: 130 }}
          options={[7, 30, 90, 365].map((d) => ({ value: d, label: `最近 ${d} 天` }))}
        />
        <Select
          aria-label="变更类型"
          allowClear
          placeholder="全部类型"
          value={kind}
          onChange={(v) => setKind(v ?? null)}
          style={{ width: 140 }}
          options={[
            "SoftwareInstalled",
            "SoftwareRemoved",
            "SoftwareUpdated",
            "SystemUpdated",
            "HardwareChanged",
          ].map((k) => ({ value: k, label: inventoryChangeLabel(k) }))}
        />
      </Space>
      <Fresh
        error={changes.error && !changes.lastData ? changes.error : null}
        loading={changes.loading}
      >
        <Table<InventoryChangeRow>
          size="middle"
          rowKey={(c) => `${c.deviceId}\n${c.at}\n${c.kind}\n${c.subject}\n${c.detail}`}
          dataSource={rows}
          locale={{ emptyText: "这段时间没有资产变更" }}
          pagination={{ pageSize: 50, hideOnSinglePage: true }}
          scroll={{ x: 900 }}
          columns={[
            { title: "时间", dataIndex: "at", width: 170, render: time },
            {
              title: "终端",
              key: "device",
              width: 180,
              render: (_, r) => <DeviceCell row={r} openDevice={openDevice} />,
            },
            {
              title: "类型",
              dataIndex: "kind",
              width: 110,
              render: (k: string) => <ChangeTag kind={k} />,
            },
            { title: "对象", dataIndex: "subject", width: 240 },
            { title: "详情", dataIndex: "detail" },
          ]}
        />
      </Fresh>
    </Space>
  );
}
