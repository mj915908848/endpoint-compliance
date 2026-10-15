import { useState } from "react";
import { App, Button, Input, Select, Space } from "antd";
import { DownloadOutlined } from "@ant-design/icons";
import { downloadFile } from "../api";
import { useResource, useRefresh } from "../useResource";
import { DeviceTable, errorText, Fresh, PageHeading, Panel, UpdatedAt } from "../components";
import type { DeviceSummary } from "../types";

export function Devices({ openDevice }: { openDevice: (id: string) => void }) {
  const refresh = useRefresh();
  const { message } = App.useApp();
  const [query, setQuery] = useState(""),
    [filter, setFilter] = useState("all"),
    [exporting, setExporting] = useState(false);
  const data = useResource<DeviceSummary[]>("/api/devices");
  const visible = (data.data ?? []).filter(
    (d) =>
      (filter === "all" ||
        (filter === "offline"
          ? d.onlineState !== "Online"
          : d.onlineState === "Online" && d.currentVerdict === filter)) &&
      `${d.hostName} ${d.note ?? ""} ${d.id}`.toLowerCase().includes(query.toLowerCase()),
  );
  async function exportList() {
    setExporting(true);
    try {
      const d = new Date();
      const stamp = `${d.getFullYear()}${String(d.getMonth() + 1).padStart(2, "0")}${String(d.getDate()).padStart(2, "0")}`;
      await downloadFile("/api/devices/export.csv", `终端列表-${stamp}.csv`, "终端列表");
    } catch (e) {
      void message.error(errorText(e));
    } finally {
      setExporting(false);
    }
  }
  return (
    <>
      <PageHeading
        title="终端设备"
        description="查看每台终端的当前结论、在线状态、证据和检查报告。"
        extra={<UpdatedAt at={data.updatedAt} refreshing={data.refreshing} />}
        action={
          <Space>
            <Button icon={<DownloadOutlined />} loading={exporting} onClick={exportList}>
              导出 Excel
            </Button>
            <Button onClick={refresh}>刷新</Button>
          </Space>
        }
      />
      <Panel
        title={`设备清单（${visible.length}）`}
        actions={
          <Space wrap>
            <Input.Search
              aria-label="搜索设备"
              placeholder="主机名、备注或设备 ID"
              allowClear
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              style={{ width: 240 }}
            />
            <Select
              aria-label="筛选状态"
              value={filter}
              onChange={setFilter}
              style={{ width: 150 }}
              options={[
                { value: "all", label: "全部状态" },
                { value: "PASS", label: "通过" },
                { value: "FAIL", label: "不通过" },
                { value: "UNKNOWN", label: "无法判断" },
                { value: "offline", label: "失联 / 疑似失联" },
              ]}
            />
          </Space>
        }
      >
        <Fresh error={data.error} loading={data.loading}>
          <DeviceTable devices={visible} onSelect={openDevice} />
        </Fresh>
      </Panel>
    </>
  );
}
