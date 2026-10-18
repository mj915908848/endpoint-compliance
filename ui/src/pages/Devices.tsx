import { useState } from "react";
import { useSearchParams } from "react-router";
import { App, Button, Input, Select, Space, Typography } from "antd";
import { DownloadOutlined } from "@ant-design/icons";
import { downloadFile } from "../api";
import { useResource, useRefresh } from "../useResource";
import {
  DeviceTable,
  errorText,
  Fresh,
  networkText,
  PageHeading,
  Panel,
  UpdatedAt,
} from "../components";
import type { DeviceSummary } from "../types";

export function Devices({ openDevice }: { openDevice: (id: string) => void }) {
  const refresh = useRefresh();
  const { message } = App.useApp();
  // The overview links here with ?filter=, so its counts open the devices they count.
  const [params] = useSearchParams();
  const [query, setQuery] = useState(""),
    [filter, setFilter] = useState(params.get("filter") ?? "all"),
    [exporting, setExporting] = useState(false);
  const data = useResource<DeviceSummary[]>("/api/devices");
  const all = data.data ?? [];
  const onlineCount = all.filter((d) => d.onlineState === "Online").length;
  const visible = all.filter(
    (d) =>
      (filter === "all" ||
        (filter === "attention"
          ? d.onlineState !== "Online" || d.currentVerdict !== "PASS"
          : filter === "offline"
            ? d.onlineState !== "Online"
            : filter === "online"
              ? d.onlineState === "Online"
              : d.onlineState === "Online" && d.currentVerdict === filter)) &&
      `${d.hostName} ${d.note ?? ""} ${d.id} ${networkText(d)}`
        .toLowerCase()
        .includes(query.trim().toLowerCase()),
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
        title={
          <Space size={8} wrap>
            <span>设备清单（{visible.length}）</span>
            {all.length > 0 && (
              <Typography.Text type="secondary" style={{ fontSize: 13, fontWeight: "normal" }}>
                在线{" "}
                <Typography.Text type="success" strong>
                  {onlineCount}
                </Typography.Text>{" "}
                / 共 {all.length} 台
              </Typography.Text>
            )}
          </Space>
        }
        actions={
          <Space wrap>
            <Input.Search
              aria-label="搜索设备"
              placeholder="主机名、IP、MAC 或备注"
              allowClear
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              style={{ width: 260 }}
            />
            <Select
              aria-label="筛选状态"
              value={filter}
              onChange={setFilter}
              style={{ width: 150 }}
              options={[
                { value: "all", label: "全部状态" },
                { value: "online", label: "在线" },
                { value: "PASS", label: "通过" },
                { value: "FAIL", label: "不通过" },
                { value: "UNKNOWN", label: "无法判断" },
                { value: "offline", label: "失联 / 疑似失联" },
                { value: "attention", label: "需要关注" },
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
