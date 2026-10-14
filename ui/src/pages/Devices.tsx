import { useState } from "react";
import { Button, Input, Select, Space } from "antd";
import { useResource, useRefresh } from "../useResource";
import { DeviceTable, Fresh, PageHeading, Panel, UpdatedAt } from "../components";
import type { DeviceSummary } from "../types";

export function Devices({ openDevice }: { openDevice: (id: string) => void }) {
  const refresh = useRefresh();
  const [query, setQuery] = useState(""),
    [filter, setFilter] = useState("all");
  const data = useResource<DeviceSummary[]>("/api/devices");
  const visible = (data.data ?? []).filter(
    (d) =>
      (filter === "all" ||
        (filter === "offline"
          ? d.onlineState !== "Online"
          : d.onlineState === "Online" && d.currentVerdict === filter)) &&
      `${d.hostName} ${d.id}`.toLowerCase().includes(query.toLowerCase()),
  );
  return (
    <>
      <PageHeading
        title="终端设备"
        description="查看每台终端的当前结论、在线状态、证据和检查报告。"
        extra={<UpdatedAt at={data.updatedAt} refreshing={data.refreshing} />}
        action={<Button onClick={refresh}>刷新</Button>}
      />
      <Panel
        title={`设备清单（${visible.length}）`}
        actions={
          <Space wrap>
            <Input.Search
              aria-label="搜索设备"
              placeholder="主机名或设备 ID"
              allowClear
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              style={{ width: 220 }}
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
