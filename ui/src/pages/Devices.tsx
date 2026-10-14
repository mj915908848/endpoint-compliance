import { useState } from "react";
import { useResource } from "../useResource";
import { Panel, Fresh, PageHeading, DeviceTable } from "../components";
import type { DeviceSummary } from "../types";

export function Devices({
  revision,
  refresh,
  openDevice,
}: {
  revision: number;
  refresh: () => void;
  openDevice: (id: string) => void;
}) {
  const [query, setQuery] = useState(""),
    [filter, setFilter] = useState("all");
  const data = useResource<DeviceSummary[]>("/api/devices", revision);
  const visible = (data.data ?? []).filter(
    (d) =>
      (filter === "all" ||
        (filter === "offline" ? d.onlineState !== "Online" : d.currentVerdict === filter)) &&
      `${d.hostName} ${d.id}`.toLowerCase().includes(query.toLowerCase()),
  );
  return (
    <>
      <PageHeading
        kicker="FLEET / DEVICES"
        title="终端设备"
        description="查看当前结论、失联历史、执行证据及固定报告。"
        action={
          <button className="secondary" onClick={refresh}>
            刷新列表
          </button>
        }
      />
      <Panel
        title="设备清单"
        actions={
          <div className="filters">
            <input
              aria-label="搜索设备"
              placeholder="搜索主机名或设备 ID"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
            />
            <select
              aria-label="筛选状态"
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
            >
              <option value="all">全部状态</option>
              <option value="PASS">范围内通过</option>
              <option value="FAIL">不通过</option>
              <option value="UNKNOWN">无法判断</option>
              <option value="offline">失联 / 疑似失联</option>
            </select>
          </div>
        }
      >
        <Fresh error={data.error} loading={data.loading}>
          <DeviceTable devices={visible} onSelect={openDevice} />
        </Fresh>
      </Panel>
    </>
  );
}
