import { useState } from "react";
import { useResource } from "../useResource";
import { Panel, Fresh, PageHeading, DeviceTable } from "../components";
import { DeviceDetailPage } from "./DeviceDetail";
import type { DeviceSummary, Session } from "../types";

export function Devices({
  session,
  revision,
  refresh,
  initialDevice,
}: {
  session: Session;
  revision: number;
  refresh: () => void;
  initialDevice: string | null;
}) {
  const [id, setId] = useState<string | null>(initialDevice),
    [query, setQuery] = useState(""),
    [filter, setFilter] = useState("all");
  const data = useResource<DeviceSummary[]>("/api/devices", revision);
  const visible = (data.data ?? []).filter(
    (d) =>
      (filter === "all" ||
        (filter === "offline" ? d.onlineState !== "Online" : d.currentVerdict === filter)) &&
      `${d.hostName} ${d.id}`.toLowerCase().includes(query.toLowerCase()),
  );
  if (id)
    return (
      <DeviceDetailPage
        id={id}
        session={session}
        back={() => setId(null)}
        revision={revision}
        refresh={refresh}
      />
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
          <DeviceTable devices={visible} onSelect={setId} />
        </Fresh>
      </Panel>
    </>
  );
}
