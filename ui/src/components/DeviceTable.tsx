import { DeviceState, Empty, time } from "./common";
import type { DeviceSummary } from "../types";

export function DeviceTable({
  devices,
  onSelect,
}: {
  devices: DeviceSummary[];
  onSelect: (id: string) => void;
}) {
  return devices.length === 0 ? (
    <Empty title="暂无终端">使用一次性登记码为终端登记，终端首次上报后会显示在这里。</Empty>
  ) : (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>终端</th>
            <th>当前结论 / 连线</th>
            <th>策略与防护</th>
            <th>最近采集</th>
            <th>操作</th>
          </tr>
        </thead>
        <tbody>
          {devices.map((d) => (
            <tr key={d.id}>
              <td>
                <strong>{d.hostName}</strong>
                <small className="mono">{d.id}</small>
              </td>
              <td>
                <DeviceState device={d} />
              </td>
              <td>
                <strong>
                  目标 v{d.targetPolicyVersion} · 已应用 v{d.appliedPolicyVersion}
                </strong>
                <small>{d.protectionStatus || "状态未知"}</small>
              </td>
              <td>
                {time(d.lastScan)}
                <small>心跳 {time(d.lastHeartbeat)}</small>
              </td>
              <td>
                <button className="link-button" onClick={() => onSelect(d.id)}>
                  查看详情 →
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
