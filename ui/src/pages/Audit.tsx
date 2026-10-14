import { useResource } from "../useResource";
import { Empty, time, Panel, Fresh, PageHeading } from "../components";
import type { Audit } from "../types";

export function AuditPage({ revision }: { revision: number }) {
  const data = useResource<Audit[]>("/api/audit", revision);
  return (
    <>
      <PageHeading
        kicker="ACCOUNTABILITY / AUDIT"
        title="审计记录"
        description="管理操作按时间倒序呈现，包括策略、告警和终端命令。"
      />
      <Panel title="最近操作">
        <Fresh error={data.error} loading={data.loading}>
          {data.data?.length ? (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>时间</th>
                    <th>操作人</th>
                    <th>动作</th>
                    <th>目标</th>
                  </tr>
                </thead>
                <tbody>
                  {data.data.map((a) => (
                    <tr key={a.id}>
                      <td>{time(a.at)}</td>
                      <td>{a.actor}</td>
                      <td>
                        <strong>{a.action}</strong>
                      </td>
                      <td className="mono">{a.target}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <Empty title="尚无审计记录" />
          )}
        </Fresh>
      </Panel>
    </>
  );
}
