import { useState } from "react";
import { request } from "../api";
import { useResource } from "../useResource";
import { AlertCard, Empty, Panel, Fresh, PageHeading } from "../components";
import { role } from "../session";
import type { Alert, Session } from "../types";

export function Alerts({
  session,
  revision,
  refresh,
}: {
  session: Session;
  revision: number;
  refresh: () => void;
}) {
  const data = useResource<Alert[]>("/api/alerts", revision);
  const [filter, setFilter] = useState("active");
  return (
    <>
      <PageHeading
        kicker="INCIDENTS / ALERTS"
        title="告警中心"
        description="人工确认用于处理记录；技术恢复必须有终端新证据。"
        action={
          <button className="secondary" onClick={refresh}>
            刷新告警
          </button>
        }
      />
      <Panel
        title="告警记录"
        actions={
          <select aria-label="告警筛选" value={filter} onChange={(e) => setFilter(e.target.value)}>
            <option value="active">持续问题</option>
            <option value="all">全部</option>
            <option value="recovered">技术已恢复</option>
          </select>
        }
      >
        <Fresh error={data.error} loading={data.loading}>
          {(data.data ?? []).filter(
            (a) =>
              filter === "all" ||
              (filter === "active" ? a.state !== "Resolved" : a.state === "Resolved"),
          ).length ? (
            <div className="alert-list">
              {(data.data ?? [])
                .filter(
                  (a) =>
                    filter === "all" ||
                    (filter === "active" ? a.state !== "Resolved" : a.state === "Resolved"),
                )
                .map((a) => (
                  <AlertCard
                    key={a.id}
                    alert={a}
                    canAck={role(session, "Operator")}
                    onAck={async (id) => {
                      await request(`/api/alerts/${encodeURIComponent(id)}/ack`, {
                        method: "POST",
                        body: {},
                        csrfToken: session.csrfToken,
                      });
                    }}
                  />
                ))}
            </div>
          ) : (
            <Empty title="没有符合筛选条件的告警" />
          )}
        </Fresh>
      </Panel>
    </>
  );
}
