import { useState } from "react";
import { Button, Segmented, Space } from "antd";
import { request } from "../api";
import { useResource, useRefresh } from "../useResource";
import { AlertCard, Empty, Fresh, PageHeading, Panel, UpdatedAt } from "../components";
import { role } from "../session";
import type { Alert, Session } from "../types";

export function Alerts({ session }: { session: Session }) {
  const refresh = useRefresh();
  const data = useResource<Alert[]>("/api/alerts");
  const [filter, setFilter] = useState("active");
  const visible = (data.data ?? []).filter(
    (a) =>
      filter === "all" || (filter === "active" ? a.state !== "Resolved" : a.state === "Resolved"),
  );
  return (
    <>
      <PageHeading
        title="告警中心"
        description="“确认”只记录管理员已知悉；告警是否恢复，以终端新的检查结果为准。"
        extra={<UpdatedAt at={data.updatedAt} refreshing={data.refreshing} />}
        action={<Button onClick={refresh}>刷新</Button>}
      />
      <Panel
        title={`告警记录（${visible.length}）`}
        actions={
          <Segmented
            aria-label="告警筛选"
            value={filter}
            onChange={setFilter}
            options={[
              { value: "active", label: "未恢复" },
              { value: "recovered", label: "已恢复" },
              { value: "all", label: "全部" },
            ]}
          />
        }
      >
        <Fresh error={data.error} loading={data.loading}>
          {visible.length ? (
            <Space orientation="vertical" size={12} style={{ width: "100%" }}>
              {visible.map((a) => (
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
                    refresh();
                  }}
                />
              ))}
            </Space>
          ) : (
            <Empty title="没有符合条件的告警" />
          )}
        </Fresh>
      </Panel>
    </>
  );
}
