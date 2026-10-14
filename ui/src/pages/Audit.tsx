import { Table, Typography } from "antd";
import { useResource } from "../useResource";
import { auditActionLabel, Empty, Fresh, PageHeading, Panel, time, UpdatedAt } from "../components";
import type { Audit } from "../types";

const systemActors: Record<string, string> = {
  system: "系统",
  bootstrap: "系统初始化",
  enrollment: "终端登记",
};

export function AuditPage() {
  const data = useResource<Audit[]>("/api/audit");
  return (
    <>
      <PageHeading
        title="审计记录"
        description="按时间倒序记录所有管理操作，包括登录、策略变更、告警处理和终端请求。"
        extra={<UpdatedAt at={data.updatedAt} refreshing={data.refreshing} />}
      />
      <Panel title="最近操作">
        <Fresh error={data.error} loading={data.loading}>
          <Table<Audit>
            rowKey="id"
            dataSource={data.data ?? []}
            size="middle"
            scroll={{ x: 640 }}
            pagination={{ pageSize: 50, hideOnSinglePage: true, showSizeChanger: false }}
            locale={{ emptyText: <Empty title="暂无审计记录" /> }}
            columns={[
              { title: "时间", key: "at", width: 190, render: (_, a) => time(a.at) },
              {
                title: "操作人",
                key: "actor",
                width: 160,
                render: (_, a) => systemActors[a.actor] ?? a.actor,
              },
              {
                title: "操作",
                key: "action",
                width: 180,
                render: (_, a) => (
                  <Typography.Text strong>{auditActionLabel(a.action)}</Typography.Text>
                ),
              },
              {
                title: "对象",
                key: "target",
                render: (_, a) => <span className="mono">{a.target}</span>,
              },
            ]}
          />
        </Fresh>
      </Panel>
    </>
  );
}
