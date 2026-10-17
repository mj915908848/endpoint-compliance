import { useState } from "react";
import { App, Button, Table, Typography } from "antd";
import { request } from "../api";
import { useResource } from "../useResource";
import {
  auditActionLabel,
  Empty,
  errorText,
  Fresh,
  PageHeading,
  Panel,
  time,
  UpdatedAt,
} from "../components";
import type { Audit } from "../types";

/** The page refreshes the newest records; earlier ones are fetched a page at a time behind them. */
const PAGE = 500;

const systemActors: Record<string, string> = {
  system: "系统",
  bootstrap: "系统初始化",
  enrollment: "终端登记",
};

export function AuditPage() {
  const { message } = App.useApp();
  const data = useResource<Audit[]>(`/api/audit?limit=${PAGE}`);
  const [older, setOlder] = useState<Audit[]>([]);
  const [olderDone, setOlderDone] = useState(false);
  const [olderLoading, setOlderLoading] = useState(false);
  const latest = data.data ?? [];
  const known = new Set(latest.map((a) => a.id));
  const rows = [...latest, ...older.filter((a) => !known.has(a.id))];
  const done = olderDone || (data.data !== undefined && latest.length < PAGE);
  const loadOlder = async () => {
    const last = rows.at(-1);
    if (!last) return;
    setOlderLoading(true);
    try {
      const page = await request<Audit[]>(
        `/api/audit?before=${encodeURIComponent(last.at)}&beforeId=${encodeURIComponent(last.id)}&limit=${PAGE}`,
      );
      setOlder((o) => {
        const seen = new Set(o.map((a) => a.id));
        return [...o, ...page.filter((a) => !seen.has(a.id))];
      });
      if (page.length < PAGE) setOlderDone(true);
    } catch (e) {
      message.error(`加载更早的审计记录失败：${errorText(e)}`);
    } finally {
      setOlderLoading(false);
    }
  };
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
            dataSource={rows}
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
          {rows.length > 0 && (
            <div style={{ marginTop: 16, textAlign: "center" }}>
              {done ? (
                <Typography.Text type="secondary">
                  已显示全部 {rows.length} 条审计记录
                </Typography.Text>
              ) : (
                <Button loading={olderLoading} onClick={loadOlder}>
                  已显示最近 {rows.length} 条，加载更早的记录
                </Button>
              )}
            </div>
          )}
        </Fresh>
      </Panel>
    </>
  );
}
