import { Descriptions, Space, Table, Tag, Typography } from "antd";
import { useResource } from "../useResource";
import { Empty, Fresh, PageHeading, Panel } from "../components";
import type { Status } from "../types";

const modeLabels: Record<string, string> = {
  Production: "生产模式",
  LoopbackDemo: "本机演示",
  LanHttpTrial: "内网试用（HTTP）",
};

const capabilityNames: Record<string, string> = { network: "通用网络访问拦截" };

type Capability = { id: string; implemented: boolean; verified: boolean; detail: string };

export function SystemPage() {
  const status = useResource<Status>("/api/status");
  const caps: Capability[] = (status.data?.networkCapabilities ?? []).map((c) =>
    typeof c === "string" ? { id: c, implemented: false, verified: false, detail: "" } : c,
  );
  return (
    <>
      <PageHeading
        title="系统状态"
        description="管理端的运行模式、存储和网络防护能力。终端上的实际防护效果以终端上报的证据为准。"
      />
      <Space orientation="vertical" size={16} style={{ width: "100%" }}>
        <Panel title="运行环境">
          <Fresh error={status.error} loading={status.loading}>
            {status.data && (
              <Descriptions
                size="small"
                bordered
                column={1}
                items={[
                  {
                    label: "运行模式",
                    children: (
                      <Tag color={status.data.mode === "Production" ? "success" : "warning"}>
                        {modeLabels[status.data.mode] ?? status.data.mode}
                      </Tag>
                    ),
                  },
                  { label: "版本", children: status.data.version ?? "未知" },
                  { label: "数据库", children: status.data.storage },
                  {
                    label: "策略签名密钥 ID",
                    children: <span className="mono">{status.data.policyKeyId}</span>,
                  },
                ]}
              />
            )}
          </Fresh>
        </Panel>
        <Panel title="网络防护能力">
          <Fresh error={status.error} loading={status.loading}>
            <Table<Capability>
              rowKey="id"
              dataSource={caps}
              size="small"
              pagination={false}
              locale={{ emptyText: <Empty title="管理端未声明网络防护能力" /> }}
              columns={[
                { title: "能力", key: "id", render: (_, c) => capabilityNames[c.id] ?? c.id },
                {
                  title: "状态",
                  key: "state",
                  render: (_, c) => (
                    <Space size={4}>
                      <Tag color={c.implemented ? "success" : "warning"}>
                        {c.implemented ? "已实现" : "未实现"}
                      </Tag>
                      <Tag color={c.verified ? "success" : "warning"}>
                        {c.verified ? "已验证" : "未验证"}
                      </Tag>
                    </Space>
                  ),
                },
                {
                  title: "说明",
                  key: "detail",
                  render: (_, c) => <Typography.Text type="secondary">{c.detail}</Typography.Text>,
                },
              ]}
            />
          </Fresh>
        </Panel>
      </Space>
    </>
  );
}
