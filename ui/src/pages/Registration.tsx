import { useState } from "react";
import {
  Alert,
  Button,
  Col,
  Form,
  Input,
  InputNumber,
  Popconfirm,
  Row,
  Select,
  Space,
  Table,
  Tag,
  Typography,
} from "antd";
import { DownloadOutlined } from "@ant-design/icons";
import { downloadJson, request } from "../api";
import { Empty, ErrorNotice, errorText, Fresh, PageHeading, Panel, time } from "../components";
import { role } from "../session";
import { useRefresh, useResource } from "../useResource";
import type { EnrollmentCode, Session } from "../types";

const validity = [
  { value: 15, label: "15 分钟" },
  { value: 60, label: "1 小时" },
  { value: 24 * 60, label: "1 天" },
  { value: 3 * 24 * 60, label: "3 天" },
  { value: 7 * 24 * 60, label: "7 天" },
];

interface Created {
  code: string;
  id: string;
  label: string;
  expiresAt: string;
  maxUses: number;
}

/** "有效", or why the code can no longer enroll a device. */
export function codeState(c: EnrollmentCode, now = Date.now()): [string, string] {
  if (c.revoked) return ["已撤销", "default"];
  if (c.uses >= c.maxUses) return ["已用完", "default"];
  if (Date.parse(c.expiresAt) <= now) return ["已过期", "default"];
  return ["有效", "success"];
}

export function Registration({ session }: { session: Session }) {
  const operator = role(session, "Operator");
  const [label, setLabel] = useState(""),
    [uses, setUses] = useState(1),
    [minutes, setMinutes] = useState(15),
    [server, setServer] = useState(window.location.origin),
    [result, setResult] = useState<Created | null>(null),
    [error, setError] = useState<string | null>(null),
    [busy, setBusy] = useState(false);
  const codes = useResource<EnrollmentCode[]>(operator ? "/api/enrollment-codes" : null);
  const refresh = useRefresh();

  async function create() {
    setResult(null);
    setError(null);
    setBusy(true);
    try {
      setResult(
        await request<Created>("/api/enrollment-codes", {
          method: "POST",
          body: { expiresMinutes: minutes, maxUses: uses, label },
          csrfToken: session.csrfToken,
        }),
      );
      refresh();
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(false);
    }
  }

  async function revoke(id: string) {
    setError(null);
    try {
      await request(`/api/enrollment-codes/${encodeURIComponent(id)}`, {
        method: "DELETE",
        csrfToken: session.csrfToken,
      });
      refresh();
    } catch (e) {
      setError(errorText(e));
    }
  }

  if (!operator)
    return (
      <>
        <PageHeading title="终端登记" />
        <Alert type="info" showIcon title="当前账号没有登记终端的权限（需要“操作员”角色）。" />
      </>
    );

  return (
    <>
      <PageHeading
        title="终端登记"
        description="每台电脑安装客户端时要用登记码向管理端登记。一个登记码可以登记多台电脑，用完台数、到期或撤销后失效。"
      />
      <Space orientation="vertical" size={16} style={{ width: "100%" }}>
        <Panel title="生成登记码">
          <Form layout="vertical" onFinish={create}>
            <Row gutter={[24, 0]}>
              <Col xs={24} md={8}>
                <Form.Item
                  label="名称"
                  extra="可选，例如部门或批次，便于在下方列表和审计记录中辨认。"
                >
                  <Input
                    aria-label="名称"
                    maxLength={100}
                    value={label}
                    onChange={(e) => setLabel(e.target.value)}
                    placeholder="如：研发部 10 月批次"
                  />
                </Form.Item>
              </Col>
              <Col xs={12} md={5}>
                <Form.Item label="可登记台数">
                  <InputNumber
                    precision={0}
                    aria-label="可登记台数"
                    min={1}
                    max={500}
                    value={uses}
                    onChange={(v) => setUses(v ?? 1)}
                    suffix="台"
                    style={{ width: "100%" }}
                  />
                </Form.Item>
              </Col>
              <Col xs={12} md={5}>
                <Form.Item label="有效期">
                  <Select
                    aria-label="有效期"
                    value={minutes}
                    onChange={setMinutes}
                    options={validity}
                  />
                </Form.Item>
              </Col>
              <Col xs={24} md={6}>
                <Form.Item label=" ">
                  <Button type="primary" htmlType="submit" loading={busy}>
                    生成登记码
                  </Button>
                </Form.Item>
              </Col>
            </Row>
          </Form>
          <ErrorNotice error={error} />
          {result && (
            <Alert
              type="success"
              showIcon
              title={`登记码已生成：可登记 ${result.maxUses} 台，有效期至 ${time(result.expiresAt)}`}
              description={
                <Space orientation="vertical" size={12} style={{ width: "100%" }}>
                  <Typography.Text copyable className="mono registration-code">
                    {result.code}
                  </Typography.Text>
                  <Typography.Text type="secondary">
                    此码只显示这一次，关闭或刷新页面后无法再查看。持有它的人都能登记电脑，请只交给安装人员。
                  </Typography.Text>
                  <div>
                    <Typography.Text strong>省去逐台输入：</Typography.Text>
                    下载登记配置，和 MSI 安装包放在同一个文件夹，
                    之后每台电脑安装时地址和登记码会自动填好。
                  </div>
                  <Space wrap>
                    <Input
                      aria-label="终端连接的管理端地址"
                      prefix={<Typography.Text type="secondary">管理端地址</Typography.Text>}
                      value={server}
                      onChange={(e) => setServer(e.target.value.trim())}
                      style={{ width: 420, maxWidth: "100%" }}
                    />
                    <Button
                      icon={<DownloadOutlined />}
                      onClick={() =>
                        downloadJson(
                          { serverUrl: server.replace(/\/+$/, ""), code: result.code },
                          "登记配置.json",
                        )
                      }
                    >
                      下载登记配置
                    </Button>
                  </Space>
                  <Typography.Text type="secondary">
                    管理端地址是电脑连接管理端用的地址，默认为当前浏览器访问的地址；经网关访问时填网关上的域名。
                  </Typography.Text>
                </Space>
              }
            />
          )}
        </Panel>
        <Panel title="登记码">
          <Fresh error={codes.error} loading={codes.loading}>
            <Table<EnrollmentCode>
              rowKey="id"
              dataSource={codes.data ?? []}
              size="middle"
              scroll={{ x: 720 }}
              pagination={{ pageSize: 20, hideOnSinglePage: true, showSizeChanger: false }}
              locale={{ emptyText: <Empty title="还没有生成过登记码" /> }}
              columns={[
                {
                  title: "名称",
                  key: "label",
                  render: (_, c) =>
                    c.label || <Typography.Text type="secondary">未命名</Typography.Text>,
                },
                {
                  title: "已登记",
                  key: "uses",
                  width: 110,
                  render: (_, c) => `${c.uses} / ${c.maxUses} 台`,
                },
                {
                  title: "有效期至",
                  key: "expiresAt",
                  width: 170,
                  render: (_, c) => time(c.expiresAt),
                },
                {
                  title: "创建",
                  key: "created",
                  width: 200,
                  render: (_, c) => `${c.createdBy} · ${time(c.createdAt)}`,
                },
                {
                  title: "状态",
                  key: "state",
                  width: 90,
                  render: (_, c) => {
                    const [text, color] = codeState(c);
                    return <Tag color={color}>{text}</Tag>;
                  },
                },
                {
                  title: "操作",
                  key: "actions",
                  width: 80,
                  render: (_, c) =>
                    codeState(c)[0] === "有效" && (
                      <Popconfirm
                        title="撤销这个登记码？"
                        description="撤销后不能再用它登记新电脑，已登记的电脑不受影响。"
                        okText="撤销"
                        okButtonProps={{ danger: true }}
                        onConfirm={() => revoke(c.id)}
                      >
                        <Button type="link" danger size="small">
                          撤销
                        </Button>
                      </Popconfirm>
                    ),
                },
              ]}
            />
          </Fresh>
        </Panel>
      </Space>
    </>
  );
}
