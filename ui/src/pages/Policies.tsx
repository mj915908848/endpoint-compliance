import { useEffect, useMemo, useState } from "react";
import {
  Alert,
  App,
  Button,
  Checkbox,
  Col,
  Descriptions,
  Input,
  Row,
  Space,
  Steps,
  Table,
  Tag,
  Typography,
} from "antd";
import { request } from "../api";
import { useResource, useRefresh } from "../useResource";
import {
  controlLabel,
  Empty,
  ErrorNotice,
  errorText,
  Fresh,
  moduleLabel,
  PageHeading,
  Panel,
  time,
} from "../components";
import { role } from "../session";
import type { Draft, Policy, Session, SignedPolicy } from "../types";

const modeLabel = (mode: string) => (mode === "Enforce" ? "强制模式" : "审计模式");

export function Policies({ session }: { session: Session }) {
  const { message } = App.useApp();
  const refresh = useRefresh();
  const current = useResource<SignedPolicy>("/api/policies/current"),
    drafts = useResource<Draft[]>("/api/policies/drafts");
  const policy = useMemo(() => {
    try {
      return current.data ? (JSON.parse(current.data.payload) as Policy) : null;
    } catch {
      return null;
    }
  }, [current.data]);
  const [editor, setEditor] = useState(""),
    [reviewed, setReviewed] = useState(false),
    [error, setError] = useState<string | null>(null),
    [busy, setBusy] = useState(false);
  // Next version of a document: keeps the deployment's mode and targets, renews the validity window.
  const nextVersion = (base: Policy) =>
    JSON.stringify(
      {
        ...base,
        mode: policy?.mode ?? base.mode,
        targetDeviceIds: policy?.targetDeviceIds ?? base.targetDeviceIds,
        version: (policy?.version ?? 0) + 1,
        issuedAt: new Date().toISOString(),
        expiresAt: new Date(Date.now() + 30 * 86400000).toISOString(),
      },
      null,
      2,
    );
  useEffect(() => {
    if (policy && !editor) setEditor(nextVersion(policy));
  }, [policy, editor]);
  // Rule content shipped with this server version; differs from the published policy after an upgrade.
  const template = useResource<Policy>("/api/policies/template");
  const rules = (p: Policy) =>
    JSON.stringify([
      p.products,
      p.blockDomains,
      p.approvedNetworkAdapters ?? [],
      p.requiredModules,
    ]);
  const outdated = !!policy && !!template.data && rules(policy) !== rules(template.data);
  function loadTemplate() {
    if (!template.data) return;
    setEditor(nextVersion(template.data));
    setReviewed(false);
    document.getElementById("policy-editor")?.scrollIntoView({ behavior: "smooth" });
    message.info("已载入内置最新规则，请核对后保存为草稿。");
  }

  async function mutate(path: string, body: unknown, done: string) {
    setBusy(true);
    setError(null);
    try {
      await request(path, { method: "POST", body, csrfToken: session.csrfToken });
      message.success(done);
      refresh();
      return true;
    } catch (e) {
      setError(errorText(e));
      return false;
    } finally {
      setBusy(false);
    }
  }
  async function save() {
    let document: Policy;
    try {
      document = JSON.parse(editor) as Policy;
      if (!document || typeof document !== "object" || Array.isArray(document)) throw Error();
    } catch {
      setError("策略内容不是有效的 JSON。");
      return;
    }
    if (policy && document.version <= policy.version) {
      setError(`新版本号必须大于当前版本 v${policy.version}。`);
      return;
    }
    if (
      await mutate(
        "/api/policies/drafts",
        { document, impactReviewed: reviewed },
        "草稿已保存，等待其他审核人审核。",
      )
    )
      setReviewed(false);
  }

  return (
    <>
      <PageHeading
        title="策略管理"
        description="策略需经过“起草、影响评估、独立审核、发布”四步。强制模式发布前，管理端会再次校验终端是否具备相应的防护能力。"
        action={<Button onClick={refresh}>刷新</Button>}
      />
      <Space orientation="vertical" size={16} style={{ width: "100%" }}>
        <ErrorNotice error={error} />
        {outdated && role(session, "Publisher") && (
          <Alert
            type="info"
            showIcon
            title="当前生效策略与本版本管理端的内置规则不同"
            description="管理端升级后会带来新的检测规则（如新增产品、网卡白名单）。载入后按正常流程保存草稿、由审核人审核并发布，终端在下次联系管理端时生效。"
            action={<Button onClick={loadTemplate}>载入内置最新规则</Button>}
          />
        )}
        <Row gutter={[16, 16]}>
          <Col xs={24} xl={14}>
            <Panel title="当前生效策略">
              <Fresh error={current.error} loading={current.loading}>
                {policy ? (
                  <Descriptions
                    size="small"
                    bordered
                    column={1}
                    items={[
                      {
                        label: "版本",
                        children: (
                          <Space>
                            <Typography.Text strong>v{policy.version}</Typography.Text>
                            <Tag color={policy.mode === "Enforce" ? "warning" : "default"}>
                              {modeLabel(policy.mode)}
                            </Tag>
                            <Typography.Text type="secondary" className="mono">
                              {policy.policyId}
                            </Typography.Text>
                          </Space>
                        ),
                      },
                      {
                        label: "有效期",
                        children: `${time(policy.issuedAt)} 至 ${time(policy.expiresAt)}`,
                      },
                      {
                        label: "适用终端",
                        children: policy.targetDeviceIds.length
                          ? `${policy.targetDeviceIds.length} 台指定终端`
                          : "全部终端",
                      },
                      { label: "禁用产品", children: `${policy.products.length} 项` },
                      { label: "禁止访问的域名", children: `${policy.blockDomains.length} 项` },
                      {
                        label: "已批准的网卡",
                        children: policy.approvedNetworkAdapters?.length
                          ? policy.approvedNetworkAdapters.join("、")
                          : "无",
                      },
                      {
                        label: "必需检查项",
                        children: policy.requiredModules.map(moduleLabel).join("、") || "未定义",
                      },
                      {
                        label: "必需防护措施",
                        children: policy.requiredControls.map(controlLabel).join("、") || "无",
                      },
                    ]}
                  />
                ) : (
                  <Empty title="无法解析当前策略" />
                )}
              </Fresh>
            </Panel>
          </Col>
          <Col xs={24} xl={10}>
            <Panel title="发布流程">
              <Steps
                orientation="vertical"
                size="small"
                current={-1}
                items={[
                  { title: "起草", content: "发布人编辑策略内容并确认适用终端。" },
                  { title: "影响评估", content: "确认已评估目标终端、业务影响和例外情况。" },
                  { title: "独立审核", content: "由另一名具有审核权限的账号审核通过。" },
                  { title: "发布", content: "发布人发布；管理端校验强制模式所需的防护能力。" },
                ]}
              />
              <Alert
                type="info"
                showIcon
                title="审计模式只检查、不拦截。发布成功仅表示管理端已签发策略，终端是否已接收和生效，请以终端上报为准。"
              />
            </Panel>
          </Col>
        </Row>
        <Panel title="策略草稿">
          <Fresh error={drafts.error} loading={drafts.loading}>
            <Table<Draft>
              rowKey="id"
              dataSource={drafts.data ?? []}
              size="middle"
              scroll={{ x: 640 }}
              pagination={{ pageSize: 10, hideOnSinglePage: true }}
              locale={{ emptyText: <Empty title="暂无策略草稿" /> }}
              columns={[
                {
                  title: "草稿",
                  key: "id",
                  render: (_, d) => <span className="mono">{d.id.slice(0, 12)}</span>,
                },
                {
                  title: "版本",
                  key: "version",
                  render: (_, d) => `v${d.document.version} · ${modeLabel(d.document.mode)}`,
                },
                {
                  title: "起草 / 审核",
                  key: "people",
                  render: (_, d) => (
                    <Space orientation="vertical" size={0}>
                      <span>起草：{d.createdBy}</span>
                      <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                        审核：{d.approvedBy ?? "未审核"}
                      </Typography.Text>
                    </Space>
                  ),
                },
                {
                  title: "状态",
                  key: "state",
                  render: (_, d) => (
                    <Tag color={d.published ? "success" : d.approvedBy ? "processing" : "warning"}>
                      {d.published ? "已发布" : d.approvedBy ? "已审核" : "待审核"}
                    </Tag>
                  ),
                },
                {
                  title: "操作",
                  key: "actions",
                  render: (_, d) => (
                    <Space>
                      {!d.published &&
                        !d.approvedBy &&
                        role(session, "Reviewer") &&
                        d.createdBy !== session.username && (
                          <Button
                            size="small"
                            disabled={busy}
                            onClick={() =>
                              mutate(
                                `/api/policies/${encodeURIComponent(d.id)}/approve`,
                                {},
                                "审核通过。",
                              )
                            }
                          >
                            审核通过
                          </Button>
                        )}
                      {!d.published && d.approvedBy && role(session, "Publisher") && (
                        <Button
                          size="small"
                          type="primary"
                          disabled={busy}
                          onClick={() =>
                            mutate(
                              `/api/policies/${encodeURIComponent(d.id)}/publish`,
                              {},
                              "策略已发布，请留意终端的接收和生效情况。",
                            )
                          }
                        >
                          发布
                        </Button>
                      )}
                    </Space>
                  ),
                },
              ]}
            />
          </Fresh>
        </Panel>
        {role(session, "Publisher") && (
          <Panel title="新建策略草稿" id="policy-editor">
            <Typography.Paragraph type="secondary">
              已根据当前策略生成下一版本的初稿。可在 JSON
              中编辑禁用产品、域名、适用终端和防护要求，提交后由管理端校验格式和约束。
            </Typography.Paragraph>
            <Input.TextArea
              aria-label="策略内容（JSON）"
              className="json-editor"
              spellCheck={false}
              autoSize={{ minRows: 12, maxRows: 28 }}
              value={editor}
              onChange={(e) => {
                setEditor(e.target.value);
                setReviewed(false);
              }}
            />
            <Space style={{ marginTop: 12 }} wrap>
              <Checkbox checked={reviewed} onChange={(e) => setReviewed(e.target.checked)}>
                我已评估适用终端、业务影响、例外情况和防护能力
              </Checkbox>
              <Button type="primary" loading={busy} disabled={!reviewed || !editor} onClick={save}>
                保存草稿
              </Button>
            </Space>
          </Panel>
        )}
      </Space>
    </>
  );
}
