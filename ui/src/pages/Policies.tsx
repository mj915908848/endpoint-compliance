import { useEffect, useMemo, useState } from "react";
import { Alert, App, Button, Input, Modal, Space, Tag, Tooltip, Typography } from "antd";
import { request } from "../api";
import { useResource, useRefresh } from "../useResource";
import {
  describeChanges,
  ErrorNotice,
  errorText,
  Fresh,
  modeLabel,
  PageHeading,
  PolicyEditor,
  sameContent,
  time,
} from "../components";
import { role } from "../session";
import type { DeviceSummary, Policy, Session, SignedPolicy } from "../types";

const parse = (signed: SignedPolicy | null | undefined) => {
  try {
    return signed ? (JSON.parse(signed.payload) as Policy) : null;
  } catch {
    return null;
  }
};

export function Policies({ session }: { session: Session }) {
  const { message, modal } = App.useApp();
  const refresh = useRefresh();
  const current = useResource<SignedPolicy>("/api/policies/current"),
    devices = useResource<DeviceSummary[]>("/api/devices"),
    // Rule content shipped with this server version; differs from the published policy after an upgrade.
    template = useResource<Policy>("/api/policies/template");
  const policy = useMemo(() => parse(current.data), [current.data]);
  const canPublish = role(session, "Publisher");
  const [draft, setDraft] = useState<Policy | null>(null),
    [error, setError] = useState<string | null>(null),
    [busy, setBusy] = useState(false),
    [json, setJson] = useState<string | null>(null);
  useEffect(() => {
    if (policy && !draft) setDraft(policy);
  }, [policy, draft]);
  const dirty = !!policy && !!draft && !sameContent(policy, draft);

  const rules = (p: Policy) =>
    JSON.stringify([
      p.products,
      p.blockDomains,
      p.approvedNetworkAdapters ?? [],
      p.requiredModules,
    ]);
  const outdated = !!draft && !!template.data && rules(draft) !== rules(template.data);
  function loadTemplate() {
    if (!template.data || !draft) return;
    // Keep this deployment's own name, mode and targets; take the rule content from the template.
    setDraft({
      ...template.data,
      policyId: draft.policyId,
      mode: draft.mode,
      targetDeviceIds: draft.targetDeviceIds,
    });
    message.info("已载入内置最新规则，核对后点击“保存并发布”即可生效。");
  }

  function publish() {
    if (!policy || !draft) return;
    const changes = describeChanges(policy, draft);
    modal.confirm({
      title: `发布策略 v${policy.version + 1}？`,
      width: 560,
      content: (
        <Space orientation="vertical" size={8} style={{ width: "100%" }}>
          <ul className="report-list">
            {changes.map((c) => (
              <li key={c}>{c}</li>
            ))}
          </ul>
          <Typography.Text type="secondary">
            终端下次联系管理端时接收新策略，之后的检查按新规则判断。
          </Typography.Text>
        </Space>
      ),
      okText: "发布",
      cancelText: "取消",
      onOk: async () => {
        setBusy(true);
        setError(null);
        try {
          const signed = await request<SignedPolicy>("/api/policies", {
            method: "POST",
            body: draft,
            csrfToken: session.csrfToken,
          });
          setDraft(parse(signed));
          message.success(`策略 v${policy.version + 1} 已发布。`);
          refresh();
        } catch (e) {
          setError(errorText(e));
        } finally {
          setBusy(false);
        }
      },
    });
  }

  function applyJson() {
    try {
      const value = JSON.parse(json ?? "") as Policy;
      if (!value || typeof value !== "object" || !Array.isArray(value.products)) throw Error();
      setDraft({ ...draft!, ...value });
      setJson(null);
    } catch {
      message.error("不是有效的策略 JSON。");
    }
  }

  return (
    <>
      <PageHeading
        title="策略管理"
        description={
          policy ? (
            <Space size={8} wrap>
              <span>当前生效 v{policy.version}</span>
              <Tag color={policy.mode === "Enforce" ? "warning" : "default"}>
                {modeLabel(policy.mode)}
              </Tag>
              <span>
                发布于 {time(policy.issuedAt)}，有效至 {time(policy.expiresAt)}
              </span>
            </Space>
          ) : (
            "正在读取当前策略"
          )
        }
        action={
          <Space wrap>
            {canPublish && (
              <Button disabled={!draft} onClick={() => setJson(JSON.stringify(draft, null, 2))}>
                以 JSON 编辑
              </Button>
            )}
            <Button onClick={refresh}>刷新</Button>
            {canPublish && (
              <Tooltip title={dirty ? undefined : "没有需要保存的修改"}>
                <Button type="primary" disabled={!dirty} loading={busy} onClick={publish}>
                  保存并发布
                </Button>
              </Tooltip>
            )}
          </Space>
        }
      />
      <Space orientation="vertical" size={16} style={{ width: "100%" }}>
        <ErrorNotice error={error} title="发布失败" />
        {!canPublish && (
          <Alert type="info" showIcon title="当前账号只能查看策略，修改和发布需要发布权限。" />
        )}
        {outdated && canPublish && (
          <Alert
            type="info"
            showIcon
            title="管理端内置了更新的检测规则"
            description="例如新增的产品和网卡白名单。载入后会保留当前的策略名称、运行模式和适用终端。"
            action={<Button onClick={loadTemplate}>载入内置最新规则</Button>}
          />
        )}
        <Fresh error={current.error} loading={current.loading || !draft}>
          {draft && (
            <PolicyEditor
              value={draft}
              onChange={setDraft}
              devices={devices.data ?? []}
              readOnly={!canPublish}
            />
          )}
        </Fresh>
      </Space>
      {canPublish && dirty && (
        <div className="policy-bar" role="region" aria-label="未发布的修改">
          <Typography.Text>有未保存的修改，发布后终端才会按新策略检查</Typography.Text>
          <Space>
            <Button onClick={() => setDraft(policy)}>放弃修改</Button>
            <Button type="primary" loading={busy} onClick={publish}>
              保存并发布
            </Button>
          </Space>
        </div>
      )}
      <Modal
        open={json !== null}
        title="以 JSON 编辑策略"
        okText="应用到编辑器"
        cancelText="取消"
        width={760}
        onOk={applyJson}
        onCancel={() => setJson(null)}
      >
        <Typography.Paragraph type="secondary">
          适合批量导入或修改应用程序拦截规则。版本号和有效期由管理端在发布时设置。
        </Typography.Paragraph>
        <Input.TextArea
          aria-label="策略内容（JSON）"
          className="json-editor"
          spellCheck={false}
          autoSize={{ minRows: 12, maxRows: 24 }}
          value={json ?? ""}
          onChange={(e) => setJson(e.target.value)}
        />
      </Modal>
    </>
  );
}
