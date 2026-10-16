import { useEffect, useMemo, useState } from "react";
import {
  Alert,
  App,
  Button,
  Input,
  Modal,
  Segmented,
  Space,
  Table,
  Tag,
  Tooltip,
  Typography,
} from "antd";
import { PlusOutlined } from "@ant-design/icons";
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
import type { DeviceSummary, Policy, PolicyHistoryItem, PolicyListItem, Session } from "../types";

const parse = (signed: { payload: string } | null | undefined) => {
  try {
    return signed ? (JSON.parse(signed.payload) as Policy) : null;
  } catch {
    return null;
  }
};

const NEW = "__new__";

export function Policies({ session }: { session: Session }) {
  const { message, modal } = App.useApp();
  const refresh = useRefresh();
  const list = useResource<PolicyListItem[]>("/api/policies"),
    devices = useResource<DeviceSummary[]>("/api/devices"),
    // Rule content shipped with this server version; differs from the published policy after an upgrade.
    template = useResource<Policy>("/api/policies/template");
  const policies = useMemo(
    () =>
      (list.data ?? []).flatMap((item) => {
        const doc = parse(item.release);
        return doc ? [{ ...item, doc }] : [];
      }),
    [list.data],
  );
  const canPublish = role(session, "Publisher");
  // The selected policy's key, or NEW for a policy not yet published.
  const [selected, setSelected] = useState("default");
  const creating = selected === NEW;
  const entry = policies.find((p) => p.key === selected);
  const defaultDoc = policies.find((p) => p.isDefault)?.doc ?? null;
  const policy = creating ? null : (entry?.doc ?? null);
  const isDefault = !creating && (entry?.isDefault ?? true);
  const [draft, setDraft] = useState<Policy | null>(null),
    [error, setError] = useState<string | null>(null),
    [busy, setBusy] = useState(false),
    [json, setJson] = useState<string | null>(null),
    [history, setHistory] = useState(false);
  useEffect(() => {
    if (policy && !draft) setDraft(policy);
  }, [policy, draft]);
  const dirty = creating ? !!draft : !!policy && !!draft && !sameContent(policy, draft);
  // Devices another named policy already lists cannot be chosen here.
  const takenBy = new Map(
    policies
      .filter((p) => !p.isDefault && p.key !== selected)
      .flatMap((p) => p.doc.targetDeviceIds.map((id) => [id, p.doc.policyId] as const)),
  );

  function select(key: string) {
    const go = () => {
      setSelected(key);
      setError(null);
      if (key === NEW && defaultDoc)
        // A new policy starts from the default policy's rules, in audit mode, with no devices.
        setDraft({ ...defaultDoc, policyId: "", mode: "Audit", targetDeviceIds: [] });
      else setDraft(policies.find((p) => p.key === key)?.doc ?? null);
    };
    if (!dirty) return go();
    modal.confirm({
      title: "放弃未发布的修改？",
      content: "切换后，当前策略未发布的修改会丢失。",
      okText: "放弃并切换",
      cancelText: "继续编辑",
      onOk: go,
    });
  }

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

  function restore(old: Policy) {
    setDraft(old);
    setHistory(false);
    message.info(`已载入 v${old.version} 的内容，核对后点击“保存并发布”即可恢复。`);
  }

  function publish() {
    if (!draft || (!policy && !creating)) return;
    const changes = creating
      ? [
          `新建策略“${draft.policyId || "（未命名）"}”，适用 ${draft.targetDeviceIds.length} 台终端`,
          "这些终端改用这份策略，其余终端仍使用默认策略",
        ]
      : describeChanges(policy!, draft);
    modal.confirm({
      title: creating ? "发布新策略？" : `发布“${policy!.policyId}”的新版本？`,
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
          const published = await request<PolicyListItem>(
            `/api/policies/${creating ? "new" : encodeURIComponent(selected)}`,
            { method: "POST", body: draft, csrfToken: session.csrfToken },
          );
          const doc = parse(published.release);
          setSelected(published.key);
          setDraft(doc);
          message.success(`“${doc?.policyId}” v${doc?.version} 已发布。`);
          refresh();
        } catch (e) {
          setError(errorText(e));
        } finally {
          setBusy(false);
        }
      },
    });
  }

  function remove() {
    if (!entry || entry.isDefault) return;
    modal.confirm({
      title: `删除策略“${entry.doc.policyId}”？`,
      content: `它适用的 ${entry.devices} 台终端将改用默认策略，终端下次联系管理端时生效。`,
      okText: "删除",
      okButtonProps: { danger: true },
      cancelText: "取消",
      onOk: async () => {
        try {
          await request(`/api/policies/${encodeURIComponent(entry.key)}`, {
            method: "DELETE",
            csrfToken: session.csrfToken,
          });
          message.success(`已删除“${entry.doc.policyId}”。`);
          setSelected("default");
          setDraft(defaultDoc);
          refresh();
        } catch (e) {
          message.error(errorText(e));
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
          creating ? (
            "新建一份策略，指定适用的终端；其余终端仍使用默认策略。"
          ) : policy ? (
            <Space size={8} wrap>
              <span>
                {policy.policyId} · 当前生效 v{policy.version} · 适用 {entry?.devices ?? 0} 台终端
              </span>
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
            {entry && !creating && <Button onClick={() => setHistory(true)}>历史版本</Button>}
            <Button onClick={refresh}>刷新</Button>
            {canPublish && entry && !entry.isDefault && !creating && (
              <Button danger onClick={remove}>
                删除策略
              </Button>
            )}
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
        {policies.length > 0 && (
          <Space wrap size={12}>
            <Segmented
              aria-label="选择策略"
              value={selected}
              onChange={select}
              options={[
                ...policies.map((p) => ({
                  value: p.key,
                  label: `${p.doc.policyId}${p.isDefault ? "（默认）" : ""} · ${p.devices} 台`,
                })),
                ...(creating ? [{ value: NEW, label: "新策略（未发布）" }] : []),
              ]}
            />
            {canPublish && !creating && (
              <Button icon={<PlusOutlined />} onClick={() => select(NEW)}>
                新建策略
              </Button>
            )}
          </Space>
        )}
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
        <Fresh error={list.error} loading={list.loading || !draft}>
          {draft && (
            <PolicyEditor
              key={selected}
              value={draft}
              onChange={setDraft}
              devices={devices.data ?? []}
              readOnly={!canPublish}
              isDefault={isDefault}
              takenBy={takenBy}
            />
          )}
        </Fresh>
      </Space>
      {canPublish && dirty && (
        <div className="policy-bar" role="region" aria-label="未发布的修改">
          <Typography.Text>有未保存的修改，发布后终端才会按新策略检查</Typography.Text>
          <Space>
            <Button onClick={() => (creating ? select("default") : setDraft(policy))}>
              {creating ? "取消新建" : "放弃修改"}
            </Button>
            <Button type="primary" loading={busy} onClick={publish}>
              保存并发布
            </Button>
          </Space>
        </div>
      )}
      {history && policy && (
        <PolicyHistory
          policyKey={selected}
          current={policy}
          canRestore={canPublish}
          onRestore={restore}
          onClose={() => setHistory(false)}
        />
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

/** A policy's earlier releases; restoring one loads it into the editor to be published as a new version. */
function PolicyHistory({
  policyKey,
  current,
  canRestore,
  onRestore,
  onClose,
}: {
  policyKey: string;
  current: Policy;
  canRestore: boolean;
  onRestore: (doc: Policy) => void;
  onClose: () => void;
}) {
  const items = useResource<PolicyHistoryItem[]>(
    `/api/policies/${encodeURIComponent(policyKey)}/history`,
  );
  const rows = (items.data ?? []).flatMap((item) => {
    const doc = parse(item.release);
    return doc ? [{ ...item, doc }] : [];
  });
  return (
    <Modal
      open
      title={`“${current.policyId}”的历史版本`}
      footer={null}
      width={760}
      onCancel={onClose}
    >
      <Typography.Paragraph type="secondary">
        恢复会把所选版本的内容载入编辑器，核对后“保存并发布”，作为新版本下发给终端。展开一行可查看它与当前版本的差别。
      </Typography.Paragraph>
      <Fresh error={items.error} loading={items.loading}>
        <Table
          rowKey="version"
          dataSource={rows}
          size="small"
          pagination={rows.length > 10 ? { pageSize: 10, showSizeChanger: false } : false}
          expandable={{
            rowExpandable: (r) => r.version !== current.version,
            expandedRowRender: (r) => {
              const changes = describeChanges(current, r.doc);
              return changes.length ? (
                <ul className="report-list">
                  {changes.map((c) => (
                    <li key={c}>恢复后 {c}</li>
                  ))}
                </ul>
              ) : (
                <Typography.Text type="secondary">内容与当前版本相同</Typography.Text>
              );
            },
          }}
          columns={[
            {
              title: "版本",
              key: "version",
              width: 120,
              render: (_, r) => (
                <Space size={4}>
                  <span>v{r.version}</span>
                  {r.version === current.version && <Tag color="success">当前</Tag>}
                </Space>
              ),
            },
            { title: "发布时间", key: "at", render: (_, r) => time(r.publishedAt) },
            { title: "发布人", key: "by", render: (_, r) => r.publishedBy || "—" },
            {
              title: "内容",
              key: "content",
              render: (_, r) =>
                `${modeLabel(r.doc.mode)} · 产品 ${r.doc.products.length} 个` +
                (r.doc.targetDeviceIds.length ? ` · 终端 ${r.doc.targetDeviceIds.length} 台` : ""),
            },
            ...(canRestore
              ? [
                  {
                    title: "",
                    key: "restore",
                    width: 110,
                    render: (_: unknown, r: (typeof rows)[number]) =>
                      r.version !== current.version && (
                        <Button size="small" onClick={() => onRestore(r.doc)}>
                          恢复此版本
                        </Button>
                      ),
                  },
                ]
              : []),
          ]}
        />
      </Fresh>
    </Modal>
  );
}
