import { useEffect, useMemo, useState } from "react";
import { request } from "../api";
import { useResource } from "../useResource";
import {
  Badge,
  Empty,
  ErrorNotice,
  time,
  errorText,
  Panel,
  Fresh,
  PageHeading,
} from "../components";
import { role } from "../session";
import type { Draft, Policy, Session, SignedPolicy } from "../types";

export function Policies({
  session,
  revision,
  refresh,
}: {
  session: Session;
  revision: number;
  refresh: () => void;
}) {
  const current = useResource<SignedPolicy>("/api/policies/current", revision),
    drafts = useResource<Draft[]>("/api/policies/drafts", revision);
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
    [notice, setNotice] = useState<string | null>(null),
    [busy, setBusy] = useState(false);
  useEffect(() => {
    if (policy && !editor)
      setEditor(
        JSON.stringify(
          {
            ...policy,
            version: policy.version + 1,
            issuedAt: new Date().toISOString(),
            expiresAt: new Date(Date.now() + 30 * 86400000).toISOString(),
          },
          null,
          2,
        ),
      );
  }, [policy, editor]);
  async function mutate(path: string, body: unknown, message: string) {
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      await request(path, {
        method: "POST",
        body,
        csrfToken: session.csrfToken,
      });
      setNotice(message);
      refresh();
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(false);
    }
  }
  function save() {
    let document: Policy;
    try {
      document = JSON.parse(editor) as Policy;
      if (!document || typeof document !== "object" || Array.isArray(document)) throw Error();
    } catch {
      setError("策略 JSON 格式无效");
      return;
    }
    if (policy && document.version <= policy.version) {
      setError("新版本号必须大于当前版本");
      return;
    }
    mutate(
      "/api/policies/drafts",
      { document, impactReviewed: reviewed },
      "草稿已保存，等待独立审核。",
    );
  }
  return (
    <>
      <PageHeading
        kicker="GOVERNANCE / POLICY"
        title="策略与规则"
        description="草稿、影响确认、独立复核、发布分步记录；强制策略由服务端再次校验设备与执行能力。"
        action={
          <button className="secondary" onClick={refresh}>
            刷新策略
          </button>
        }
      />
      <ErrorNotice error={error} />
      {notice && (
        <div className="success-notice" role="status">
          {notice}
        </div>
      )}
      <div className="detail-grid">
        <Panel eyebrow="CURRENT RELEASE" title="当前已签名策略">
          <Fresh error={current.error} loading={current.loading}>
            {policy ? (
              <>
                <div className="policy-meta">
                  <Badge tone={policy.mode === "Enforce" ? "warning" : "neutral"}>
                    {policy.mode === "Audit" ? "审计模式" : "强制模式"}
                  </Badge>
                  <strong>v{policy.version}</strong>
                  <span>{policy.policyId}</span>
                </div>
                <dl className="facts">
                  <dt>有效期</dt>
                  <dd>
                    {time(policy.issuedAt)} — {time(policy.expiresAt)}
                  </dd>
                  <dt>目标设备</dt>
                  <dd>{policy.targetDeviceIds.length} 台</dd>
                  <dt>产品规则</dt>
                  <dd>{policy.products.length} 项</dd>
                  <dt>域名规则</dt>
                  <dd>{policy.blockDomains.length} 项</dd>
                  <dt>必需执行层</dt>
                  <dd>{policy.requiredControls.join("、") || "未定义"}</dd>
                </dl>
                <p className="muted small">
                  页面显示服务端签名文档内容；发布和实际生效状态分别由服务端与终端报告。
                </p>
              </>
            ) : (
              <Empty title="无法解析当前策略" />
            )}
          </Fresh>
        </Panel>
        <Panel eyebrow="PUBLISH FLOW" title="审批边界">
          <ol className="flow-list">
            <li>编辑策略文档与规则，确认目标设备。</li>
            <li>检查影响并勾选“已审阅影响”。</li>
            <li>由其他 Reviewer 账号独立审批。</li>
            <li>Publisher 发布；服务端校验强制执行能力。</li>
          </ol>
          <div className="callout">
            审计模式不会声称阻断生效。发布成功也不代表终端已收到、应用或验证策略。
          </div>
        </Panel>
      </div>
      <Panel eyebrow="DRAFTS" title="草稿与审批">
        {" "}
        <Fresh error={drafts.error} loading={drafts.loading}>
          {drafts.data?.length ? (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>草稿</th>
                    <th>模式 / 版本</th>
                    <th>创建 / 审批</th>
                    <th>状态</th>
                    <th>操作</th>
                  </tr>
                </thead>
                <tbody>
                  {drafts.data.map((d) => (
                    <tr key={d.id}>
                      <td className="mono">{d.id.slice(0, 12)}</td>
                      <td>
                        {d.document.mode} · v{d.document.version}
                      </td>
                      <td>
                        {d.createdBy}
                        <small>复核：{d.approvedBy ?? "待审批"}</small>
                      </td>
                      <td>
                        <Badge tone={d.published ? "good" : d.approvedBy ? "neutral" : "warning"}>
                          {d.published ? "已发布" : d.approvedBy ? "已审批" : "待审批"}
                        </Badge>
                      </td>
                      <td>
                        <div className="inline">
                          {!d.published &&
                            role(session, "Reviewer") &&
                            d.createdBy !== session.username && (
                              <button
                                className="secondary compact"
                                disabled={busy}
                                onClick={() =>
                                  mutate(
                                    `/api/policies/${encodeURIComponent(d.id)}/approve`,
                                    {},
                                    "草稿已审批。",
                                  )
                                }
                              >
                                审批
                              </button>
                            )}
                          {!d.published && d.approvedBy && role(session, "Publisher") && (
                            <button
                              className="primary compact"
                              disabled={busy}
                              onClick={() =>
                                mutate(
                                  `/api/policies/${encodeURIComponent(d.id)}/publish`,
                                  {},
                                  "发布请求已完成，请核对终端实际应用状态。",
                                )
                              }
                            >
                              发布
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <Empty title="暂无策略草稿" />
          )}
        </Fresh>
      </Panel>
      {role(session, "Publisher") && (
        <Panel eyebrow="EDITOR" title="创建策略草稿">
          <p className="muted">
            从当前策略生成下一版本初稿。使用 JSON
            编辑产品、域名、目标设备及执行要求；格式与约束由管理端校验。
          </p>
          <label className="block-label">
            策略文档 JSON
            <textarea
              className="json-editor"
              spellCheck={false}
              value={editor}
              onChange={(e) => {
                setEditor(e.target.value);
                setReviewed(false);
              }}
            />
          </label>
          <label className="checkbox">
            <input
              type="checkbox"
              checked={reviewed}
              onChange={(e) => setReviewed(e.target.checked)}
            />
            已审阅目标设备、业务影响、例外和执行能力
          </label>
          <div className="form-actions">
            <button className="primary" disabled={busy || !reviewed || !editor} onClick={save}>
              {busy ? "正在提交…" : "保存草稿"}
            </button>
          </div>
        </Panel>
      )}
    </>
  );
}
