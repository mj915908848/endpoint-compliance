import { useEffect, useMemo, useState, type ReactNode } from "react";
import { downloadJson, downloadReport, HttpError, request } from "./api";
import {
  AlertCard,
  Badge,
  DeviceState,
  Empty,
  ErrorNotice,
  Loading,
  Login,
  time,
  VerdictBadge,
  verdictLabels,
  errorText,
} from "./components";
import { useResource } from "./useResource";
import type {
  Alert,
  Audit,
  Control,
  DeviceDetail,
  DeviceSummary,
  Draft,
  Policy,
  Report,
  Session,
  SignedPolicy,
  Snapshot,
  Status,
} from "./types";

type Page =
  | "overview"
  | "devices"
  | "alerts"
  | "policies"
  | "registration"
  | "audit"
  | "system";
const pages: { id: Page; label: string; glyph: string; sub: string }[] = [
  { id: "overview", label: "总览", glyph: "◫", sub: "当前态势" },
  { id: "devices", label: "终端设备", glyph: "▤", sub: "设备与报告" },
  { id: "alerts", label: "告警中心", glyph: "◇", sub: "处置记录" },
  { id: "policies", label: "策略发布", glyph: "▣", sub: "规则与审批" },
  { id: "registration", label: "终端登记", glyph: "⊕", sub: "一次性凭据" },
  { id: "audit", label: "审计记录", glyph: "≡", sub: "管理操作" },
  { id: "system", label: "系统状态", glyph: "◉", sub: "能力边界" },
];
const role = (session: Session, name: string) => session.roles.includes(name);
function Panel({
  title,
  eyebrow,
  actions,
  children,
}: {
  title: string;
  eyebrow?: string;
  actions?: ReactNode;
  children: ReactNode;
}) {
  return (
    <section className="panel">
      <div className="panel-head">
        <div>
          {eyebrow && <span className="eyebrow">{eyebrow}</span>}
          <h2>{title}</h2>
        </div>
        {actions}
      </div>
      {children}
    </section>
  );
}
function Fresh({
  error,
  loading,
  children,
}: {
  error: string | null;
  loading: boolean;
  children: ReactNode;
}) {
  return error ? (
    <ErrorNotice error={error} />
  ) : loading ? (
    <Loading />
  ) : (
    <>{children}</>
  );
}
function Metric({
  label,
  value,
  tone,
  caption,
}: {
  label: string;
  value: string | number;
  tone?: string;
  caption?: string;
}) {
  return (
    <div className={`metric ${tone ?? ""}`}>
      <span>{label}</span>
      <strong>{value}</strong>
      {caption && <small>{caption}</small>}
    </div>
  );
}
function PageHeading({
  kicker,
  title,
  description,
  action,
}: {
  kicker: string;
  title: string;
  description: string;
  action?: ReactNode;
}) {
  return (
    <div className="page-heading">
      <div>
        <span className="eyebrow">{kicker}</span>
        <h1>{title}</h1>
        <p>{description}</p>
      </div>
      {action}
    </div>
  );
}
function DeviceTable({
  devices,
  onSelect,
}: {
  devices: DeviceSummary[];
  onSelect: (id: string) => void;
}) {
  return devices.length === 0 ? (
    <Empty title="暂无终端">
      使用一次性登记码为终端登记，终端首次上报后会显示在这里。
    </Empty>
  ) : (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>终端</th>
            <th>当前结论 / 连线</th>
            <th>策略与防护</th>
            <th>最近采集</th>
            <th>操作</th>
          </tr>
        </thead>
        <tbody>
          {devices.map((d) => (
            <tr key={d.id}>
              <td>
                <strong>{d.hostName}</strong>
                <small className="mono">{d.id}</small>
              </td>
              <td>
                <DeviceState device={d} />
              </td>
              <td>
                <strong>
                  目标 v{d.targetPolicyVersion} · 已应用 v
                  {d.appliedPolicyVersion}
                </strong>
                <small>{d.protectionStatus || "状态未知"}</small>
              </td>
              <td>
                {time(d.lastScan)}
                <small>心跳 {time(d.lastHeartbeat)}</small>
              </td>
              <td>
                <button className="link-button" onClick={() => onSelect(d.id)}>
                  查看详情 →
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
function Overview({
  openDevice,
  openAlerts,
  revision,
}: {
  openDevice: (id: string) => void;
  openAlerts: () => void;
  revision: number;
}) {
  const devices = useResource<DeviceSummary[]>("/api/devices", revision),
    alerts = useResource<Alert[]>("/api/alerts", revision);
  const stats = useMemo(() => {
    const all = devices.data ?? [];
    return {
      pass: all.filter(
        (d) => d.onlineState === "Online" && d.currentVerdict === "PASS",
      ).length,
      fail: all.filter(
        (d) => d.onlineState === "Online" && d.currentVerdict === "FAIL",
      ).length,
      unknown: all.filter(
        (d) => d.onlineState === "Online" && d.currentVerdict === "UNKNOWN",
      ).length,
      offline: all.filter((d) => d.onlineState !== "Online").length,
    };
  }, [devices.data]);
  return (
    <>
      <PageHeading
        kicker="OPERATIONS / OVERVIEW"
        title="终端合规总览"
        description="以管理端当前事实为准。失联设备单列，上次结论只作为历史记录。"
      />
      <Fresh error={devices.error} loading={devices.loading}>
        <div className="metric-grid">
          <Metric
            label="当前范围内通过"
            value={stats.pass}
            tone="good"
            caption="仅当前在线终端"
          />
          <Metric
            label="当前不通过"
            value={stats.fail}
            tone="danger"
            caption="确认违规证据"
          />
          <Metric
            label="无法判断"
            value={stats.unknown}
            tone="warning"
            caption="检查或执行能力不足"
          />
          <Metric
            label="失联 / 疑似失联"
            value={stats.offline}
            tone="neutral"
            caption="历史通过不计入当前通过"
          />
        </div>
        <div className="overview-grid">
          <Panel eyebrow="DEVICE FLEET" title="需要关注的终端">
            <DeviceTable
              devices={(devices.data ?? [])
                .filter(
                  (d) =>
                    d.currentVerdict !== "PASS" || d.onlineState !== "Online",
                )
                .slice(0, 8)}
              onSelect={openDevice}
            />
            {devices.data?.length === 0 && null}
          </Panel>
          <Panel
            eyebrow="ALERTS"
            title="未恢复告警"
            actions={
              <button className="link-button" onClick={openAlerts}>
                查看全部 →
              </button>
            }
          >
            <Fresh error={alerts.error} loading={alerts.loading}>
              {(alerts.data ?? [])
                .filter((a) => a.state !== "Recovered")
                .slice(0, 5).length === 0 ? (
                <Empty title="当前没有持续告警" />
              ) : (
                <div className="compact-list">
                  {(alerts.data ?? [])
                    .filter((a) => a.state !== "Recovered")
                    .slice(0, 5)
                    .map((a) => (
                      <div className="compact-alert" key={a.id}>
                        <Badge
                          tone={a.type === "Violation" ? "danger" : "warning"}
                        >
                          {a.type === "Violation"
                            ? "确认违规"
                            : a.type === "BlockedAttempt"
                              ? "已阻止尝试"
                              : a.type === "Offline"
                                ? "失联"
                                : "健康与线索"}
                        </Badge>
                        <strong>{a.summary}</strong>
                        <small>
                          {a.hostName} · {time(a.lastSeen)}{" "}
                          {a.acknowledged ? "· 已确认" : ""}
                        </small>
                      </div>
                    ))}
                </div>
              )}
            </Fresh>
          </Panel>
        </div>
      </Fresh>
    </>
  );
}
function DeviceDetailPage({
  id,
  session,
  back,
  revision,
  refresh,
}: {
  id: string;
  session: Session;
  back: () => void;
  revision: number;
  refresh: () => void;
}) {
  const encoded = encodeURIComponent(id),
    detail = useResource<DeviceDetail>(`/api/devices/${encoded}`, revision),
    report = useResource<Report>(
      detail.data?.snapshot ? `/api/devices/${encoded}/report` : null,
      revision,
    );
  const [actionError, setActionError] = useState<string | null>(null),
    [busy, setBusy] = useState(false);
  const d = detail.data?.device;
  async function scan() {
    setBusy(true);
    setActionError(null);
    try {
      await request(`/api/devices/${encoded}/commands`, {
        method: "POST",
        body: { type: "ScanNow" },
        csrfToken: session.csrfToken,
      });
      refresh();
    } catch (e) {
      setActionError(errorText(e));
    } finally {
      setBusy(false);
    }
  }
  async function markdown() {
    setActionError(null);
    try {
      await downloadReport(id);
    } catch (e) {
      setActionError(errorText(e));
    }
  }
  return (
    <>
      <div className="backline">
        <button className="link-button" onClick={back}>
          ← 返回终端列表
        </button>
      </div>
      <PageHeading
        kicker="DEVICE / DETAIL"
        title={d?.hostName ?? "终端详情"}
        description={d ? `设备 ID：${d.id}` : "正在读取设备事实"}
        action={
          <div className="inline">
            {role(session, "Operator") && (
              <button
                className="secondary"
                disabled={busy || !d}
                onClick={scan}
              >
                {busy ? "正在提交…" : "请求重新检查"}
              </button>
            )}
            <button className="secondary" onClick={refresh}>
              刷新状态
            </button>
          </div>
        }
      />
      <ErrorNotice error={actionError} />
      <Fresh error={detail.error} loading={detail.loading}>
        {d && (
          <>
            <div className="metric-grid">
              <Metric
                label="当前检查结论"
                value={
                  d.onlineState === "Online"
                    ? verdictLabels[d.currentVerdict]
                    : "无法判断"
                }
                tone={
                  d.onlineState === "Online" && d.currentVerdict === "PASS"
                    ? "good"
                    : d.onlineState === "Online" && d.currentVerdict === "FAIL"
                      ? "danger"
                      : "warning"
                }
                caption={
                  d.onlineState === "Online"
                    ? "设备在线"
                    : `设备${d.onlineState === "Offline" ? "失联" : "疑似失联"}；上次结论仅供参考`
                }
              />
              <Metric
                label="确认违规对象"
                value={d.violationCount}
                tone={d.violationCount ? "danger" : "neutral"}
              />
              <Metric
                label="目标 / 已应用策略"
                value={`v${d.targetPolicyVersion} / v${d.appliedPolicyVersion}`}
                caption={d.protectionStatus}
              />
              <Metric
                label="待处理命令"
                value={detail.data?.pendingCommands ?? 0}
                caption={`最近心跳 ${time(d.lastHeartbeat)}`}
              />
            </div>
            {d.simulated && (
              <div className="callout warning">
                <strong>模拟终端</strong>
                此设备的采集与执行证据来自模拟环境，不能作为 Windows
                实机防护验收。
              </div>
            )}
            <div className="detail-grid">
              <Panel eyebrow="CURRENT STATE" title="设备与策略">
                <dl className="facts">
                  <dt>当前结论</dt>
                  <dd>
                    <DeviceState device={d} />
                  </dd>
                  <dt>最近采集</dt>
                  <dd>{time(d.lastScan)}</dd>
                  <dt>最近心跳</dt>
                  <dd>{time(d.lastHeartbeat)}</dd>
                  <dt>执行状态</dt>
                  <dd>{d.protectionStatus || "未知"}</dd>
                </dl>
              </Panel>
              <Panel eyebrow="CONTROL VERIFICATION" title="执行层证据">
                <ControlList controls={detail.data?.controls ?? []} />
              </Panel>
            </div>
            <Panel eyebrow="SCAN COVERAGE" title="检查范围与证据">
              {detail.data?.snapshot ? (
                <SnapshotView snapshot={detail.data.snapshot} />
              ) : (
                <Empty title="尚无检查快照">
                  终端需要完成首次扫描后才会产生检查结论与固定报告。
                </Empty>
              )}
            </Panel>
            <Panel
              eyebrow="REPORT"
              title="固定九节报告"
              actions={
                <div className="inline">
                  <button
                    className="secondary compact"
                    disabled={!report.data}
                    onClick={() =>
                      report.data &&
                      downloadJson(
                        report.data,
                        `终端报告-${id.replace(/[^a-zA-Z0-9_-]/g, "_")}.json`,
                      )
                    }
                  >
                    下载 JSON
                  </button>
                  <button
                    className="secondary compact"
                    disabled={!report.data}
                    onClick={markdown}
                  >
                    下载 Markdown
                  </button>
                </div>
              }
            >
              <Fresh error={report.error} loading={report.loading}>
                {report.data ? (
                  <ReportView report={report.data} />
                ) : (
                  <Empty title="尚无报告" />
                )}
              </Fresh>
            </Panel>
          </>
        )}
      </Fresh>
    </>
  );
}
function ControlList({ controls }: { controls: Control[] }) {
  return controls.length === 0 ? (
    <Empty title="暂无执行层证据">
      未上报已验证控制路径，不能推断阻断生效。
    </Empty>
  ) : (
    <div className="stack">
      {controls.map((c, i) => (
        <div className="control-row" key={`${c.id}-${i}`}>
          <div>
            <strong>{c.id}</strong>
            <small>
              版本 v{c.version} · {c.detail}
            </small>
          </div>
          <div className="inline">
            <Badge tone={c.verified ? "good" : "warning"}>
              {c.verified ? "已验证" : "未验证"}
            </Badge>
            <Badge>{c.state}</Badge>
            {c.rebootRequired && <Badge tone="warning">待重启</Badge>}
          </div>
        </div>
      ))}
    </div>
  );
}
function SnapshotView({ snapshot: s }: { snapshot: Snapshot }) {
  return (
    <div className="snapshot">
      <div className="inline">
        <Badge tone={s.simulated ? "warning" : "neutral"}>
          {s.simulated ? "模拟快照" : "终端上报快照"}
        </Badge>
        <span className="muted">
          采集于 {time(s.collectedAt)} · 策略 v{s.policyVersion} · {s.platform}
        </span>
      </div>
      <h3>模块覆盖</h3>
      {s.modules.length === 0 ? (
        <Empty title="没有模块结果" />
      ) : (
        <div className="chips">
          {s.modules.map((m, i) => (
            <div className="module-chip" key={i}>
              <strong>{m.module}</strong>
              <small>
                {m.scope} · {m.status} · {time(m.collectedAt)}
              </small>
              {m.error && <span className="danger-text">{m.error}</span>}
            </div>
          ))}
        </div>
      )}
      <h3>证据清单</h3>
      {s.evidence.length === 0 ? (
        <Empty title="没有上报证据" />
      ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>对象</th>
                <th>类型</th>
                <th>摘要</th>
                <th>来源 / 用户</th>
              </tr>
            </thead>
            <tbody>
              {s.evidence.map((e, i) => (
                <tr key={i}>
                  <td>
                    <strong>{e.productName || e.productId}</strong>
                    <small>{e.productId}</small>
                  </td>
                  <td>
                    <Badge tone={e.confirmed ? "danger" : "warning"}>
                      {e.confirmed ? "确认" : "线索"} · {e.kind}
                    </Badge>
                  </td>
                  <td>{e.summary}</td>
                  <td>
                    {e.source}
                    <small>{e.userSid || "设备范围"}</small>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
const reportNames = [
  "基本信息",
  "检查结论",
  "不通过项",
  "软件安装与进程",
  "代理配置",
  "端口与执行层线索",
  "检查覆盖",
  "处理建议",
  "范围与限制",
];
function ReportView({ report: r }: { report: Report }) {
  const s = r.snapshot;
  const installation = s.evidence.filter((e) =>
    ["Installation", "Process", "Extension"].includes(e.kind),
  );
  const proxy = s.evidence.filter((e) => e.kind === "Proxy");
  const clue = s.evidence.filter((e) =>
    ["Clue", "BlockedAttempt"].includes(e.kind),
  );
  const sections: ReactNode[] = [
    <dl className="facts">
      <dt>终端</dt>
      <dd>
        {s.hostName} · {s.deviceId}
      </dd>
      <dt>平台</dt>
      <dd>{s.platform}</dd>
      <dt>采集时间</dt>
      <dd>{time(s.collectedAt)}</dd>
      <dt>策略</dt>
      <dd>v{s.policyVersion}</dd>
    </dl>,
    <>
      <div className="inline">
        <VerdictBadge verdict={r.verdict} />
        <strong>{r.summary}</strong>
      </div>
      <p>
        违规对象 {r.violationCount} · 证据 {r.evidenceCount} · 防护{" "}
        {r.protectionStatus}
      </p>
    </>,
    <List values={r.reasons} empty="无已报告的不通过原因" />,
    <EvidenceList values={installation} />,
    <EvidenceList values={proxy} />,
    <>
      <EvidenceList values={clue} />
      <ControlList controls={s.controls} />
    </>,
    <>
      <List values={r.coverageGaps} empty="报告没有列出覆盖缺口" />
      <p className="muted">模块结果与时间见上方检查范围。</p>
    </>,
    <p>
      请按客户制度核对确认违规对象、采集缺口与执行层证据。管理员确认告警不会改变技术状态；完成处置后请求终端重新检查。
    </p>,
    <p>
      报告基于当前结构化快照。模拟采集、离线历史、未验证执行层和未覆盖网络路径均不能证明真实防护已生效。
    </p>,
  ];
  return (
    <div className="report-sections">
      {reportNames.map((name, i) => (
        <section key={name}>
          <div className="report-index">{String(i + 1).padStart(2, "0")}</div>
          <div>
            <h3>{name}</h3>
            {sections[i]}
          </div>
        </section>
      ))}
    </div>
  );
}
function List({ values, empty }: { values: string[]; empty: string }) {
  return values.length ? (
    <ul className="plain-list">
      {values.map((v, i) => (
        <li key={i}>{v}</li>
      ))}
    </ul>
  ) : (
    <p className="muted">{empty}</p>
  );
}
function EvidenceList({ values }: { values: Snapshot["evidence"] }) {
  return values.length ? (
    <ul className="plain-list">
      {values.map((e, i) => (
        <li key={i}>
          <strong>{e.productName}</strong> · {e.summary}{" "}
          <span className="muted">（{e.source}）</span>
        </li>
      ))}
    </ul>
  ) : (
    <p className="muted">本节没有对应证据。</p>
  );
}
function Devices({
  session,
  revision,
  refresh,
  initialDevice,
}: {
  session: Session;
  revision: number;
  refresh: () => void;
  initialDevice: string | null;
}) {
  const [id, setId] = useState<string | null>(initialDevice),
    [query, setQuery] = useState(""),
    [filter, setFilter] = useState("all");
  const data = useResource<DeviceSummary[]>("/api/devices", revision);
  const visible = (data.data ?? []).filter(
    (d) =>
      (filter === "all" ||
        (filter === "offline"
          ? d.onlineState !== "Online"
          : d.currentVerdict === filter)) &&
      `${d.hostName} ${d.id}`.toLowerCase().includes(query.toLowerCase()),
  );
  if (id)
    return (
      <DeviceDetailPage
        id={id}
        session={session}
        back={() => setId(null)}
        revision={revision}
        refresh={refresh}
      />
    );
  return (
    <>
      <PageHeading
        kicker="FLEET / DEVICES"
        title="终端设备"
        description="查看当前结论、失联历史、执行证据及固定报告。"
        action={
          <button className="secondary" onClick={refresh}>
            刷新列表
          </button>
        }
      />
      <Panel
        title="设备清单"
        actions={
          <div className="filters">
            <input
              aria-label="搜索设备"
              placeholder="搜索主机名或设备 ID"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
            />
            <select
              aria-label="筛选状态"
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
            >
              <option value="all">全部状态</option>
              <option value="PASS">范围内通过</option>
              <option value="FAIL">不通过</option>
              <option value="UNKNOWN">无法判断</option>
              <option value="offline">失联 / 疑似失联</option>
            </select>
          </div>
        }
      >
        <Fresh error={data.error} loading={data.loading}>
          <DeviceTable devices={visible} onSelect={setId} />
        </Fresh>
      </Panel>
    </>
  );
}
function Alerts({
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
          <select
            aria-label="告警筛选"
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
          >
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
              (filter === "active"
                ? a.state !== "Recovered"
                : a.state === "Recovered"),
          ).length ? (
            <div className="alert-list">
              {(data.data ?? [])
                .filter(
                  (a) =>
                    filter === "all" ||
                    (filter === "active"
                      ? a.state !== "Recovered"
                      : a.state === "Recovered"),
                )
                .map((a) => (
                  <AlertCard
                    key={a.id}
                    alert={a}
                    canAck={role(session, "Operator")}
                    onAck={async (id) => {
                      await request(
                        `/api/alerts/${encodeURIComponent(id)}/ack`,
                        {
                          method: "POST",
                          body: {},
                          csrfToken: session.csrfToken,
                        },
                      );
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
function Policies({
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
      if (!document || typeof document !== "object" || Array.isArray(document))
        throw Error();
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
                  <Badge
                    tone={policy.mode === "Enforce" ? "warning" : "neutral"}
                  >
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
                        <Badge
                          tone={
                            d.published
                              ? "good"
                              : d.approvedBy
                                ? "neutral"
                                : "warning"
                          }
                        >
                          {d.published
                            ? "已发布"
                            : d.approvedBy
                              ? "已审批"
                              : "待审批"}
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
                          {!d.published &&
                            d.approvedBy &&
                            role(session, "Publisher") && (
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
            <button
              className="primary"
              disabled={busy || !reviewed || !editor}
              onClick={save}
            >
              {busy ? "正在提交…" : "保存草稿"}
            </button>
          </div>
        </Panel>
      )}
    </>
  );
}
function Registration({ session }: { session: Session }) {
  const [minutes, setMinutes] = useState(15),
    [result, setResult] = useState<{ code: string; expiresAt: string } | null>(
      null,
    ),
    [error, setError] = useState<string | null>(null),
    [busy, setBusy] = useState(false);
  async function create() {
    setResult(null);
    setError(null);
    setBusy(true);
    try {
      setResult(
        await request("/api/enrollment-codes", {
          method: "POST",
          body: { expiresMinutes: minutes },
          csrfToken: session.csrfToken,
        }),
      );
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(false);
    }
  }
  return (
    <>
      <PageHeading
        kicker="ONBOARDING / ENROLLMENT"
        title="终端登记"
        description="登记码一次性显示，使用后失效。请按客户批准渠道安全交付给终端安装人员。"
      />
      <Panel title="生成一次性登记码">
        <ErrorNotice error={error} />
        {role(session, "Operator") ? (
          <>
            <label className="block-label">
              有效分钟数
              <input
                type="number"
                min="1"
                max="60"
                value={minutes}
                onChange={(e) => setMinutes(Number(e.target.value))}
              />
            </label>
            <button
              className="primary"
              disabled={busy || minutes < 1 || minutes > 60}
              onClick={create}
            >
              {busy ? "正在生成…" : "生成登记码"}
            </button>
            {result && (
              <div className="registration-code" role="status">
                <span className="eyebrow">仅本次展示 · 请立即安全保存</span>
                <strong className="mono">{result.code}</strong>
                <small>
                  到期时间：{time(result.expiresAt)}
                  。页面刷新后无法再次查看此码。
                </small>
              </div>
            )}
          </>
        ) : (
          <div className="callout">
            当前账号无登记权限。需要 Operator 角色。
          </div>
        )}
      </Panel>
    </>
  );
}
function AuditPage({ revision }: { revision: number }) {
  const data = useResource<Audit[]>("/api/audit", revision);
  return (
    <>
      <PageHeading
        kicker="ACCOUNTABILITY / AUDIT"
        title="审计记录"
        description="管理操作按时间倒序呈现，包括策略、告警和终端命令。"
      />
      <Panel title="最近操作">
        <Fresh error={data.error} loading={data.loading}>
          {data.data?.length ? (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>时间</th>
                    <th>操作人</th>
                    <th>动作</th>
                    <th>目标</th>
                  </tr>
                </thead>
                <tbody>
                  {data.data.map((a) => (
                    <tr key={a.id}>
                      <td>{time(a.at)}</td>
                      <td>{a.actor}</td>
                      <td>
                        <strong>{a.action}</strong>
                      </td>
                      <td className="mono">{a.target}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <Empty title="尚无审计记录" />
          )}
        </Fresh>
      </Panel>
    </>
  );
}
function SystemPage({ revision }: { revision: number }) {
  const status = useResource<Status>("/api/status", revision);
  const caps = Array.isArray(status.data?.networkCapabilities)
    ? status.data.networkCapabilities
    : [];
  return (
    <>
      <PageHeading
        kicker="SYSTEM / CAPABILITIES"
        title="系统状态"
        description="查看部署模式、存储与服务端声明的网络能力；真实执行覆盖仍需终端证据。"
      />
      <Panel title="运行环境">
        <Fresh error={status.error} loading={status.loading}>
          {status.data && (
            <dl className="facts">
              <dt>运行模式</dt>
              <dd>
                <Badge
                  tone={status.data.mode === "Production" ? "good" : "warning"}
                >
                  {status.data.mode}
                </Badge>
              </dd>
              <dt>存储</dt>
              <dd>{status.data.storage}</dd>
              <dt>策略密钥 ID</dt>
              <dd className="mono">{status.data.policyKeyId}</dd>
            </dl>
          )}
        </Fresh>
      </Panel>
      <Panel title="网络执行能力">
        <Fresh error={status.error} loading={status.loading}>
          {caps.length ? (
            <div className="stack">
              {caps.map((c, i) =>
                typeof c === "string" ? (
                  <div className="control-row" key={i}>
                    {c}
                  </div>
                ) : (
                  <div className="control-row" key={i}>
                    <div>
                      <strong>{c.id}</strong>
                      <small>{c.detail}</small>
                    </div>
                    <div className="inline">
                      <Badge tone={c.implemented ? "good" : "warning"}>
                        {c.implemented ? "已实现" : "未实现"}
                      </Badge>
                      <Badge tone={c.verified ? "good" : "warning"}>
                        {c.verified ? "已验证" : "未验证"}
                      </Badge>
                    </div>
                  </div>
                ),
              )}
            </div>
          ) : (
            <Empty title="未声明网络执行能力" />
          )}
        </Fresh>
      </Panel>
    </>
  );
}
export function App() {
  const [session, setSession] = useState<Session | null>(null),
    [authLoading, setAuthLoading] = useState(true),
    [authError, setAuthError] = useState<string | null>(null),
    [page, setPage] = useState<Page>("overview"),
    [selectedDevice, setSelectedDevice] = useState<string | null>(null),
    [revision, setRevision] = useState(0),
    [logoutBusy, setLogoutBusy] = useState(false);
  const refresh = () => setRevision((n) => n + 1);
  async function check() {
    setAuthLoading(true);
    setAuthError(null);
    try {
      setSession(await request<Session>("/api/me"));
    } catch (e) {
      if (e instanceof HttpError && e.status === 401) setSession(null);
      else setAuthError(errorText(e));
    } finally {
      setAuthLoading(false);
    }
  }
  useEffect(() => {
    void check();
  }, []);
  async function login(username: string, password: string) {
    const result = await request<Session>("/api/auth/login", {
      method: "POST",
      body: { username, password },
    });
    setSession(result);
    setPage("overview");
    refresh();
  }
  async function logout() {
    if (!session) return;
    setLogoutBusy(true);
    try {
      await request("/api/auth/logout", {
        method: "POST",
        body: {},
        csrfToken: session.csrfToken,
      });
      setSession(null);
    } catch (e) {
      setAuthError(errorText(e));
    } finally {
      setLogoutBusy(false);
    }
  }
  if (authLoading)
    return (
      <div className="startup">
        <Loading />
      </div>
    );
  if (authError && !session)
    return (
      <div className="startup">
        <ErrorNotice error={authError} />
        <button className="secondary" onClick={check}>
          重试连接
        </button>
      </div>
    );
  if (!session) return <Login onLogin={login} />;
  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="sidebar-brand">
          <div className="brand-icon">盾</div>
          <div>
            <strong>终端合规</strong>
            <span>内网管理中心</span>
          </div>
        </div>
        <div className="sidebar-caption">工作区</div>
        <nav aria-label="主导航">
          {pages.map((p) => (
            <button
              key={p.id}
              className={`nav-item ${page === p.id ? "active" : ""}`}
              onClick={() => {
                setPage(p.id);
                if (p.id === "devices") setSelectedDevice(null);
              }}
            >
              <span className="nav-glyph">{p.glyph}</span>
              <span>
                <strong>{p.label}</strong>
                <small>{p.sub}</small>
              </span>
            </button>
          ))}
        </nav>
        <div className="sidebar-foot">
          <span className="status-dot" />
          仅连接当前内网管理端
        </div>
      </aside>
      <div className="main-shell">
        <header className="topbar">
          <div className="breadcrumb">
            管理中心 <span>/</span> {pages.find((p) => p.id === page)?.label}
          </div>
          <div className="top-actions">
            <span className="account">
              <span className="avatar">
                {session.username.slice(0, 1).toUpperCase()}
              </span>
              <span>
                <strong>{session.username}</strong>
                <small>{session.roles.join(" · ")}</small>
              </span>
            </span>
            <button className="ghost" disabled={logoutBusy} onClick={logout}>
              退出
            </button>
          </div>
        </header>
        <main className="content">
          <ErrorNotice error={authError} />
          {page === "overview" && (
            <Overview
              revision={revision}
              openDevice={(id) => {
                setSelectedDevice(id);
                setPage("devices");
              }}
              openAlerts={() => setPage("alerts")}
            />
          )}{" "}
          {page === "devices" && (
            <Devices
              key={selectedDevice ?? "list"}
              session={session}
              revision={revision}
              refresh={refresh}
              initialDevice={selectedDevice}
            />
          )}{" "}
          {page === "alerts" && (
            <Alerts session={session} revision={revision} refresh={refresh} />
          )}{" "}
          {page === "policies" && (
            <Policies session={session} revision={revision} refresh={refresh} />
          )}{" "}
          {page === "registration" && <Registration session={session} />}{" "}
          {page === "audit" && <AuditPage revision={revision} />}{" "}
          {page === "system" && <SystemPage revision={revision} />}
        </main>
        <footer className="footer">
          终端合规管理中心 <span>·</span> 结论、执行、防护与通知状态分别核对
        </footer>
      </div>
    </div>
  );
}
