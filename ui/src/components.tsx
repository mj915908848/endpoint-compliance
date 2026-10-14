import { useEffect, useState, type FormEvent, type ReactNode } from "react";
import type { Alert, DeviceSummary, ModuleResult, Verdict } from "./types";
export const verdictLabels: Record<Verdict, string> = {
  PASS: "范围内通过",
  FAIL: "不通过",
  UNKNOWN: "无法判断",
};
export const time = (value: string | null | undefined) =>
  value
    ? new Date(value).toLocaleString("zh-CN", { hour12: false })
    : "尚无记录";
export const errorText = (error: unknown) =>
  error instanceof Error ? error.message : "操作失败，请重试";
export function Badge({
  children,
  tone = "neutral",
}: {
  children: ReactNode;
  tone?: string;
}) {
  return <span className={`badge ${tone}`}>{children}</span>;
}
export function VerdictBadge({ verdict }: { verdict: Verdict }) {
  return (
    <Badge
      tone={
        verdict === "PASS" ? "good" : verdict === "FAIL" ? "danger" : "warning"
      }
    >
      {verdictLabels[verdict] ?? "无法判断"}
    </Badge>
  );
}
export function ErrorNotice({ error }: { error: string | null }) {
  return error ? (
    <div className="error-notice" role="alert">
      <strong>操作未完成</strong>
      <span>{error}</span>
    </div>
  ) : null;
}
export function Empty({
  title = "尚无记录",
  children,
}: {
  title?: string;
  children?: ReactNode;
}) {
  return (
    <div className="empty">
      <span className="empty-symbol">◇</span>
      <h3>{title}</h3>
      <p>{children || "数据由终端上报后显示。"}</p>
    </div>
  );
}
export function Loading() {
  return (
    <div className="loading" role="status">
      <span className="spinner" />
      正在读取管理端数据…
    </div>
  );
}
export function DeviceState({ device }: { device: DeviceSummary }) {
  const offline = device.onlineState !== "Online";
  return (
    <div className="device-state">
      <div className="inline">
        <VerdictBadge verdict={offline ? "UNKNOWN" : device.currentVerdict} />
        <Badge tone={offline ? "warning" : "neutral"}>
          {device.onlineState === "Offline"
            ? "失联"
            : device.onlineState === "SuspectedOffline"
              ? "疑似失联"
              : device.onlineState === "Online"
                ? "在线"
                : "在线状态未知"}
        </Badge>
        {device.simulated && <Badge tone="warning">模拟终端</Badge>}
      </div>
      {offline && device.lastVerdict && (
        <small>
          上次结论：{verdictLabels[device.lastVerdict]} ·{" "}
          {time(device.lastScan)}（历史记录）
        </small>
      )}
    </div>
  );
}
export function OverviewGuide({ devices }: { devices: DeviceSummary[] }) {
  const online = devices.filter((d) => d.onlineState === "Online");
  const failed = online.filter((d) => d.currentVerdict === "FAIL");
  const offline = devices.filter((d) => d.onlineState !== "Online");
  const lastFailed = offline.filter((d) => d.lastVerdict === "FAIL");
  return (
    <div className="result-guide" aria-label="检查结果说明">
      <strong>先看结论</strong>
      {devices.length === 0 ? (
        <p>尚无终端上报。先登记设备并运行一次采集。</p>
      ) : (
        <>
          <p>
            {failed.length > 0
              ? `${failed.length} 台在线终端当前不通过，发现 ${failed.reduce((count, d) => count + d.violationCount, 0)} 项已确认违规。下方“未恢复告警”列出原因。`
              : online.length === 0
                ? "当前没有在线检查结论，不能把页面上的 0 理解为通过。"
                : online.some((d) => d.currentVerdict === "UNKNOWN")
                  ? "在线终端中仍有检查不完整的设备，请查看设备详情。"
                  : `${online.length} 台在线终端在已声明范围内通过。`}
          </p>
          {offline.length > 0 && (
            <p>
              另有 {offline.length} 台终端失联或疑似失联，当前无法判断。
              {lastFailed.length > 0 && `其中 ${lastFailed.length} 台上次检查不通过，违规记录仍在。`}
              若使用一次性试用包，请在待检电脑重新运行“本机采集试用.bat”，再刷新页面。
            </p>
          )}
        </>
      )}
    </div>
  );
}
export function DeviceGuide({ device }: { device: DeviceSummary }) {
  if (device.onlineState !== "Online")
    return (
      <div className="result-guide warning" aria-label="设备结果说明">
        <strong>当前不能判定</strong>
        <p>
          这台电脑没有新心跳。
          {device.lastVerdict === "FAIL" ? "上次检查不通过，已发现的违规记录仍需处理。" : "上次检查结果仅供参考。"}
          若使用一次性试用包，请在这台电脑重新运行“本机采集试用.bat”，再刷新页面。
        </p>
      </div>
    );
  if (device.currentVerdict === "FAIL")
    return (
      <div className="result-guide danger" aria-label="设备结果说明">
        <strong>本次检查不通过：发现 {device.violationCount} 项已确认违规</strong>
        <p>客户规则是“安装也不允许”。请查看下方证据，移除禁用软件、扩展或代理配置后重新采集。其他项目读取失败不会抵消已确认的违规。</p>
      </div>
    );
  return (
    <div className={`result-guide ${device.currentVerdict === "UNKNOWN" ? "warning" : "good"}`} aria-label="设备结果说明">
      <strong>{device.currentVerdict === "UNKNOWN" ? "当前无法判断" : "当前范围内通过"}</strong>
      <p>{device.currentVerdict === "UNKNOWN" ? "没有足够完整的新鲜检查证据。请查看下方未覆盖项目，处理后重新采集。" : "本次已声明的检查范围内未发现禁用项；仍请查看覆盖范围和防护状态。"}</p>
    </div>
  );
}
export function CoverageGuide({ modules }: { modules: ModuleResult[] }) {
  const errors = modules.filter((m) => m.status === "Error").length;
  const unknown = modules.filter((m) => m.status !== "Complete" && m.status !== "Error").length;
  const complete = modules.length - errors - unknown;
  return (
    <div className={`result-guide ${errors || unknown ? "warning" : "good"}`} aria-label="检查覆盖说明">
      <strong>检查覆盖：{complete} 项完成，{errors} 项读取失败，{unknown} 项未能覆盖</strong>
      <p>读取失败或账户配置未加载属于检查缺口，不代表新发现违规；已确认的违规仍需处理。处理完违规后若缺口仍在，结果可能继续显示“无法判断”。</p>
    </div>
  );
}
export function AlertCard({
  alert,
  canAck,
  onAck,
}: {
  alert: Alert;
  canAck: boolean;
  onAck: (id: string) => Promise<unknown>;
}) {
  const [acked, setAcked] = useState(alert.acknowledged),
    [busy, setBusy] = useState(false),
    [error, setError] = useState<string | null>(null);
  useEffect(() => setAcked(alert.acknowledged), [alert.id, alert.acknowledged]);
  async function ack() {
    setBusy(true);
    setError(null);
    try {
      await onAck(alert.id);
      setAcked(true);
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(false);
    }
  }
  const recovered = alert.state === "Resolved";
  const type: Record<string, string> = {
    Violation: "确认违规",
    BlockedAttempt: "已阻止尝试",
    Health: "设备健康",
    Offline: "设备失联",
    Clue: "待核查线索",
  };
  return (
    <article className="alert-card">
      <div
        className={`alert-icon ${recovered ? "neutral" : alert.type === "Violation" ? "danger" : "warning"}`}
      >
        {alert.type === "Violation" ? "!" : "◇"}
      </div>
      <div className="alert-main">
        <div className="inline">
          <Badge
            tone={
              recovered
                ? "neutral"
                : alert.type === "Violation"
                  ? "danger"
                  : "warning"
            }
          >
            {type[alert.type] || alert.type}
          </Badge>
          <Badge tone={recovered ? "neutral" : "warning"}>
            {recovered ? "技术已恢复" : "问题持续"}
          </Badge>
          <Badge>{acked ? "已确认" : "待确认"}</Badge>
        </div>
        <h3>{alert.summary}</h3>
        <p>
          <strong>{alert.hostName}</strong>
          <span className="separator">/</span>
          {alert.objectKey}
        </p>
        <small>
          首次 {time(alert.firstSeen)} · 最近 {time(alert.lastSeen)} · 事件序号{" "}
          {alert.lastSequence}
        </small>
        <p className="muted small">
          确认不会改变设备检查结论；技术恢复需要终端的新采集证据。
        </p>
        <ErrorNotice error={error} />
      </div>
      {canAck && !acked && (
        <button className="secondary compact" disabled={busy} onClick={ack}>
          {busy ? "正在确认…" : "确认已阅"}
        </button>
      )}
    </article>
  );
}
export function Login({
  onLogin,
}: {
  onLogin: (username: string, password: string) => Promise<unknown>;
}) {
  const [username, setUsername] = useState(""),
    [password, setPassword] = useState(""),
    [busy, setBusy] = useState(false),
    [error, setError] = useState<string | null>(null);
  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await onLogin(username, password);
      setPassword("");
    } catch (e) {
      setError(errorText(e));
      setPassword("");
    } finally {
      setBusy(false);
    }
  }
  return (
    <main className="login-screen">
      <section className="login-brand">
        <div className="brand-mark">盾</div>
        <p className="eyebrow">ENDPOINT COMPLIANCE</p>
        <h1>
          让每一项合规结论
          <br />
          都有据可查。
        </h1>
        <p>
          客户内网的终端合规管理中心。
          <br />
          采集、策略、通知与审计，集中呈现。
        </p>
        <div className="login-note">
          仅连接部署的内网管理端 · 无公网资源依赖
        </div>
      </section>
      <section className="login-form">
        <div>
          <span className="eyebrow">管理中心</span>
          <h2>管理员登录</h2>
          <p className="muted">使用部署管理员分配的账号。</p>
        </div>
        <form onSubmit={submit}>
          <label>
            管理员账号
            <input
              name="username"
              autoComplete="username"
              required
              value={username}
              onChange={(e) => setUsername(e.target.value)}
            />
          </label>
          <label>
            密码
            <input
              name="password"
              type="password"
              autoComplete="current-password"
              required
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
          </label>
          <ErrorNotice error={error} />
          <button className="primary" disabled={busy}>
            {busy ? "正在登录…" : "登录管理中心"}
          </button>
        </form>
        <p className="small muted">
          没有默认账号或密码。权限由管理端校验，账号凭据仅用于本次认证。
        </p>
      </section>
    </main>
  );
}
