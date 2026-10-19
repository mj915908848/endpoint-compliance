import { Component, useEffect, useRef, useState, type ReactNode } from "react";
import {
  Alert as Notice,
  Button,
  Card,
  Empty as AntEmpty,
  Flex,
  Form,
  Input,
  Space,
  Spin,
  Tag,
  Tooltip,
  Typography,
} from "antd";
import {
  CheckCircleFilled,
  ClockCircleFilled,
  CloseCircleFilled,
  ExclamationCircleFilled,
} from "@ant-design/icons";
import type { Alert, DeviceSummary, ModuleResult, Verdict } from "../types";
import { alertTypeLabel, onlineLabel, verdictLabels } from "./labels";

export const time = (value: string | null | undefined) =>
  value ? new Date(value).toLocaleString("zh-CN", { hour12: false }) : "暂无记录";

export const errorText = (error: unknown) =>
  error instanceof Error ? error.message : "操作失败，请重试";

const verdictColor: Record<Verdict, string> = {
  PASS: "success",
  FAIL: "error",
  UNKNOWN: "warning",
};

/** `muted` greys the tag out, for a device whose current verdict is unknown only because it is offline. */
export function VerdictTag({ verdict, muted = false }: { verdict: Verdict; muted?: boolean }) {
  return (
    <Tag color={muted ? "default" : (verdictColor[verdict] ?? "warning")} variant="filled">
      {verdictLabels[verdict] ?? "无法判断"}
    </Tag>
  );
}

/** How long ago, in rough words: "3 分钟", "2 小时", "5 天". */
export function ago(value: string | null | undefined, now = Date.now()) {
  if (!value) return null;
  const minutes = Math.max(0, Math.floor((now - new Date(value).getTime()) / 60_000));
  if (minutes < 60) return `${Math.max(1, minutes)} 分钟`;
  if (minutes < 60 * 24) return `${Math.floor(minutes / 60)} 小时`;
  return `${Math.floor(minutes / 60 / 24)} 天`;
}

/** A dot before a device's name: green and haloed when online, amber when it may be offline, grey when offline. */
export function OnlineDot({
  device,
}: {
  device: Pick<DeviceSummary, "onlineState" | "lastHeartbeat">;
}) {
  const label = onlineLabel(device.onlineState) ?? "在线状态未知";
  const tone =
    device.onlineState === "Online"
      ? "online"
      : device.onlineState === "SuspectedOffline"
        ? "suspect"
        : "offline";
  return (
    <Tooltip title={`${label} · 最近心跳 ${time(device.lastHeartbeat)}`}>
      <span className={`online-dot online-dot-${tone}`} role="img" aria-label={label} />
    </Tooltip>
  );
}

/** The dot with its label, e.g. "● 失联 2 小时", for places that state the online state in words. */
export function OnlineState({
  device,
}: {
  device: Pick<DeviceSummary, "onlineState" | "lastHeartbeat">;
}) {
  const label = onlineLabel(device.onlineState) ?? "在线状态未知";
  const since = device.onlineState === "Online" ? null : ago(device.lastHeartbeat);
  return (
    <Space size={6}>
      <OnlineDot device={device} />
      <span>{since ? `${label} ${since}` : label}</span>
    </Space>
  );
}

/** The primary adapter's first address and MAC, e.g. "10.0.0.5 · 00-11-22-33-44-55", with the rest on hover. */
export function NetworkLine({ device }: { device: DeviceSummary }) {
  const [first, ...rest] = device.network ?? [];
  if (!first) return null;
  const line = (
    <Typography.Text type="secondary" className="mono" style={{ fontSize: 12 }}>
      {[first.addresses[0], first.mac].filter(Boolean).join(" · ")}
      {(first.addresses.length > 1 || rest.length > 0) && " …"}
    </Typography.Text>
  );
  return first.addresses.length > 1 || rest.length > 0 ? (
    <Tooltip title={<NetworkList adapters={device.network ?? []} />}>{line}</Tooltip>
  ) : (
    line
  );
}

export function NetworkList({ adapters }: { adapters: DeviceSummary["network"] & object }) {
  return (
    <Space orientation="vertical" size={0}>
      {adapters.map((a) => (
        <span key={a.mac} className="mono">
          {a.name}：{a.addresses.join("、") || "无地址"}（{a.mac}）
        </span>
      ))}
    </Space>
  );
}

/** Lower-case text of a device's addresses and MACs, with the MACs also written with colons, for search. */
export const networkText = (d: DeviceSummary) =>
  (d.network ?? [])
    .flatMap((a) => [...a.addresses, a.mac, a.mac.replaceAll("-", ":")])
    .concat(d.sourceAddress ?? "")
    .join(" ")
    .toLowerCase();

export function ErrorNotice({
  error,
  title = "操作未完成",
}: {
  error: string | null;
  title?: string;
}) {
  return error ? <Notice type="error" showIcon title={title} description={error} /> : null;
}

export function Empty({ title = "暂无记录", children }: { title?: string; children?: ReactNode }) {
  return (
    <AntEmpty
      image={AntEmpty.PRESENTED_IMAGE_SIMPLE}
      description={
        <Space orientation="vertical" size={2}>
          <Typography.Text strong>{title}</Typography.Text>
          {children && <Typography.Text type="secondary">{children}</Typography.Text>}
        </Space>
      }
    />
  );
}

export function Loading() {
  return (
    <Flex justify="center" style={{ padding: 32 }} role="status">
      <Spin description="正在读取数据…" />
    </Flex>
  );
}

/** Current verdict for a device. Offline devices never show a current result, only history. */
/** Host name with the operator's note, e.g. "DESKTOP-7Q2（张三 · 研发部）". */
export const deviceName = (d: { hostName: string; note?: string }) =>
  d.note ? `${d.hostName}（${d.note}）` : d.hostName;

export function DeviceState({ device }: { device: DeviceSummary }) {
  const offline = device.onlineState !== "Online";
  return (
    <Space orientation="vertical" size={2}>
      <Space size={4} wrap>
        <VerdictTag verdict={offline ? "UNKNOWN" : device.currentVerdict} muted={offline} />
        {device.simulated && <Tag color="purple">模拟终端</Tag>}
      </Space>
      {offline && device.lastVerdict && (
        <Typography.Text type="secondary" style={{ fontSize: 12 }}>
          上次结论：{verdictLabels[device.lastVerdict]}（{time(device.lastScan)}，仅供参考）
        </Typography.Text>
      )}
    </Space>
  );
}

const RERUN_HINT = "请确认该电脑已开机联网、客户端服务正在运行；恢复在线后结果会自动更新。";

export function OverviewGuide({ devices }: { devices: DeviceSummary[] }) {
  const online = devices.filter((d) => d.onlineState === "Online");
  const failed = online.filter((d) => d.currentVerdict === "FAIL");
  const offline = devices.filter((d) => d.onlineState !== "Online");
  const lastFailed = offline.filter((d) => d.lastVerdict === "FAIL");
  const violations = failed.reduce((count, d) => count + d.violationCount, 0);
  const [type, message] =
    devices.length === 0
      ? (["info", "暂无终端上报数据。请先登记终端并完成一次检查。"] as const)
      : failed.length > 0
        ? ([
            "error",
            `${failed.length} 台在线终端未通过检查，共发现 ${violations} 个违规对象，详见“未恢复告警”。`,
          ] as const)
        : online.length === 0
          ? (["warning", "当前没有在线终端，无法给出检查结论。"] as const)
          : online.some((d) => d.currentVerdict === "UNKNOWN")
            ? (["warning", "部分在线终端检查不完整，暂无法判断，请查看设备详情。"] as const)
            : (["success", `${online.length} 台在线终端均通过检查。`] as const);
  return (
    <Notice
      type={type}
      showIcon
      aria-label="检查结果说明"
      title={message}
      description={
        offline.length > 0 &&
        `另有 ${offline.length} 台终端失联或疑似失联，暂无法判断${
          lastFailed.length > 0
            ? `，其中 ${lastFailed.length} 台上次检查未通过，违规记录仍然保留`
            : ""
        }。${RERUN_HINT}`
      }
    />
  );
}

/** The device's verdict in plain language; `children` adds facts such as heartbeat times below it. */
/** The verdict, what to do about it, and the facts it rests on (children), in one card. */
export function DeviceGuide({ device, children }: { device: DeviceSummary; children?: ReactNode }) {
  const state =
    device.onlineState !== "Online"
      ? {
          tone: "warning",
          icon: <ClockCircleFilled />,
          title: "终端未在线",
          hint: `${
            device.lastVerdict === "FAIL"
              ? "上次检查未通过，已发现的违规仍需处理。"
              : "上次检查结果仅供参考。"
          }${RERUN_HINT}`,
        }
      : device.currentVerdict === "FAIL"
        ? {
            tone: "danger",
            icon: <CloseCircleFilled />,
            title: "检查未通过",
            count: device.violationCount,
            hint: "禁用软件只要安装即视为违规，无论是否运行。卸载相关软件、扩展或清除代理配置后，请重新检查。",
          }
        : device.currentVerdict === "UNKNOWN"
          ? {
              tone: "warning",
              icon: <ExclamationCircleFilled />,
              title: "暂无法判断",
              hint: "缺少完整且有效的检查数据。处理“检查覆盖”中未完成的项目后重新检查。",
            }
          : {
              tone: "good",
              icon: <CheckCircleFilled />,
              title: "检查通过",
              hint: "本次检查范围内未发现禁用项。结论仅适用于已覆盖的检查项。",
            };
  return (
    <section className={`status-card status-${state.tone}`} aria-label="设备结果说明">
      <div className="status-head">
        <span className="status-icon">{state.icon}</span>
        <div>
          <div className="status-title">
            {state.title}
            {state.count !== undefined && (
              <span className="status-pill">{state.count} 个违规对象</span>
            )}
          </div>
          <p className="status-hint">{state.hint}</p>
        </div>
      </div>
      {children && <div className="status-facts">{children}</div>}
    </section>
  );
}

export function CoverageGuide({ modules }: { modules: ModuleResult[] }) {
  const errors = modules.filter((m) => m.status === "Error").length;
  const unknown = modules.filter((m) => m.status !== "Complete" && m.status !== "Error").length;
  const complete = modules.length - errors - unknown;
  return (
    <Notice
      type={errors || unknown ? "warning" : "success"}
      showIcon
      aria-label="检查覆盖说明"
      title={`检查覆盖：${complete} 项完成，${errors} 项读取失败，${unknown} 项未覆盖`}
      description={
        errors || unknown
          ? "读取失败或未覆盖的项目属于检查缺口，并不表示发现了新的违规；已确认的违规仍需处理。缺口未消除前，结论可能保持“无法判断”。"
          : undefined
      }
    />
  );
}

export function Login({
  onLogin,
  notice,
}: {
  onLogin: (username: string, password: string) => Promise<unknown>;
  /** Why the administrator was signed out, shown above the form. */
  notice?: string | null;
}) {
  const [form] = Form.useForm<{ username: string; password: string }>();
  const [busy, setBusy] = useState(false),
    [error, setError] = useState<string | null>(null);
  async function submit(values: { username: string; password: string }) {
    setBusy(true);
    setError(null);
    try {
      await onLogin(values.username, values.password);
    } catch (e) {
      setError(errorText(e));
    } finally {
      form.setFieldValue("password", "");
      setBusy(false);
    }
  }
  return (
    <div className="login-screen">
      <section className="login-hero" aria-hidden="true">
        <div className="login-hero-text">
          <h1>终端合规管控平台</h1>
          <p>
            检查内网电脑上的代理工具与 AI
            软件，留存证据、集中告警，按策略只检查或强制拦截。全部数据只在本单位内网流转。
          </p>
        </div>
      </section>
      <section className="login-side">
        <div className="login-card">
          <div className="login-head">
            <img src="/brand/mark.svg" alt="" className="login-logo" />
            <Typography.Title level={4} style={{ margin: 0 }}>
              终端合规管控平台
            </Typography.Title>
            <span className="login-sub">管理中心</span>
          </div>
          {notice && !error && (
            <Notice type="info" showIcon title={notice} style={{ marginBottom: 16 }} />
          )}
          <Form form={form} layout="vertical" requiredMark={false} onFinish={submit}>
            <Form.Item
              label="管理员账号"
              name="username"
              rules={[{ required: true, message: "请输入账号" }]}
            >
              <Input autoComplete="username" />
            </Form.Item>
            <Form.Item
              label="密码"
              name="password"
              rules={[{ required: true, message: "请输入密码" }]}
            >
              <Input.Password autoComplete="current-password" visibilityToggle={false} />
            </Form.Item>
            {error && (
              <Form.Item>
                <ErrorNotice error={error} title="登录失败" />
              </Form.Item>
            )}
            <Button type="primary" htmlType="submit" block loading={busy}>
              登录
            </Button>
          </Form>
          <Typography.Paragraph type="secondary" style={{ marginTop: 16, fontSize: 12 }}>
            系统不提供默认账号。仅连接本单位内网管理端，不依赖任何公网资源。
          </Typography.Paragraph>
        </div>
        <footer className="login-foot">© 恺域科技</footer>
      </section>
    </div>
  );
}

/** Client release of a device, flagged when older than the server's or than the oldest it supports. */
export function AgentVersion({ device }: { device: DeviceSummary }) {
  const text = device.agentVersion ? `客户端 ${device.agentVersion}` : "客户端 0.2.7 或更早";
  if (device.agentUnsupported)
    return (
      <Tooltip title="低于管理端支持的最低客户端版本，检查结果可能不完整，请尽快升级">
        <Tag color="error" style={{ marginInlineEnd: 0 }}>
          {text} · 不受支持
        </Tag>
      </Tooltip>
    );
  return device.agentOutdated ? (
    <Tooltip title="比管理端版本旧，建议升级客户端">
      <Tag color="warning" style={{ marginInlineEnd: 0 }}>
        {text} · 待升级
      </Tag>
    </Tooltip>
  ) : (
    <span>{device.agentVersion ? text : "客户端版本未知"}</span>
  );
}

/**
 * For a paged table: changing page brings the enclosing section, collapsible group or panel back into view. Otherwise the reader is
 * left wherever the old page's pager was, and a page of different height leaves them far from the new rows.
 */
export function usePageScroll() {
  const ref = useRef<HTMLDivElement>(null);
  const onPageChange = () => {
    const target = ref.current?.closest("section, .ant-collapse-item, .panel") ?? ref.current;
    target?.scrollIntoView({ block: "start" });
  };
  return { ref, onPageChange };
}

/**
 * Shows a page that failed while rendering as an error with a way out, instead of leaving the whole window blank.
 * Give it a key that changes on navigation so the next page renders afresh.
 */
export class ErrorBoundary extends Component<{ children: ReactNode }, { error: Error | null }> {
  state = { error: null as Error | null };

  static getDerivedStateFromError(error: Error) {
    return { error };
  }

  render() {
    if (!this.state.error) return this.props.children;
    return (
      <Notice
        type="error"
        showIcon
        title="页面显示出错"
        description={
          <Space orientation="vertical" size={8}>
            <span>
              这一页遇到了无法显示的数据（{this.state.error.message}
              ）。可以换到其他页面，或重新加载后再试。
            </span>
            <Button onClick={() => window.location.reload()}>重新加载</Button>
          </Space>
        }
      />
    );
  }
}
