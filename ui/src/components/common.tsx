import { useEffect, useState, type ReactNode } from "react";
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
  Typography,
} from "antd";
import { SafetyCertificateOutlined } from "@ant-design/icons";
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

export function VerdictTag({ verdict }: { verdict: Verdict }) {
  return (
    <Tag color={verdictColor[verdict] ?? "warning"} variant="solid">
      {verdictLabels[verdict] ?? "无法判断"}
    </Tag>
  );
}

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
        <VerdictTag verdict={offline ? "UNKNOWN" : device.currentVerdict} />
        <Tag color={offline ? "warning" : "default"}>
          {onlineLabel(device.onlineState) ?? "在线状态未知"}
        </Tag>
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
export function DeviceGuide({ device, children }: { device: DeviceSummary; children?: ReactNode }) {
  if (device.onlineState !== "Online")
    return (
      <Notice
        type="warning"
        showIcon
        aria-label="设备结果说明"
        title="暂无法判断：终端未在线"
        description={
          <>
            {`该终端最近没有上报心跳。${
              device.lastVerdict === "FAIL"
                ? "上次检查未通过，已发现的违规仍需处理。"
                : "上次检查结果仅供参考。"
            }${RERUN_HINT}`}
            {children}
          </>
        }
      />
    );
  if (device.currentVerdict === "FAIL")
    return (
      <Notice
        type="error"
        showIcon
        aria-label="设备结果说明"
        title={`检查未通过：发现 ${device.violationCount} 个违规对象`}
        description={
          <>
            按照当前策略，禁用软件只要安装即视为违规，无论是否运行。请根据下方证据卸载相关软件、扩展或清除代理配置，然后重新检查。部分检查项读取失败不会抵消已确认的违规。
            {children}
          </>
        }
      />
    );
  if (device.currentVerdict === "UNKNOWN")
    return (
      <Notice
        type="warning"
        showIcon
        aria-label="设备结果说明"
        title="暂无法判断"
        description={
          <>缺少完整且有效的检查数据。请查看“检查覆盖”中未完成的项目，处理后重新检查。{children}</>
        }
      />
    );
  return (
    <Notice
      type="success"
      showIcon
      aria-label="设备结果说明"
      title="检查通过"
      description={
        <>
          在本次检查范围内未发现禁用项。结论仅适用于已覆盖的检查项，请同时关注检查覆盖与防护状态。
          {children}
        </>
      }
    />
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

export function AlertCard({
  alert,
  note,
  canAck,
  onAck,
}: {
  alert: Alert;
  note?: string;
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
  const severity = recovered ? "default" : alert.type === "Violation" ? "error" : "warning";
  return (
    <Card size="small">
      <Flex justify="space-between" align="start" gap={16} wrap>
        <Space orientation="vertical" size={4} style={{ flex: 1, minWidth: 240 }}>
          <Space size={4} wrap>
            <Tag color={severity}>{alertTypeLabel(alert.type)}</Tag>
            <Tag color={recovered ? "success" : "warning"}>{recovered ? "已恢复" : "未恢复"}</Tag>
            <Tag>{acked ? "已确认" : "待确认"}</Tag>
          </Space>
          <Typography.Text strong>{alert.summary}</Typography.Text>
          <Typography.Text type="secondary">
            {deviceName({ hostName: alert.hostName, note })} · {alert.objectKey}
          </Typography.Text>
          <Typography.Text type="secondary" style={{ fontSize: 12 }}>
            首次发现 {time(alert.firstSeen)} · 最近发现 {time(alert.lastSeen)} · 事件序号{" "}
            {alert.lastSequence}
          </Typography.Text>
          <ErrorNotice error={error} />
        </Space>
        {canAck && !acked && (
          <Button loading={busy} onClick={ack}>
            确认已阅
          </Button>
        )}
      </Flex>
    </Card>
  );
}

export function Login({
  onLogin,
}: {
  onLogin: (username: string, password: string) => Promise<unknown>;
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
    <Flex className="login-screen" align="center" justify="center">
      <Card className="login-card">
        <Space orientation="vertical" size={4} style={{ marginBottom: 24 }}>
          <SafetyCertificateOutlined className="login-mark" />
          <Typography.Title level={3} style={{ margin: 0 }}>
            终端合规管理中心
          </Typography.Title>
          <Typography.Text type="secondary">请使用管理员分配的账号登录。</Typography.Text>
        </Space>
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
      </Card>
    </Flex>
  );
}
