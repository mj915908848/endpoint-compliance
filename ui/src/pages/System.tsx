import { useEffect, useState } from "react";
import {
  Alert,
  App,
  Button,
  Checkbox,
  Descriptions,
  Form,
  Input,
  Select,
  Space,
  Switch,
  Table,
  Tag,
  Typography,
} from "antd";
import { request } from "../api";
import { role } from "../session";
import { useRefresh, useResource } from "../useResource";
import {
  alertTypeLabel,
  ClientPackagesPanel,
  Empty,
  ErrorNotice,
  errorText,
  Fresh,
  PageHeading,
  Panel,
  SigningKeyPanel,
  time,
} from "../components";
import type { AppSettings, Session, Status } from "../types";

const modeLabels: Record<string, string> = {
  Production: "生产模式",
  LoopbackDemo: "本机演示",
  LanHttpTrial: "内网试用（HTTP）",
};

const capabilityNames: Record<string, string> = { network: "通用网络访问拦截" };

type Capability = { id: string; implemented: boolean; verified: boolean; detail: string };

const channels = [
  {
    value: "WeCom",
    label: "企业微信群机器人",
    host: "qyapi.weixin.qq.com",
    help: "在企业微信群里点右上角「…」→「消息推送」（旧版为「群机器人」）→ 添加，复制 Webhook 地址。",
  },
  {
    value: "DingTalk",
    label: "钉钉群机器人",
    host: "oapi.dingtalk.com",
    help: "在钉钉群设置 →「机器人」→ 添加「自定义」机器人。安全设置选「加签」并把密钥填到下面；或选「自定义关键词」，关键词填「终端合规」。",
  },
  {
    value: "Feishu",
    label: "飞书群机器人",
    host: "open.feishu.cn",
    help: "在飞书群设置 →「群机器人」→ 添加「自定义机器人」。如果开启了「签名校验」，把密钥填到下面。",
  },
];

const pushTypes = ["Violation", "SensitiveFile", "Health", "BlockedAttempt", "Offline"];

const retentionChoices = [
  { value: 0, label: "永久保留" },
  { value: 180, label: "180 天" },
  { value: 365, label: "1 年" },
  { value: 730, label: "2 年" },
  { value: 1095, label: "3 年" },
];

function NotificationPanel({
  session,
  initial,
  live,
}: {
  session: Session;
  /** Fills the form once. */
  initial: AppSettings;
  /** What the server has saved now. */
  live: AppSettings;
}) {
  const { message } = App.useApp();
  const refresh = useRefresh();
  const saved = live.notifications;
  const start = initial.notifications;
  const [enabled, setEnabled] = useState(start.enabled),
    [channel, setChannel] = useState(start.channel),
    [url, setUrl] = useState(start.webhookUrl),
    // null keeps the saved secret.
    [secret, setSecret] = useState<string | null>(null),
    [types, setTypes] = useState(start.types),
    [consoleUrl, setConsoleUrl] = useState(start.consoleUrl || window.location.origin),
    // The saved settings this form was filled from; a save over a newer one is refused.
    [base, setBase] = useState(start.version),
    [busy, setBusy] = useState(false),
    [testing, setTesting] = useState(false),
    [error, setError] = useState<string | null>(null);
  const current = channels.find((c) => c.value === channel) ?? channels[0];
  const last = live.lastNotification;

  const stale = !busy && saved.version !== base;
  function reload() {
    setEnabled(saved.enabled);
    setChannel(saved.channel);
    setUrl(saved.webhookUrl);
    setSecret(null);
    setTypes(saved.types);
    setConsoleUrl(saved.consoleUrl || window.location.origin);
    setBase(saved.version);
    setError(null);
  }

  async function save() {
    setBusy(true);
    setError(null);
    try {
      const r = await request<{ version: string }>("/api/settings/notifications", {
        method: "PUT",
        body: { enabled, channel, webhookUrl: url, secret, types, consoleUrl, version: base },
        csrfToken: session.csrfToken,
      });
      setBase(r.version);
      setSecret(null);
      void message.success(enabled ? "已保存，出现新告警时会推送到群里" : "已保存，告警推送已关闭");
      refresh();
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(false);
    }
  }

  async function test() {
    setTesting(true);
    setError(null);
    try {
      const r = await request<{ ok: boolean; error: string | null }>(
        "/api/settings/notifications/test",
        {
          method: "POST",
          body: {},
          csrfToken: session.csrfToken,
        },
      );
      if (r.ok) void message.success("测试消息已发送，请到群里查看");
      else setError("测试消息发送失败：" + (r.error ?? "原因未知"));
      refresh();
    } catch (e) {
      setError(errorText(e));
    } finally {
      setTesting(false);
    }
  }

  return (
    <Panel title="告警推送">
      {stale && (
        <Alert
          type="warning"
          showIcon
          style={{ marginBottom: 16, maxWidth: 640 }}
          title="告警推送设置已被其他人修改。载入最新设置后再改，否则无法保存。"
          action={
            <Button size="small" onClick={reload}>
              载入最新设置
            </Button>
          }
        />
      )}
      <Form layout="vertical" style={{ maxWidth: 640 }} onFinish={save}>
        <Form.Item
          label="推送新告警"
          extra="开启后，新出现的告警约 30 秒内推送到群里；同时出现多条时合并成一条消息。"
        >
          <Switch aria-label="推送新告警" checked={enabled} onChange={setEnabled} />
        </Form.Item>
        <Form.Item label="推送到" extra={current.help}>
          <Select
            aria-label="推送渠道"
            value={channel}
            onChange={setChannel}
            options={channels.map((c) => ({ value: c.value, label: c.label }))}
          />
        </Form.Item>
        <Form.Item
          label="机器人地址（Webhook）"
          extra={
            saved.webhookUrl
              ? "地址里带有机器人的访问令牌，已保存的地址只显示开头和末尾；不修改就保留原地址。"
              : undefined
          }
        >
          <Input
            aria-label="机器人地址"
            value={url}
            onChange={(e) => setUrl(e.target.value.trim())}
            placeholder={`https://${current.host}/...`}
          />
        </Form.Item>
        {channel !== "WeCom" && (
          <Form.Item
            label="签名密钥"
            extra="机器人安全设置为「加签」或「签名校验」时填写，否则留空。"
          >
            <Space.Compact style={{ width: "100%" }}>
              <Input.Password
                aria-label="签名密钥"
                value={secret ?? ""}
                onChange={(e) => setSecret(e.target.value)}
                placeholder={
                  saved.hasSecret && secret === null ? "已设置，留空则不变" : "SEC 开头的密钥"
                }
                autoComplete="off"
              />
              {saved.hasSecret && (
                <Button onClick={() => setSecret("")} disabled={secret === ""}>
                  清除
                </Button>
              )}
            </Space.Compact>
          </Form.Item>
        )}
        <Form.Item label="推送哪些告警">
          <Checkbox.Group
            value={types}
            onChange={(v) => setTypes(v as string[])}
            options={pushTypes.map((t) => ({ value: t, label: alertTypeLabel(t) }))}
          />
          {types.includes("Offline") && (
            <Typography.Paragraph type="secondary" style={{ marginTop: 8, marginBottom: 0 }}>
              员工下班关机也会产生「设备失联」告警，开启后每天下班时会收到较多消息。
            </Typography.Paragraph>
          )}
        </Form.Item>
        <Form.Item
          label="管理端地址"
          extra="消息里附上告警页面的链接，经网关访问时填网关上的域名。"
        >
          <Input
            aria-label="管理端地址"
            value={consoleUrl}
            onChange={(e) => setConsoleUrl(e.target.value.trim())}
          />
        </Form.Item>
        <Space wrap>
          <Button type="primary" htmlType="submit" loading={busy}>
            保存
          </Button>
          <Button onClick={test} loading={testing} disabled={!saved.webhookUrl}>
            发送测试消息
          </Button>
          <Typography.Text type="secondary">测试消息使用已保存的设置。</Typography.Text>
        </Space>
      </Form>
      <div style={{ marginTop: 16 }}>
        <ErrorNotice error={error} />
        {last && (
          <Alert
            type={last.ok ? "success" : "warning"}
            showIcon
            title={
              last.ok
                ? `最近一次推送成功（${time(last.at)}${last.sent ? `，${last.sent} 条告警` : "，测试消息"}）`
                : `最近一次推送失败（${time(last.at)}）：${last.error}。会在 30 秒后重试。`
            }
          />
        )}
      </div>
    </Panel>
  );
}

function RetentionPanel({ session, days }: { session: Session; days: number }) {
  // Audit records also hold operators to account, so only publishers may change how long they are kept.
  const canEdit = role(session, "Publisher");
  const { message } = App.useApp();
  const refresh = useRefresh();
  const [value, setValue] = useState(days),
    [busy, setBusy] = useState(false),
    [error, setError] = useState<string | null>(null);

  async function save() {
    setBusy(true);
    setError(null);
    try {
      await request("/api/settings/audit-retention", {
        method: "PUT",
        body: { days: value },
        csrfToken: session.csrfToken,
      });
      void message.success("已保存");
      refresh();
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Panel title="审计记录保留">
      <Space wrap>
        <Select
          aria-label="审计记录保留期限"
          value={value}
          onChange={setValue}
          options={retentionChoices}
          style={{ width: 160 }}
          disabled={!canEdit}
        />
        {canEdit ? (
          <Button type="primary" onClick={save} loading={busy} disabled={value === days}>
            保存
          </Button>
        ) : (
          <Typography.Text type="secondary">只有发布人可以修改</Typography.Text>
        )}
      </Space>
      <Typography.Paragraph type="secondary" style={{ marginTop: 12, marginBottom: 0 }}>
        超过期限的审计记录每小时清理一次，清理本身也会记入审计记录。按网络安全法，网络日志至少保留 6
        个月，因此最短为 180 天。
      </Typography.Paragraph>
      <ErrorNotice error={error} />
    </Panel>
  );
}

/** Mounts the forms once the settings are loaded, so polling does not overwrite what is being typed. */
function SettingsPanels({ session }: { session: Session }) {
  const settings = useResource<AppSettings>("/api/settings");
  const [initial, setInitial] = useState<AppSettings | null>(null);
  useEffect(() => {
    if (settings.data && !initial) setInitial(settings.data);
  }, [settings.data, initial]);
  if (!initial)
    return (
      <Panel title="告警推送">
        <Fresh error={settings.error} loading={settings.loading}>
          {null}
        </Fresh>
      </Panel>
    );
  const current = settings.data ?? initial;
  return (
    <>
      <NotificationPanel session={session} initial={initial} live={current} />
      <RetentionPanel
        key={current.auditRetentionDays}
        session={session}
        days={current.auditRetentionDays}
      />
    </>
  );
}

export function SystemPage({ session }: { session: Session }) {
  const status = useResource<Status>("/api/status");
  const caps: Capability[] = (status.data?.networkCapabilities ?? []).map((c) =>
    typeof c === "string" ? { id: c, implemented: false, verified: false, detail: "" } : c,
  );
  return (
    <>
      <PageHeading
        title="系统设置"
        description="告警推送、审计记录保留期限、客户端远程升级、策略签名密钥，以及管理端的运行模式和网络防护能力。终端上的实际防护效果以终端上报的证据为准。"
      />
      <Space orientation="vertical" size={16} style={{ width: "100%" }}>
        {role(session, "Operator") && <SettingsPanels session={session} />}
        {(role(session, "Operator") || role(session, "Publisher")) && (
          <ClientPackagesPanel session={session} />
        )}
        {role(session, "Publisher") && <SigningKeyPanel session={session} />}
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
