import { useState } from "react";
import {
  Alert as Notice,
  App,
  Button,
  Checkbox,
  Col,
  Form,
  Input,
  InputNumber,
  Row,
  Select,
  Space,
  Switch,
  Typography,
} from "antd";
import { request } from "../api";
import { useRefresh, useResource } from "../useResource";
import type { LogForwardingSettings, LogForwardingView, Session } from "../types";
import { ErrorNotice, errorText, time } from "./common";
import { Fresh, Panel } from "./layout";

const protocols = [
  { value: "Udp", label: "UDP（常用端口 514）", port: 514 },
  { value: "Tcp", label: "TCP（每行一条，常用端口 514）", port: 514 },
  { value: "Tls", label: "TLS 加密（RFC 5425，常用端口 6514）", port: 6514 },
];

const formats = [
  { value: "Json", label: "JSON（RFC 5424 消息体为 JSON）" },
  { value: "Cef", label: "CEF（ArcSight 通用事件格式）" },
];

const facilities = Array.from({ length: 8 }, (_, i) => ({ value: 16 + i, label: `local${i}` }));

type Values = LogForwardingSettings & { kinds: string[] };

function ForwardingForm({ session, view }: { session: Session; view: LogForwardingView }) {
  const { message } = App.useApp();
  const refresh = useRefresh();
  const [form] = Form.useForm<Values>();
  const [busy, setBusy] = useState(false),
    [testing, setTesting] = useState(false),
    [error, setError] = useState<string | null>(null);
  const protocol = Form.useWatch("protocol", form) ?? view.settings.protocol;
  const enabled = Form.useWatch("enabled", form) ?? view.settings.enabled;
  const last = view.last;

  async function save(values: Values) {
    setBusy(true);
    setError(null);
    try {
      const { kinds, ...rest } = values;
      await request("/api/settings/log-forwarding", {
        method: "PUT",
        body: { ...rest, alerts: kinds.includes("alerts"), audit: kinds.includes("audit") },
        csrfToken: session.csrfToken,
      });
      void message.success(
        values.enabled ? "已保存，新的告警和审计记录会发到日志服务器" : "已保存，日志外发已关闭",
      );
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
        "/api/settings/log-forwarding/test",
        { method: "POST", body: {}, csrfToken: session.csrfToken },
      );
      if (r.ok) void message.success("测试消息已发送，请到日志服务器上查看");
      else setError("测试消息发送失败：" + (r.error ?? "原因未知"));
      refresh();
    } catch (e) {
      setError(errorText(e));
    } finally {
      setTesting(false);
    }
  }

  const s = view.settings;
  return (
    <Form<Values>
      form={form}
      layout="vertical"
      requiredMark={false}
      onFinish={save}
      initialValues={{
        ...s,
        kinds: [...(s.alerts ? ["alerts"] : []), ...(s.audit ? ["audit"] : [])],
      }}
    >
      <Form.Item name="enabled" valuePropName="checked" label="发送到日志服务器">
        <Switch aria-label="发送到日志服务器" />
      </Form.Item>
      <Row gutter={16}>
        <Col xs={24} md={10}>
          <Form.Item
            label="服务器地址"
            name="host"
            rules={[{ required: enabled, whitespace: true, message: "请填写日志服务器地址" }]}
          >
            <Input placeholder="例如 siem.example.local 或 10.0.0.20" />
          </Form.Item>
        </Col>
        <Col xs={24} md={4}>
          <Form.Item label="端口" name="port" rules={[{ required: true, message: "请填写端口" }]}>
            <InputNumber min={1} max={65535} style={{ width: "100%" }} />
          </Form.Item>
        </Col>
        <Col xs={24} md={10}>
          <Form.Item label="协议" name="protocol">
            <Select
              options={protocols}
              onChange={(v) => {
                const from = protocols.find((p) => p.value === protocol)?.port;
                if (form.getFieldValue("port") === from)
                  form.setFieldValue("port", protocols.find((p) => p.value === v)?.port);
              }}
            />
          </Form.Item>
        </Col>
      </Row>
      <Row gutter={16}>
        <Col xs={24} md={10}>
          <Form.Item
            label="消息格式"
            name="format"
            extra="大多数 SIEM（如 Splunk、QRadar、ArcSight、国内态势感知平台）两种都能解析；不确定时选 JSON。"
          >
            <Select options={formats} />
          </Form.Item>
        </Col>
        <Col xs={24} md={4}>
          <Form.Item label="设施" name="facility">
            <Select options={facilities} />
          </Form.Item>
        </Col>
        <Col xs={24} md={10}>
          <Form.Item
            label="发送内容"
            name="kinds"
            rules={[
              { required: enabled, type: "array", min: enabled ? 1 : 0, message: "请至少选择一项" },
            ]}
          >
            <Checkbox.Group
              options={[
                { value: "alerts", label: "告警（产生和恢复）" },
                { value: "audit", label: "审计记录（登录、策略、账号等操作）" },
              ]}
            />
          </Form.Item>
        </Col>
      </Row>
      {protocol === "Tls" && (
        <Form.Item
          label="信任的 CA 证书（可选）"
          name="caCertificate"
          extra="日志服务器使用单位内部 CA 签发的证书时，粘贴该 CA 的 PEM 证书；使用公共证书时留空。证书里的名称须与服务器地址一致。"
        >
          <Input.TextArea rows={4} placeholder="-----BEGIN CERTIFICATE-----" className="mono" />
        </Form.Item>
      )}
      <Space wrap>
        <Button type="primary" htmlType="submit" loading={busy}>
          保存
        </Button>
        <Button onClick={test} loading={testing} disabled={!s.host}>
          发送测试消息
        </Button>
        <Typography.Text type="secondary">测试消息按已保存的设置发送</Typography.Text>
      </Space>
      {last && (
        <Notice
          style={{ marginTop: 16 }}
          type={last.ok ? "success" : "error"}
          showIcon
          title={
            last.ok
              ? `${time(last.at)} 发送成功${last.sent ? `，共 ${last.sent} 条` : ""}`
              : `${time(last.at)} 发送失败：${last.error}，会自动重试`
          }
        />
      )}
      <ErrorNotice error={error} />
    </Form>
  );
}

/** Sends alerts and audit records to the organisation's syslog server or SIEM. */
export function LogForwardingPanel({ session }: { session: Session }) {
  const view = useResource<LogForwardingView>("/api/settings/log-forwarding");
  const data = view.lastData;
  return (
    <Panel title="日志外发（Syslog / SIEM）">
      <Typography.Paragraph type="secondary">
        把告警（产生和恢复）和审计记录实时发到单位的日志服务器或安全态势平台，便于集中留存和关联分析。开启前产生的记录不会补发；发送失败时自动重试，不会丢失。
      </Typography.Paragraph>
      <Fresh error={view.error && !data ? view.error : null} loading={view.loading}>
        {/* The form is filled once; later refreshes only update the last result below it. */}
        {data && <ForwardingForm session={session} view={data} />}
      </Fresh>
    </Panel>
  );
}
