import { useState } from "react";
import { App, Button, Flex, Form, Input, Modal, QRCode, Space, Typography } from "antd";
import { request } from "../api";
import type { Session, TwoFactorSetup } from "../types";
import { ErrorNotice, errorText } from "./common";

const MIN_LENGTH = 12;

interface Values {
  currentPassword: string;
  newPassword: string;
  confirm: string;
}

/** Changes the signed-in administrator's password; other browsers signed in with it are signed out. */
export function PasswordDialog({
  session,
  open,
  onClose,
}: {
  session: Session;
  open: boolean;
  onClose: () => void;
}) {
  const [form] = Form.useForm<Values>();
  const { message } = App.useApp();
  const [busy, setBusy] = useState(false),
    [error, setError] = useState<string | null>(null);

  function close() {
    form.resetFields();
    setError(null);
    onClose();
  }

  async function submit(values: Values) {
    setBusy(true);
    setError(null);
    try {
      await request("/api/auth/password", {
        method: "POST",
        body: { currentPassword: values.currentPassword, newPassword: values.newPassword },
        csrfToken: session.csrfToken,
      });
      void message.success("密码已修改，其他浏览器上的登录已退出");
      close();
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal
      title="修改密码"
      open={open}
      onCancel={close}
      onOk={() => form.submit()}
      okText="修改"
      confirmLoading={busy}
      destroyOnHidden
    >
      <Form form={form} layout="vertical" onFinish={submit} requiredMark={false}>
        <Form.Item
          label="当前密码"
          name="currentPassword"
          rules={[{ required: true, message: "请输入当前密码" }]}
        >
          <Input.Password autoComplete="current-password" />
        </Form.Item>
        <Form.Item
          label="新密码"
          name="newPassword"
          extra={`至少 ${MIN_LENGTH} 位。修改后 .env 里的初始密码不再有效。`}
          rules={[
            { required: true, message: "请输入新密码" },
            { min: MIN_LENGTH, message: `新密码至少 ${MIN_LENGTH} 位` },
          ]}
        >
          <Input.Password autoComplete="new-password" />
        </Form.Item>
        <Form.Item
          label="确认新密码"
          name="confirm"
          dependencies={["newPassword"]}
          rules={[
            { required: true, message: "请再输入一次新密码" },
            ({ getFieldValue }) => ({
              validator: (_, value) =>
                !value || value === getFieldValue("newPassword")
                  ? Promise.resolve()
                  : Promise.reject(new Error("两次输入的新密码不一致")),
            }),
          ]}
        >
          <Input.Password autoComplete="new-password" />
        </Form.Item>
      </Form>
      <ErrorNotice error={error} />
    </Modal>
  );
}

/** Turns two-step sign-in on: a QR code for an authenticator app, then one code from it to confirm. */
export function TwoFactorSetupForm({ session, onDone }: { session: Session; onDone: () => void }) {
  const { message } = App.useApp();
  const [setup, setSetup] = useState<TwoFactorSetup | null>(null),
    [code, setCode] = useState(""),
    [busy, setBusy] = useState(false),
    [error, setError] = useState<string | null>(null);

  async function start() {
    setBusy(true);
    setError(null);
    try {
      setSetup(
        await request<TwoFactorSetup>("/api/auth/two-factor/setup", {
          method: "POST",
          body: {},
          csrfToken: session.csrfToken,
        }),
      );
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(false);
    }
  }

  async function enable() {
    setBusy(true);
    setError(null);
    try {
      await request("/api/auth/two-factor/enable", {
        method: "POST",
        body: { code },
        csrfToken: session.csrfToken,
      });
      void message.success("两步验证已启用，以后登录时还需输入验证码");
      onDone();
    } catch (e) {
      setError(errorText(e));
      setCode("");
    } finally {
      setBusy(false);
    }
  }

  return (
    <Flex vertical gap={12}>
      <Typography.Paragraph style={{ marginBottom: 0 }}>
        启用后，登录时除了密码，还要输入手机验证器 App（如 Microsoft Authenticator、Google
        Authenticator、腾讯身份验证器）上每 30 秒变化一次的 6 位验证码。密码泄露时，别人也无法登录。
      </Typography.Paragraph>
      {!setup ? (
        <div>
          <Button type="primary" onClick={start} loading={busy}>
            开始设置
          </Button>
        </div>
      ) : (
        <>
          <Flex gap={16} wrap align="flex-start">
            <QRCode value={setup.uri} size={168} bordered={false} aria-label="两步验证二维码" />
            <Flex vertical gap={6} style={{ flex: "1 1 220px" }}>
              <span>1. 用验证器 App 扫描左侧二维码。</span>
              <span>
                无法扫描时，在 App 里手动添加，密钥：
                <Typography.Text code copyable className="totp-secret">
                  {setup.secret}
                </Typography.Text>
              </span>
              <span>2. 输入 App 上显示的 6 位验证码。</span>
            </Flex>
          </Flex>
          <Space.Compact style={{ maxWidth: 320 }}>
            <Input
              aria-label="验证码"
              placeholder="6 位验证码"
              inputMode="numeric"
              autoComplete="one-time-code"
              maxLength={7}
              value={code}
              onChange={(e) => setCode(e.target.value)}
              onPressEnter={() => code.trim() && void enable()}
            />
            <Button type="primary" onClick={enable} loading={busy} disabled={!code.trim()}>
              启用
            </Button>
          </Space.Compact>
        </>
      )}
      <ErrorNotice error={error} />
    </Flex>
  );
}

/** The signed-in administrator's own two-step sign-in: set up, or turned off with the password and a code. */
export function TwoFactorDialog({
  session,
  open,
  onClose,
  onChanged,
}: {
  session: Session;
  open: boolean;
  onClose: () => void;
  onChanged: () => void;
}) {
  const [form] = Form.useForm<{ password: string; code: string }>();
  const { message } = App.useApp();
  const [busy, setBusy] = useState(false),
    [error, setError] = useState<string | null>(null);

  function close() {
    form.resetFields();
    setError(null);
    onClose();
  }

  async function disable(values: { password: string; code: string }) {
    setBusy(true);
    setError(null);
    try {
      await request("/api/auth/two-factor/disable", {
        method: "POST",
        body: values,
        csrfToken: session.csrfToken,
      });
      void message.success("两步验证已关闭");
      close();
      onChanged();
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal title="两步验证" open={open} onCancel={close} footer={null} destroyOnHidden>
      {!session.twoFactor ? (
        <TwoFactorSetupForm
          session={session}
          onDone={() => {
            close();
            onChanged();
          }}
        />
      ) : session.twoFactorRequired ? (
        <Typography.Paragraph>
          已启用。单位要求所有账号使用两步验证，不能关闭；换手机时请联系账号管理员重置。
        </Typography.Paragraph>
      ) : (
        <>
          <Typography.Paragraph>
            已启用，登录时需输入验证器 App 上的验证码。换手机前请先关闭，再在新手机上重新设置。
          </Typography.Paragraph>
          <Form form={form} layout="vertical" onFinish={disable} requiredMark={false}>
            <Form.Item
              label="当前密码"
              name="password"
              rules={[{ required: true, message: "请输入当前密码" }]}
            >
              <Input.Password autoComplete="current-password" />
            </Form.Item>
            <Form.Item
              label="验证码"
              name="code"
              rules={[{ required: true, message: "请输入验证码" }]}
            >
              <Input inputMode="numeric" autoComplete="one-time-code" maxLength={7} />
            </Form.Item>
            <Button danger htmlType="submit" loading={busy}>
              关闭两步验证
            </Button>
          </Form>
          <ErrorNotice error={error} />
        </>
      )}
    </Modal>
  );
}
