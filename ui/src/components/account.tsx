import { useState } from "react";
import { App, Form, Input, Modal } from "antd";
import { request } from "../api";
import type { Session } from "../types";
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
