import { useState } from "react";
import { Alert, Button, Form, InputNumber, Result, Typography } from "antd";
import { request } from "../api";
import { ErrorNotice, errorText, PageHeading, Panel, time } from "../components";
import { role } from "../session";
import type { Session } from "../types";

export function Registration({ session }: { session: Session }) {
  const [minutes, setMinutes] = useState(15),
    [result, setResult] = useState<{ code: string; expiresAt: string } | null>(null),
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
        title="终端登记"
        description="登记码只显示一次，使用一次后即失效。请通过本单位认可的渠道交给终端安装人员。"
      />
      <Panel title="生成一次性登记码">
        {role(session, "Operator") ? (
          <>
            <Form layout="inline" onFinish={create} style={{ marginBottom: 16 }}>
              <Form.Item label="有效期（分钟）">
                <InputNumber
                  aria-label="有效期（分钟）"
                  min={1}
                  max={60}
                  value={minutes}
                  onChange={(v) => setMinutes(v ?? 15)}
                />
              </Form.Item>
              <Button type="primary" htmlType="submit" loading={busy}>
                生成登记码
              </Button>
            </Form>
            <ErrorNotice error={error} />
            {result && (
              <Result
                status="success"
                title={
                  <Typography.Text copyable className="mono registration-code">
                    {result.code}
                  </Typography.Text>
                }
                subTitle={`有效期至 ${time(result.expiresAt)}。此码仅显示这一次，刷新页面后无法再次查看，请立即妥善保存。`}
              />
            )}
          </>
        ) : (
          <Alert type="info" showIcon title="当前账号没有登记终端的权限（需要“操作员”角色）。" />
        )}
      </Panel>
    </>
  );
}
