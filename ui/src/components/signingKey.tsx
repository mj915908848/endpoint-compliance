import { useState } from "react";
import { App, Button, Descriptions, Progress, Space, Table, Typography } from "antd";
import { HttpError, request } from "../api";
import { useRefresh, useResource } from "../useResource";
import { errorText, time } from "./common";
import { Fresh, Panel } from "./layout";
import type { Session, SigningKeyState } from "../types";

type Waiting = NonNullable<SigningKeyState["rotation"]>["waiting"][number];

/**
 * Replacing the policy signing key: the next key is announced to clients under the current one, and once they all
 * trust it, completing re-signs every policy and installer with it. Devices that never heard of it must enroll again.
 */
export function SigningKeyPanel({ session }: { session: Session }) {
  const { message, modal } = App.useApp();
  const refresh = useRefresh();
  const state = useResource<SigningKeyState>("/api/settings/signing-key");
  const [busy, setBusy] = useState(false);
  const rotation = state.data?.rotation;

  async function send(method: string, path: string, body?: unknown) {
    setBusy(true);
    try {
      await request<SigningKeyState>(`/api/settings/signing-key${path}`, {
        method,
        body,
        csrfToken: session.csrfToken,
      });
      refresh();
      return true;
    } catch (e) {
      if (e instanceof HttpError && e.status === 409 && path === "/rotation/complete" && !body)
        return false;
      void message.error(errorText(e));
      return true;
    } finally {
      setBusy(false);
    }
  }
  function start() {
    modal.confirm({
      title: "开始更换策略签名密钥？",
      content:
        "管理端生成新密钥，并在心跳回复里用当前密钥签名告知客户端。所有终端都收到新密钥后再完成更换，终端不需要重新登记。",
      okText: "开始",
      cancelText: "取消",
      onOk: () => send("POST", "/rotation"),
    });
  }
  async function complete() {
    if (!rotation) return;
    if (rotation.ready >= rotation.devices) {
      modal.confirm({
        title: "完成密钥更换？",
        content: "全部策略和客户端安装包将改用新密钥重新签名，旧密钥另存备查。",
        okText: "完成",
        cancelText: "取消",
        onOk: async () => {
          if (!(await send("POST", "/rotation/complete"))) {
            void message.warning("又有终端需要新密钥，请刷新后再试");
            refresh();
          }
        },
      });
      return;
    }
    modal.confirm({
      title: `还有 ${rotation.devices - rotation.ready} 台终端没有收到新密钥`,
      content:
        "现在完成，这些终端将无法再验证策略和安装包，需要重新登记。通常应等它们联网后再完成。",
      okText: "仍然完成",
      okButtonProps: { danger: true },
      cancelText: "取消",
      onOk: () => send("POST", "/rotation/complete", { force: true }),
    });
  }
  function cancel() {
    modal.confirm({
      title: "取消密钥更换？",
      content: "新密钥将被删除，客户端继续使用当前密钥。",
      okText: "取消更换",
      okButtonProps: { danger: true },
      cancelText: "返回",
      onOk: () => send("DELETE", "/rotation"),
    });
  }

  return (
    <Panel title="策略签名密钥">
      <Typography.Paragraph type="secondary">
        策略和客户端安装包都用这把密钥签名，客户端登记时记下它的公钥。怀疑密钥泄露或按制度定期更换时，在这里更换，终端无需重新登记。
      </Typography.Paragraph>
      <Fresh error={state.error} loading={state.loading}>
        {state.data && (
          <Space orientation="vertical" size={12} style={{ width: "100%" }}>
            <Descriptions
              size="small"
              bordered
              column={1}
              items={[
                { key: "current", label: "当前密钥", children: state.data.keyId },
                ...(rotation
                  ? [
                      { key: "next", label: "新密钥", children: rotation.nextKeyId },
                      { key: "started", label: "开始于", children: time(rotation.startedAt) },
                      {
                        key: "ready",
                        label: "已收到新密钥",
                        children: (
                          <Space>
                            <Progress
                              percent={
                                rotation.devices
                                  ? Math.floor((rotation.ready / rotation.devices) * 100)
                                  : 100
                              }
                              size="small"
                              style={{ width: 160 }}
                            />
                            {`${rotation.ready} / ${rotation.devices} 台终端`}
                          </Space>
                        ),
                      },
                    ]
                  : []),
              ]}
            />
            {rotation ? (
              <Space wrap>
                <Button type="primary" loading={busy} onClick={complete}>
                  完成更换
                </Button>
                <Button loading={busy} onClick={cancel}>
                  取消更换
                </Button>
              </Space>
            ) : (
              <Button loading={busy} onClick={start}>
                更换密钥
              </Button>
            )}
            {rotation && rotation.waiting.length > 0 && (
              <Table<Waiting>
                rowKey="id"
                size="small"
                pagination={false}
                dataSource={rotation.waiting}
                title={() => "尚未收到新密钥的终端（终端联网后会自动收到）"}
                columns={[
                  { title: "终端", dataIndex: "hostName" },
                  {
                    title: "最近心跳",
                    key: "lastHeartbeat",
                    render: (_, d) => (d.lastHeartbeat ? time(d.lastHeartbeat) : "从未"),
                  },
                ]}
              />
            )}
          </Space>
        )}
      </Fresh>
    </Panel>
  );
}
