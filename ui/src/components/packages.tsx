import { useRef, useState } from "react";
import { App, Button, Input, Space, Table, Typography } from "antd";
import { UploadOutlined } from "@ant-design/icons";
import { request } from "../api";
import { role } from "../session";
import { useRefresh, useResource } from "../useResource";
import { Empty, ErrorNotice, errorText, time } from "./common";
import { Fresh, Panel } from "./layout";
import type { ClientPackage, Session, UpgradeRollout } from "../types";

/** The release a file name carries, such as 0.2.30 in compliance-client-0.2.30-windows-x64.msi. */
export function packageVersion(name: string): string {
  return /(\d+\.\d+\.\d+)/.exec(name)?.[1] ?? "";
}

const megabytes = (size: number) => `${(size / 1024 / 1024).toFixed(1)} MB`;

/** Client installers kept on the server for remote upgrades: uploading, sending to outdated devices, deleting. */
export function ClientPackagesPanel({ session }: { session: Session }) {
  const { message, modal } = App.useApp();
  const refresh = useRefresh();
  const packages = useResource<ClientPackage[]>("/api/client-packages");
  const input = useRef<HTMLInputElement>(null);
  const [file, setFile] = useState<File | null>(null),
    [version, setVersion] = useState(""),
    [busy, setBusy] = useState(false),
    [error, setError] = useState<string | null>(null);
  const publisher = role(session, "Publisher"),
    operator = role(session, "Operator");

  async function upload() {
    if (!file) return;
    setBusy(true);
    setError(null);
    try {
      await request(`/api/client-packages?version=${encodeURIComponent(version)}`, {
        method: "POST",
        file,
        csrfToken: session.csrfToken,
      });
      void message.success(`已上传 ${version} 安装包`);
      setFile(null);
      setVersion("");
      if (input.current) input.current.value = "";
      refresh();
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(false);
    }
  }
  function rollout(p: ClientPackage) {
    modal.confirm({
      title: `把客户端升级到 ${p.version}？`,
      content: `将向 ${p.outdated} 台客户端版本较旧的终端发送升级，终端在一天内联系管理端时下载并安装，期间托盘会关闭，员工下次登录时恢复。`,
      okText: "发送升级",
      cancelText: "取消",
      onOk: async () => {
        try {
          const r = await request<UpgradeRollout>(
            `/api/client-packages/${encodeURIComponent(p.version)}/rollout`,
            { method: "POST", csrfToken: session.csrfToken },
          );
          void message.success(
            r.queued
              ? `已向 ${r.queued} 台终端发送升级`
              : "没有需要发送的终端（已在升级中或已是新版本）",
          );
          refresh();
        } catch (e) {
          void message.error(errorText(e));
        }
      },
    });
  }
  function remove(p: ClientPackage) {
    modal.confirm({
      title: `删除 ${p.version} 安装包？`,
      content: "已发出但终端尚未下载的升级将无法完成。",
      okText: "删除",
      okButtonProps: { danger: true },
      cancelText: "取消",
      onOk: async () => {
        try {
          await request(`/api/client-packages/${encodeURIComponent(p.version)}`, {
            method: "DELETE",
            csrfToken: session.csrfToken,
          });
          refresh();
        } catch (e) {
          void message.error(errorText(e));
        }
      },
    });
  }

  return (
    <Panel title="客户端远程升级">
      <Typography.Paragraph type="secondary">
        上传发布页上的客户端
        MSI，管理端用策略签名密钥签名后托管。终端只安装签名有效、内容一致且比自己新的安装包，升级保留登记信息。
      </Typography.Paragraph>
      {publisher && (
        <Space wrap style={{ marginBottom: 12 }}>
          <input
            ref={input}
            type="file"
            accept=".msi"
            aria-label="选择客户端安装包"
            onChange={(e) => {
              const chosen = e.target.files?.[0] ?? null;
              setFile(chosen);
              setVersion(chosen ? packageVersion(chosen.name) : "");
            }}
          />
          <Input
            aria-label="安装包版本"
            placeholder="版本，如 0.2.30"
            value={version}
            onChange={(e) => setVersion(e.target.value.trim())}
            style={{ width: 160 }}
          />
          <Button
            type="primary"
            icon={<UploadOutlined />}
            loading={busy}
            disabled={!file || !version}
            onClick={upload}
          >
            上传
          </Button>
        </Space>
      )}
      <ErrorNotice error={error} />
      <Fresh error={packages.error} loading={packages.loading}>
        <Table<ClientPackage>
          rowKey="version"
          dataSource={packages.data ?? []}
          size="small"
          pagination={false}
          locale={{ emptyText: <Empty title="还没有上传客户端安装包" /> }}
          columns={[
            { title: "版本", dataIndex: "version" },
            { title: "大小", key: "size", render: (_, p) => megabytes(p.size) },
            {
              title: "上传",
              key: "uploaded",
              render: (_, p) => `${time(p.uploadedAt)} · ${p.uploadedBy}`,
            },
            { title: "版本较旧的终端", dataIndex: "outdated" },
            {
              title: "操作",
              key: "actions",
              render: (_, p) => (
                <Space size={4}>
                  {operator && (
                    <Button size="small" disabled={!p.outdated} onClick={() => rollout(p)}>
                      升级较旧的终端
                    </Button>
                  )}
                  {publisher && (
                    <Button size="small" danger onClick={() => remove(p)}>
                      删除
                    </Button>
                  )}
                </Space>
              ),
            },
          ]}
        />
      </Fresh>
    </Panel>
  );
}
