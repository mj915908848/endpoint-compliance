import { useRef, useState } from "react";
import {
  Alert,
  App,
  Button,
  Input,
  InputNumber,
  Modal,
  Radio,
  Space,
  Table,
  Tag,
  Typography,
} from "antd";
import { PaperClipOutlined, UploadOutlined } from "@ant-design/icons";
import { request } from "../api";
import { role } from "../session";
import { useRefresh, useResource } from "../useResource";
import { Empty, ErrorNotice, errorText, time } from "./common";
import { Fresh, Panel } from "./layout";
import type {
  ClientPackage,
  Session,
  UpgradeProgress,
  UpgradeProgressItem,
  UpgradeRollout,
} from "../types";

const upgradeStates: Record<string, { label: string; color: string }> = {
  Waiting: { label: "等待下载", color: "default" },
  Installing: { label: "安装中", color: "processing" },
  Succeeded: { label: "已升级", color: "success" },
  Failed: { label: "失败", color: "error" },
  NotApplied: { label: "未生效", color: "warning" },
  Expired: { label: "已过期", color: "default" },
};

/** Devices sent one version so far, by how their upgrade stands. */
function counts(p: UpgradeProgress) {
  const by = (state: string) => p.devices.filter((d) => d.state === state).length;
  return {
    succeeded: by("Succeeded"),
    failed: by("Failed") + by("NotApplied"),
    pending: by("Waiting") + by("Installing"),
    expired: by("Expired"),
  };
}

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
  const [rolling, setRolling] = useState<ClientPackage | null>(null),
    [watching, setWatching] = useState<string | null>(null);
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
        <>
          <input
            ref={input}
            type="file"
            accept=".msi"
            aria-label="选择客户端安装包"
            className="visually-hidden"
            onChange={(e) => {
              const chosen = e.target.files?.[0] ?? null;
              setFile(chosen);
              setVersion(chosen ? packageVersion(chosen.name) : "");
            }}
          />
          <Space wrap style={{ marginBottom: 12 }}>
            <Button icon={<PaperClipOutlined />} onClick={() => input.current?.click()}>
              {file ? file.name : "选择安装包"}
            </Button>
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
        </>
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
                <Space size={4} wrap>
                  {operator && (
                    <Button size="small" disabled={!p.outdated} onClick={() => setRolling(p)}>
                      升级较旧的终端
                    </Button>
                  )}
                  <Button size="small" onClick={() => setWatching(p.version)}>
                    升级进度
                  </Button>
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
      {rolling && (
        <RolloutDialog
          session={session}
          target={rolling}
          close={() => setRolling(null)}
          showProgress={() => {
            setWatching(rolling.version);
            setRolling(null);
          }}
        />
      )}
      {watching && <ProgressDialog version={watching} close={() => setWatching(null)} />}
    </Panel>
  );
}

/** Sends the upgrade to every outdated device, or to a few first. */
function RolloutDialog({
  session,
  target,
  close,
  showProgress,
}: {
  session: Session;
  target: ClientPackage;
  close: () => void;
  showProgress: () => void;
}) {
  const { message } = App.useApp();
  const refresh = useRefresh();
  const progress = useResource<UpgradeProgress>(
    `/api/client-packages/${encodeURIComponent(target.version)}/rollout`,
  );
  const [staged, setStaged] = useState(target.outdated > 5),
    [count, setCount] = useState(Math.min(5, target.outdated)),
    [busy, setBusy] = useState(false);
  const sofar = progress.data ? counts(progress.data) : null;

  async function send() {
    setBusy(true);
    try {
      const r = await request<UpgradeRollout>(
        `/api/client-packages/${encodeURIComponent(target.version)}/rollout${staged ? `?count=${count}` : ""}`,
        { method: "POST", csrfToken: session.csrfToken },
      );
      void message.success(
        r.queued
          ? `已向 ${r.queued} 台终端发送升级`
          : "没有需要发送的终端（已在升级中或已是新版本）",
      );
      refresh();
      close();
    } catch (e) {
      void message.error(errorText(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal
      open
      title={`把客户端升级到 ${target.version}`}
      okText="发送升级"
      cancelText="取消"
      confirmLoading={busy}
      okButtonProps={{ disabled: staged && !count }}
      onOk={send}
      onCancel={close}
    >
      <Space orientation="vertical" size={12} style={{ width: "100%" }}>
        {sofar && sofar.failed > 0 && (
          <Alert
            type="warning"
            showIcon
            message={`已发出的升级中有 ${sofar.failed} 台没有成功`}
            description="建议先查看原因，确认安装包没有问题再继续。"
            action={
              <Button size="small" onClick={showProgress}>
                查看进度
              </Button>
            }
          />
        )}
        <Radio.Group
          value={staged}
          onChange={(e) => setStaged(e.target.value as boolean)}
          style={{ display: "flex", flexDirection: "column", gap: 8 }}
        >
          <Radio value={true}>
            <Space size={4}>
              先升
              <InputNumber
                aria-label="先升级的台数"
                size="small"
                min={1}
                max={target.outdated}
                value={count}
                onChange={(v) => setCount(v ?? 0)}
                style={{ width: 72 }}
              />
              台，在线的终端优先
            </Space>
          </Radio>
          <Radio value={false}>全部 {target.outdated} 台版本较旧的终端</Radio>
        </Radio.Group>
        <Typography.Text type="secondary">
          终端在一天内联系管理端时下载并安装，期间托盘会关闭，员工下次登录时恢复。装完后终端会回报结果，可在「升级进度」里查看；先升几台确认没问题，再升其余的。
        </Typography.Text>
      </Space>
    </Modal>
  );
}

/** Where each device sent this version stands. */
function ProgressDialog({ version, close }: { version: string; close: () => void }) {
  const progress = useResource<UpgradeProgress>(
    `/api/client-packages/${encodeURIComponent(version)}/rollout`,
  );
  const p = progress.data;
  const sofar = p ? counts(p) : null;
  return (
    <Modal open title={`升级到 ${version} 的进度`} footer={null} onCancel={close} width={760}>
      <Fresh error={progress.error} loading={progress.loading}>
        {p && sofar && (
          <Space orientation="vertical" size={12} style={{ width: "100%" }}>
            <Typography.Text>
              已发送 {p.devices.length} 台：已升级 {sofar.succeeded}，进行中 {sofar.pending}
              ，没有成功 {sofar.failed}
              {sofar.expired > 0 && `，过期 ${sofar.expired}`}。还有 {p.remaining}{" "}
              台版本较旧的终端没有发送。
            </Typography.Text>
            <Table<UpgradeProgressItem>
              rowKey="deviceId"
              dataSource={p.devices}
              size="small"
              pagination={{ pageSize: 10, hideOnSinglePage: true }}
              scroll={{ x: 600 }}
              locale={{ emptyText: <Empty title="还没有向终端发送这个版本" /> }}
              columns={[
                {
                  title: "终端",
                  key: "host",
                  width: 160,
                  render: (_, d) => (
                    <Space orientation="vertical" size={0}>
                      <Typography.Text strong>{d.hostName}</Typography.Text>
                      {d.note && <Typography.Text type="secondary">{d.note}</Typography.Text>}
                    </Space>
                  ),
                },
                {
                  title: "状态",
                  key: "state",
                  width: 96,
                  render: (_, d) => {
                    const s = upgradeStates[d.state] ?? { label: d.state, color: "default" };
                    return <Tag color={s.color}>{s.label}</Tag>;
                  },
                },
                { title: "说明", dataIndex: "detail" },
                { title: "发送", key: "sent", width: 160, render: (_, d) => time(d.sentAt) },
              ]}
            />
          </Space>
        )}
      </Fresh>
    </Modal>
  );
}
