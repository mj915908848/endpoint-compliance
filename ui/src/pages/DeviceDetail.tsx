import { type ReactNode, useState } from "react";
import { App, Button, Descriptions, Dropdown, Input, Space, Tabs, Tag, Typography } from "antd";
import {
  ArrowLeftOutlined,
  DeleteOutlined,
  DownloadOutlined,
  EditOutlined,
  InboxOutlined,
} from "@ant-design/icons";
import { downloadJson, downloadReport, request } from "../api";
import { useResource, useRefresh } from "../useResource";
import {
  ControlList,
  CoverageGuide,
  CoverageTable,
  InventoryView,
  AgentVersion,
  ago,
  DeviceGuide,
  deviceName,
  Empty,
  errorText,
  Fresh,
  NetworkList,
  OnlineState,
  PageHeading,
  ReportFindings,
  time,
  UpdatedAt,
  VerdictHistory,
} from "../components";
import { role } from "../session";
import type {
  ClientHealth,
  DeviceDetail,
  DeviceInventory,
  Report,
  Session,
  VerdictChange,
} from "../types";

export function DeviceDetailPage({
  id,
  session,
  back,
}: {
  id: string;
  session: Session;
  back: () => void;
}) {
  const { message, modal } = App.useApp();
  const refresh = useRefresh();
  const encoded = encodeURIComponent(id),
    detail = useResource<DeviceDetail>(`/api/devices/${encoded}`),
    report = useResource<Report>(detail.data?.snapshot ? `/api/devices/${encoded}/report` : null),
    history = useResource<VerdictChange[]>(`/api/devices/${encoded}/history`);
  const [tab, setTab] = useState("report");
  // Read when its tab is first opened: a device can list thousands of programs.
  const inventory = useResource<DeviceInventory>(
    tab === "assets" ? `/api/devices/${encoded}/inventory` : null,
  );
  const [busy, setBusy] = useState(false);
  const d = detail.data?.device;
  // The name and note stay while a refresh fails, so a note being typed is not thrown away.
  const known = d ?? detail.lastData?.device;
  const snapshot = detail.data?.snapshot;
  const pending = detail.data?.pendingCommands ?? 0;
  const complete = snapshot?.modules.filter((m) => m.status === "Complete").length ?? 0;
  const fileName = `终端报告-${id.replace(/[^a-zA-Z0-9_-]/g, "_")}`;

  async function scan() {
    setBusy(true);
    try {
      await request(`/api/devices/${encoded}/commands`, {
        method: "POST",
        body: { type: "ScanNow" },
        csrfToken: session.csrfToken,
      });
      message.success("已发送检查请求，终端下次联系管理端时执行。");
      refresh();
    } catch (e) {
      message.error(errorText(e));
    } finally {
      setBusy(false);
    }
  }
  function upgrade() {
    modal.confirm({
      title: "升级这台终端的客户端？",
      content:
        "终端下次联系管理端时下载最新上传的客户端安装包并安装，期间托盘会关闭，员工下次登录时恢复。一天内未联系管理端则取消。",
      okText: "发送升级",
      cancelText: "取消",
      onOk: async () => {
        try {
          await request(`/api/devices/${encoded}/commands`, {
            method: "POST",
            body: { type: "Upgrade" },
            csrfToken: session.csrfToken,
          });
          message.success("已发送升级请求");
          refresh();
        } catch (e) {
          message.error(errorText(e));
        }
      },
    });
  }
  async function saveNote(note: string) {
    await request(`/api/devices/${encoded}/note`, {
      method: "PUT",
      body: { note },
      csrfToken: session.csrfToken,
    });
    message.success(note ? "备注已保存" : "备注已清除");
    refresh();
  }
  function remove() {
    if (!d) return;
    modal.confirm({
      title: `删除终端 ${deviceName(d)}？`,
      content:
        "将删除该终端的检查记录、告警和待执行请求，此操作不可撤销。该电脑上的客户端将无法再上报，如需继续管控，请生成新的注册码重新注册。",
      okText: "删除",
      okButtonProps: { danger: true },
      cancelText: "取消",
      onOk: async () => {
        try {
          await request(`/api/devices/${encoded}`, {
            method: "DELETE",
            csrfToken: session.csrfToken,
          });
          message.success(`已删除终端 ${d.hostName}`);
          back();
          refresh();
        } catch (e) {
          message.error(errorText(e));
        }
      },
    });
  }
  function archive(restore: boolean) {
    if (!d) return;
    modal.confirm({
      title: restore ? `取消归档 ${deviceName(d)}？` : `归档 ${deviceName(d)}？`,
      content: restore
        ? "终端回到终端列表；长期未上线的仍会按系统设置再次自动归档。"
        : "归档的终端不再出现在终端列表、总览统计、客户端升级和签名密钥更换中，它的告警自动恢复。终端重新上线时自动取消归档。适合已换下或报废的电脑。",
      okText: restore ? "取消归档" : "归档",
      cancelText: "取消",
      onOk: async () => {
        try {
          await request(`/api/devices/${restore ? "restore" : "archive"}`, {
            method: "POST",
            body: { ids: [id] },
            csrfToken: session.csrfToken,
          });
          message.success(restore ? "已取消归档" : `已归档终端 ${d.hostName}`);
          refresh();
        } catch (e) {
          message.error(errorText(e));
        }
      },
    });
  }
  async function download(kind: string) {
    try {
      if (kind === "md") await downloadReport(id);
      else if (report.data) downloadJson(report.data, `${fileName}.json`);
    } catch (e) {
      message.error(errorText(e));
    }
  }

  return (
    <>
      <Button type="link" icon={<ArrowLeftOutlined />} onClick={back} style={{ paddingLeft: 0 }}>
        返回终端列表
      </Button>
      <PageHeading
        title={known?.hostName ?? "终端详情"}
        description={
          known ? (
            <Space orientation="vertical" size={2}>
              <DeviceNote
                note={known.note ?? ""}
                canEdit={role(session, "Operator")}
                onSave={saveNote}
              />
              <span className="mono">设备 ID：{known.id}</span>
            </Space>
          ) : (
            "正在读取终端信息"
          )
        }
        extra={<UpdatedAt at={detail.updatedAt} refreshing={detail.refreshing} />}
        action={
          <Space wrap>
            {role(session, "Operator") && (
              <Button loading={busy} disabled={!d} onClick={scan}>
                请求重新检查
              </Button>
            )}
            {role(session, "Operator") && d?.agentOutdated && (
              <Button onClick={upgrade}>升级客户端</Button>
            )}
            <Dropdown
              disabled={!report.data}
              menu={{
                items: [
                  { key: "md", label: "Markdown 报告" },
                  { key: "json", label: "JSON 数据" },
                ],
                onClick: ({ key }) => void download(key),
              }}
            >
              <Button icon={<DownloadOutlined />}>下载报告</Button>
            </Dropdown>
            <Button onClick={refresh}>刷新</Button>
            {role(session, "Operator") && (
              <Button
                icon={<InboxOutlined />}
                disabled={!d}
                onClick={() => archive(!!d?.archivedAt)}
              >
                {d?.archivedAt ? "取消归档" : "归档"}
              </Button>
            )}
            {role(session, "Operator") && (
              <Button danger icon={<DeleteOutlined />} disabled={!d} onClick={remove}>
                删除终端
              </Button>
            )}
          </Space>
        }
      />
      <Fresh error={detail.error} loading={detail.loading}>
        {d && (
          <Space orientation="vertical" size={16} style={{ width: "100%" }}>
            <DeviceGuide device={d}>
              <Fact label="在线状态">
                <OnlineState device={d} />
                {d.archivedAt && (
                  <Tag style={{ marginLeft: 8 }} title={time(d.archivedAt)}>
                    已归档
                  </Tag>
                )}
              </Fact>
              <Fact label="IP / MAC">
                {d.network?.length ? (
                  <NetworkList adapters={d.network} />
                ) : d.network ? (
                  "未发现已连接的物理网卡"
                ) : (
                  "客户端 0.2.22 起上报"
                )}
              </Fact>
              {d.sourceAddress && (
                <Fact label="上报来源 IP">
                  <span className="mono">{d.sourceAddress}</span>
                </Fact>
              )}
              <Fact label="最近检查">{time(d.lastScan)}</Fact>
              <Fact label="最近心跳">{time(d.lastHeartbeat)}</Fact>
              <Fact label="客户端版本">
                <AgentVersion device={d} />
              </Fact>
              <Fact label="客户端运行" wide={!!detail.data?.healthProblems?.length}>
                <ClientHealthFact
                  health={detail.data?.health ?? null}
                  problems={detail.data?.healthProblems ?? []}
                />
              </Fact>
              <Fact label="策略" wide>
                {d.policyName && `${d.policyName} `}v{d.targetPolicyVersion}
                {!d.policyApplied && "（终端尚未应用，下次联系管理端时更新）"}
                {d.protectionStatus && ` · ${d.protectionStatus}`}
              </Fact>
              {pending > 0 && <Fact label="待执行的检查请求">{pending}</Fact>}
              {d.simulated && (
                <Fact label="数据来源">
                  <Tag color="purple">模拟终端，不能作为实机验收依据</Tag>
                </Fact>
              )}
            </DeviceGuide>
            <div className="panel tabs-panel">
              <Tabs
                activeKey={tab}
                onChange={setTab}
                items={[
                  {
                    key: "report",
                    label: "检查结果",
                    children: !snapshot ? (
                      <Empty title="暂无检查结果">终端完成首次检查后显示。</Empty>
                    ) : (
                      <Fresh error={report.error} loading={report.loading}>
                        {report.data && <ReportFindings report={report.data} />}
                      </Fresh>
                    ),
                  },
                  {
                    key: "coverage",
                    label: snapshot
                      ? `检查覆盖（${complete}/${snapshot.modules.length}）`
                      : "检查覆盖",
                    children: snapshot ? (
                      <Space orientation="vertical" size={12} style={{ width: "100%" }}>
                        <CoverageGuide modules={snapshot.modules} />
                        <CoverageTable modules={snapshot.modules} users={snapshot.users} />
                      </Space>
                    ) : (
                      <Empty title="暂无检查数据" />
                    ),
                  },
                  {
                    key: "history",
                    label: "结论变化",
                    children: (
                      <Fresh error={history.error} loading={history.loading}>
                        {history.data && <VerdictHistory changes={history.data} />}
                      </Fresh>
                    ),
                  },
                  {
                    key: "assets",
                    label: "资产",
                    children: (
                      <Fresh error={inventory.error} loading={inventory.loading}>
                        {inventory.data && <InventoryView data={inventory.data} />}
                      </Fresh>
                    ),
                  },
                  {
                    key: "device",
                    label: "设备与防护",
                    children: (
                      <Space orientation="vertical" size={16} style={{ width: "100%" }}>
                        <Descriptions
                          size="small"
                          bordered
                          column={1}
                          items={[
                            { label: "平台", children: snapshot?.platform ?? "未知" },
                            {
                              label: "用户账户",
                              children: snapshot?.users?.length
                                ? snapshot.users.map((u) => (
                                    <div key={u.sid}>
                                      {u.name} <span className="mono muted">{u.sid}</span>
                                    </div>
                                  ))
                                : "未上报",
                            },
                            {
                              label: "数据来源",
                              children: d.simulated ? "模拟终端" : "终端实机采集",
                            },
                          ]}
                        />
                        <ControlList controls={detail.data?.controls ?? []} />
                      </Space>
                    ),
                  },
                ]}
              />
            </div>
          </Space>
        )}
      </Fresh>
    </>
  );
}

/** What the client said about itself with its last heartbeat. */
function ClientHealthFact({
  health,
  problems,
}: {
  health: ClientHealth | null;
  problems: string[];
}) {
  if (!health) return <Typography.Text type="secondary">客户端升级后上报</Typography.Text>;
  const facts = [
    health.queued > 0
      ? `待上报 ${health.queued} 条${health.oldestQueued ? `，最早一条在 ${ago(health.oldestQueued)}前` : ""}`
      : "无待上报记录",
    health.lastUpload ? `最近上报 ${ago(health.lastUpload)}前` : null,
    health.refused > 0 ? `近一天被拒收 ${health.refused} 条` : null,
    health.dropped > 0 ? `已丢弃 ${health.dropped} 份较早的检查结果` : null,
    health.enforcementError && health.enforcementErrorAt
      ? `结束禁用程序出错（${ago(health.enforcementErrorAt)}前）：${health.enforcementError}`
      : null,
  ].filter(Boolean);
  return (
    <Space orientation="vertical" size={0}>
      {problems.length ? (
        <Typography.Text type="warning">{problems.join("；")}</Typography.Text>
      ) : (
        <Typography.Text type="success">正常</Typography.Text>
      )}
      <Typography.Text type="secondary" style={{ fontSize: 12 }}>
        {facts.join(" · ")}
      </Typography.Text>
    </Space>
  );
}

function Fact({ label, children, wide }: { label: string; children: ReactNode; wide?: boolean }) {
  return (
    <div className={wide ? "status-fact status-fact-wide" : "status-fact"}>
      <div className="status-fact-label">{label}</div>
      <div className="status-fact-value">{children}</div>
    </div>
  );
}

/** Who uses this PC; host names alone rarely say. */
function DeviceNote({
  note,
  canEdit,
  onSave,
}: {
  note: string;
  canEdit: boolean;
  onSave: (note: string) => Promise<void>;
}) {
  const [text, setText] = useState<string | null>(null),
    [busy, setBusy] = useState(false),
    [error, setError] = useState<string | null>(null);
  async function save() {
    setBusy(true);
    setError(null);
    try {
      await onSave((text ?? "").trim());
      setText(null);
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(false);
    }
  }
  if (text !== null)
    return (
      <Space orientation="vertical" size={2}>
        <Space.Compact>
          <Input
            aria-label="终端备注"
            autoFocus
            maxLength={100}
            placeholder="例如：张三 · 研发部 · 工位 A-12"
            value={text}
            onChange={(e) => setText(e.target.value)}
            onPressEnter={save}
            style={{ width: 320 }}
          />
          <Button type="primary" loading={busy} onClick={save}>
            保存
          </Button>
          <Button onClick={() => setText(null)}>取消</Button>
        </Space.Compact>
        {error && <Typography.Text type="danger">{error}</Typography.Text>}
      </Space>
    );
  return (
    <Space size={4}>
      {note ? <Typography.Text>备注：{note}</Typography.Text> : <span>未填写备注</span>}
      {canEdit && (
        <Button type="link" size="small" icon={<EditOutlined />} onClick={() => setText(note)}>
          {note ? "修改" : "添加备注"}
        </Button>
      )}
    </Space>
  );
}
