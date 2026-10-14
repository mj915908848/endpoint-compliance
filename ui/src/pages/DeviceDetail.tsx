import { type ReactNode, useState } from "react";
import { App, Button, Descriptions, Dropdown, Input, Space, Tabs, Tag, Typography } from "antd";
import {
  ArrowLeftOutlined,
  DeleteOutlined,
  DownloadOutlined,
  EditOutlined,
} from "@ant-design/icons";
import { downloadJson, downloadReport, request } from "../api";
import { useResource, useRefresh } from "../useResource";
import {
  ControlList,
  CoverageGuide,
  CoverageTable,
  DeviceGuide,
  deviceName,
  Empty,
  errorText,
  Fresh,
  onlineLabel,
  PageHeading,
  ReportFindings,
  time,
  UpdatedAt,
} from "../components";
import { role } from "../session";
import type { DeviceDetail, Report, Session } from "../types";

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
    report = useResource<Report>(detail.data?.snapshot ? `/api/devices/${encoded}/report` : null);
  const [busy, setBusy] = useState(false);
  const d = detail.data?.device;
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
        title={d?.hostName ?? "终端详情"}
        description={
          d ? (
            <Space orientation="vertical" size={2}>
              <DeviceNote
                key={d.note}
                note={d.note ?? ""}
                canEdit={role(session, "Operator")}
                onSave={saveNote}
              />
              <span className="mono">设备 ID：{d.id}</span>
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
              <div className="device-facts">
                <Fact label="在线状态">{onlineLabel(d.onlineState) ?? "未知"}</Fact>
                <Fact label="最近检查">{time(d.lastScan)}</Fact>
                <Fact label="最近心跳">{time(d.lastHeartbeat)}</Fact>
                <Fact label="策略">
                  v{d.targetPolicyVersion}
                  {d.appliedPolicyVersion !== d.targetPolicyVersion &&
                    `（终端已应用 v${d.appliedPolicyVersion}）`}
                  {d.protectionStatus && ` · ${d.protectionStatus}`}
                </Fact>
                {pending > 0 && <Fact label="待执行的检查请求">{pending}</Fact>}
                {d.simulated && <Tag color="purple">模拟终端，不能作为实机验收依据</Tag>}
              </div>
            </DeviceGuide>
            <div className="panel tabs-panel">
              <Tabs
                defaultActiveKey="report"
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

function Fact({ label, children }: { label: string; children: ReactNode }) {
  return (
    <span className="device-fact">
      <span className="muted">{label}</span>
      {children}
    </span>
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
