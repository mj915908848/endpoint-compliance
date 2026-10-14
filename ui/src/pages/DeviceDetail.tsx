import { useState } from "react";
import { App, Button, Col, Descriptions, Dropdown, Row, Space, Tabs, Tag } from "antd";
import { ArrowLeftOutlined, DownloadOutlined } from "@ant-design/icons";
import { downloadJson, downloadReport, request } from "../api";
import { useResource, useRefresh } from "../useResource";
import {
  ControlList,
  CoverageGuide,
  CoverageTable,
  DeviceGuide,
  DeviceState,
  Empty,
  errorText,
  EvidenceTable,
  Fresh,
  Metric,
  onlineLabel,
  PageHeading,
  ReportView,
  time,
  UpdatedAt,
  verdictLabels,
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
  const { message } = App.useApp();
  const refresh = useRefresh();
  const encoded = encodeURIComponent(id),
    detail = useResource<DeviceDetail>(`/api/devices/${encoded}`),
    report = useResource<Report>(detail.data?.snapshot ? `/api/devices/${encoded}/report` : null);
  const [busy, setBusy] = useState(false);
  const d = detail.data?.device;
  const snapshot = detail.data?.snapshot;
  const online = d?.onlineState === "Online";
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
        description={d ? <span className="mono">设备 ID：{d.id}</span> : "正在读取终端信息"}
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
          </Space>
        }
      />
      <Fresh error={detail.error} loading={detail.loading}>
        {d && (
          <Space orientation="vertical" size={16} style={{ width: "100%" }}>
            <DeviceGuide device={d} />
            <Row gutter={[16, 16]}>
              <Col xs={12} lg={6}>
                <Metric
                  label="当前结论"
                  value={online ? verdictLabels[d.currentVerdict] : "无法判断"}
                  tone={
                    !online
                      ? "warning"
                      : d.currentVerdict === "PASS"
                        ? "good"
                        : d.currentVerdict === "FAIL"
                          ? "danger"
                          : "warning"
                  }
                  caption={online ? "终端在线" : `${onlineLabel(d.onlineState)}，上次结论仅供参考`}
                />
              </Col>
              <Col xs={12} lg={6}>
                <Metric
                  label="违规对象"
                  value={d.violationCount}
                  tone={d.violationCount ? "danger" : "neutral"}
                />
              </Col>
              <Col xs={12} lg={6}>
                <Metric
                  label="策略版本（目标 / 已应用）"
                  value={`v${d.targetPolicyVersion} / v${d.appliedPolicyVersion}`}
                  caption={d.protectionStatus}
                />
              </Col>
              <Col xs={12} lg={6}>
                <Metric
                  label="待执行的检查请求"
                  value={detail.data?.pendingCommands ?? 0}
                  caption={`最近心跳 ${time(d.lastHeartbeat)}`}
                />
              </Col>
            </Row>
            <div className="panel tabs-panel">
              <Tabs
                defaultActiveKey="report"
                items={[
                  {
                    key: "report",
                    label: "检查报告",
                    children: !snapshot ? (
                      <Empty title="暂无检查报告">终端完成首次检查后生成报告。</Empty>
                    ) : (
                      <Fresh error={report.error} loading={report.loading}>
                        {report.data && <ReportView report={report.data} />}
                      </Fresh>
                    ),
                  },
                  {
                    key: "evidence",
                    label: `全部证据（${snapshot?.evidence.length ?? 0}）`,
                    children: (
                      <EvidenceTable values={snapshot?.evidence ?? []} empty="终端未上报证据" />
                    ),
                  },
                  {
                    key: "coverage",
                    label: "检查覆盖",
                    children: snapshot ? (
                      <Space orientation="vertical" size={12} style={{ width: "100%" }}>
                        <CoverageGuide modules={snapshot.modules} />
                        <CoverageTable modules={snapshot.modules} />
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
                          column={{ xs: 1, md: 2 }}
                          items={[
                            { label: "当前状态", children: <DeviceState device={d} /> },
                            { label: "防护状态", children: d.protectionStatus || "未知" },
                            { label: "最近检查", children: time(d.lastScan) },
                            { label: "最近心跳", children: time(d.lastHeartbeat) },
                            {
                              label: "数据来源",
                              children: d.simulated ? (
                                <Tag color="purple">模拟终端，不能作为 Windows 实机验收依据</Tag>
                              ) : (
                                "终端实机"
                              ),
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
