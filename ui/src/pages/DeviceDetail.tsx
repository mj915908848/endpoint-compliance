import { useState } from "react";
import { downloadJson, downloadReport, request } from "../api";
import { useResource } from "../useResource";
import { DeviceGuide, DeviceState, Empty, ErrorNotice, time, verdictLabels, errorText, Panel, Fresh, Metric, PageHeading, ControlList, SnapshotView, ReportView } from "../components";
import { role } from "../session";
import type { DeviceDetail, Report, Session } from "../types";

export function DeviceDetailPage({
  id,
  session,
  back,
  revision,
  refresh,
}: {
  id: string;
  session: Session;
  back: () => void;
  revision: number;
  refresh: () => void;
}) {
  const encoded = encodeURIComponent(id),
    detail = useResource<DeviceDetail>(`/api/devices/${encoded}`, revision),
    report = useResource<Report>(
      detail.data?.snapshot ? `/api/devices/${encoded}/report` : null,
      revision,
    );
  const [actionError, setActionError] = useState<string | null>(null),
    [busy, setBusy] = useState(false);
  const d = detail.data?.device;
  async function scan() {
    setBusy(true);
    setActionError(null);
    try {
      await request(`/api/devices/${encoded}/commands`, {
        method: "POST",
        body: { type: "ScanNow" },
        csrfToken: session.csrfToken,
      });
      refresh();
    } catch (e) {
      setActionError(errorText(e));
    } finally {
      setBusy(false);
    }
  }
  async function markdown() {
    setActionError(null);
    try {
      await downloadReport(id);
    } catch (e) {
      setActionError(errorText(e));
    }
  }
  return (
    <>
      <div className="backline">
        <button className="link-button" onClick={back}>
          ← 返回终端列表
        </button>
      </div>
      <PageHeading
        kicker="DEVICE / DETAIL"
        title={d?.hostName ?? "终端详情"}
        description={d ? `设备 ID：${d.id}` : "正在读取设备事实"}
        action={
          <div className="inline">
            {role(session, "Operator") && (
              <button
                className="secondary"
                disabled={busy || !d}
                onClick={scan}
              >
                {busy ? "正在提交…" : "请求重新检查"}
              </button>
            )}
            <button className="secondary" onClick={refresh}>
              刷新状态
            </button>
          </div>
        }
      />
      <ErrorNotice error={actionError} />
      <Fresh error={detail.error} loading={detail.loading}>
        {d && (
          <>
            <DeviceGuide device={d} />
            <div className="metric-grid">
              <Metric
                label="当前检查结论"
                value={
                  d.onlineState === "Online"
                    ? verdictLabels[d.currentVerdict]
                    : "无法判断"
                }
                tone={
                  d.onlineState === "Online" && d.currentVerdict === "PASS"
                    ? "good"
                    : d.onlineState === "Online" && d.currentVerdict === "FAIL"
                      ? "danger"
                      : "warning"
                }
                caption={
                  d.onlineState === "Online"
                    ? "设备在线"
                    : `设备${d.onlineState === "Offline" ? "失联" : "疑似失联"}；上次结论仅供参考`
                }
              />
              <Metric
                label="确认违规对象"
                value={d.violationCount}
                tone={d.violationCount ? "danger" : "neutral"}
              />
              <Metric
                label="目标 / 已应用策略"
                value={`v${d.targetPolicyVersion} / v${d.appliedPolicyVersion}`}
                caption={d.protectionStatus}
              />
              <Metric
                label="待处理命令"
                value={detail.data?.pendingCommands ?? 0}
                caption={`最近心跳 ${time(d.lastHeartbeat)}`}
              />
            </div>
            {d.simulated && (
              <div className="callout warning">
                <strong>模拟终端</strong>
                此设备的采集与执行证据来自模拟环境，不能作为 Windows
                实机防护验收。
              </div>
            )}
            <div className="detail-grid">
              <Panel eyebrow="CURRENT STATE" title="设备与策略">
                <dl className="facts">
                  <dt>当前结论</dt>
                  <dd>
                    <DeviceState device={d} />
                  </dd>
                  <dt>最近采集</dt>
                  <dd>{time(d.lastScan)}</dd>
                  <dt>最近心跳</dt>
                  <dd>{time(d.lastHeartbeat)}</dd>
                  <dt>执行状态</dt>
                  <dd>{d.protectionStatus || "未知"}</dd>
                </dl>
              </Panel>
              <Panel eyebrow="CONTROL VERIFICATION" title="执行层证据">
                <ControlList controls={detail.data?.controls ?? []} />
              </Panel>
            </div>
            <Panel eyebrow="SCAN COVERAGE" title="检查范围与证据">
              {detail.data?.snapshot ? (
                <SnapshotView snapshot={detail.data.snapshot} />
              ) : (
                <Empty title="尚无检查快照">
                  终端需要完成首次扫描后才会产生检查结论与固定报告。
                </Empty>
              )}
            </Panel>
            <Panel
              eyebrow="REPORT"
              title="固定九节报告"
              actions={
                <div className="inline">
                  <button
                    className="secondary compact"
                    disabled={!report.data}
                    onClick={() =>
                      report.data &&
                      downloadJson(
                        report.data,
                        `终端报告-${id.replace(/[^a-zA-Z0-9_-]/g, "_")}.json`,
                      )
                    }
                  >
                    下载 JSON
                  </button>
                  <button
                    className="secondary compact"
                    disabled={!report.data}
                    onClick={markdown}
                  >
                    下载 Markdown
                  </button>
                </div>
              }
            >
              <Fresh error={report.error} loading={report.loading}>
                {report.data ? (
                  <ReportView report={report.data} />
                ) : (
                  <Empty title="尚无报告" />
                )}
              </Fresh>
            </Panel>
          </>
        )}
      </Fresh>
    </>
  );
}
