import { type ReactNode } from "react";
import { Collapse, Grid, Space, Table, Tag, Tooltip, Typography } from "antd";
import { Empty, time, usePageScroll } from "./common";
import {
  controlLabel,
  controlStateLabel,
  evidenceLabel,
  moduleErrorLabel,
  moduleLabel,
  scopeLabel,
  statusLabel,
} from "./labels";
import type { Control, Evidence, ModuleResult, Report, UserAccount } from "../types";

export const reportAdvice = [
  "按本单位制度处理已确认的软件和代理配置，补齐检查缺口后重新检查。",
  "在管理端确认告警只表示已知悉，不代表问题已解决；问题是否解决以终端新的完整检查为准。",
  "启用强制策略前，先在审计模式下试运行，并验证拦截效果和回退方案。",
];

export const reportLimits = [
  "结论仅适用于报告所列终端、用户、检查项和采集时间；检查清单并非穷尽。",
  "端口、网络接口和名称相似的程序只作为线索，不能单独认定违规；拦截记录也不代表曾经成功使用。",
  "浏览器策略只覆盖浏览器访问，不能证明其他程序的网络访问已被阻断。",
  "在完成 Windows 实机、安装包签名和网关验收前，不能据此认定生产环境防护已经生效。",
  "检查不读取聊天内容、密码或浏览记录，也不会自动卸载软件。",
  "敏感文件扫描只比对文件和文件夹名称，不读取、不上传文件内容。",
];

/** Scope cell: account name, with the SID on hover for exact matching. */
function Scope({ scope, users }: { scope: string | null | undefined; users?: UserAccount[] }) {
  const label = scopeLabel(scope, users);
  return scope && scope !== "machine" && !label.endsWith(scope) ? (
    <Tooltip title={scope}>
      <span className="scope-name">{label}</span>
    </Tooltip>
  ) : (
    <span>{label}</span>
  );
}

/** Pages of 20 rows; changing page brings the section heading back into view. */
function usePages(count: number) {
  const { ref, onPageChange } = usePageScroll();
  const pagination =
    count > 20
      ? { pageSize: 20, showSizeChanger: false, onChange: onPageChange }
      : (false as const);
  return { ref, pagination };
}

/** A dot before a heading: red or amber when something needs attention, green when nothing was found. */
type Tone = "danger" | "warning" | "good" | "muted";
const Dot = ({ tone }: { tone: Tone }) => <span className={`report-dot report-dot-${tone}`} />;

function KindTag({ e }: { e: Evidence }) {
  if (e.kind === "Clue" || e.kind === "BlockedAttempt")
    return <Tag variant="filled">{evidenceLabel(e.kind)}</Tag>;
  return (
    <Tag variant="filled" color={e.confirmed ? "error" : "warning"}>
      {e.confirmed ? "" : "线索 · "}
      {evidenceLabel(e.kind)}
    </Tag>
  );
}

/**
 * Records in three columns: what and whose, what was seen and where, and the kind of record. Sensitive files show
 * the path instead, with the owner and scanned scope beneath. On a phone the three stack in one cell.
 */
export function EvidenceTable({
  values,
  empty,
  users,
}: {
  values: Evidence[];
  empty?: string;
  users?: UserAccount[];
}) {
  const { ref, pagination } = usePages(values.length);
  const narrow = !Grid.useBreakpoint().md;
  const owner = (e: Evidence) => (
    <>
      {e.kind === "SensitiveFile" ? "所有者 " : ""}
      {e.kind === "SensitiveFile" && !e.userSid ? (
        "未知"
      ) : (
        <Scope scope={e.userSid} users={users} />
      )}
    </>
  );
  const product = (e: Evidence) => (
    <Typography.Text strong>{e.productName || e.productId}</Typography.Text>
  );
  const finding = (e: Evidence) =>
    e.kind === "SensitiveFile" ? (
      <div>
        <span className="mono">{e.objectKey}</span>
        <div className="report-sub">
          {e.summary} · 扫描范围 <Scope scope={e.source} users={users} />
        </div>
      </div>
    ) : (
      <div>
        {e.summary}
        <div className="report-sub">{e.source}</div>
      </div>
    );
  return (
    <div ref={ref}>
      <Table<Evidence>
        rowKey={(e, i) => `${e.source}-${e.objectKey}-${i}`}
        dataSource={values}
        size="small"
        showHeader={false}
        pagination={pagination}
        locale={{ emptyText: <Empty title={empty ?? "没有相关证据"} /> }}
        columns={
          narrow
            ? [
                {
                  key: "record",
                  render: (_, e) => (
                    <div className="report-record">
                      <div className="report-record-head">
                        {product(e)}
                        <span className="report-sub">{owner(e)}</span>
                        <KindTag e={e} />
                      </div>
                      {finding(e)}
                    </div>
                  ),
                },
              ]
            : [
                {
                  key: "product",
                  width: 220,
                  render: (_, e) => (
                    <div>
                      {product(e)}
                      <div className="report-sub">{owner(e)}</div>
                    </div>
                  ),
                },
                { key: "summary", render: (_, e) => finding(e) },
                { key: "kind", width: 130, align: "right", render: (_, e) => <KindTag e={e} /> },
              ]
        }
      />
    </div>
  );
}

export function CoverageTable({
  modules,
  users,
}: {
  modules: ModuleResult[];
  users?: UserAccount[];
}) {
  return (
    <Table<ModuleResult>
      rowKey={(m, i) => `${m.module}-${m.scope}-${i}`}
      dataSource={modules}
      size="small"
      pagination={false}
      scroll={{ x: 640 }}
      locale={{ emptyText: <Empty title="没有检查项结果" /> }}
      columns={[
        { title: "检查项", key: "module", render: (_, m) => moduleLabel(m.module) },
        { title: "范围", key: "scope", render: (_, m) => <Scope scope={m.scope} users={users} /> },
        {
          title: "状态",
          key: "status",
          render: (_, m) => (
            <Tag
              color={
                m.status === "Complete" ? "success" : m.status === "Error" ? "error" : "warning"
              }
            >
              {statusLabel(m.status)}
            </Tag>
          ),
        },
        { title: "采集时间", key: "at", render: (_, m) => time(m.collectedAt) },
        {
          title: "说明",
          key: "error",
          render: (_, m) =>
            m.error ? <Typography.Text type="danger">{moduleErrorLabel(m)}</Typography.Text> : "—",
        },
      ]}
    />
  );
}

export function ControlList({ controls }: { controls: Control[] }) {
  return (
    <Table<Control>
      rowKey={(c, i) => `${c.id}-${i}`}
      dataSource={controls}
      size="small"
      pagination={false}
      scroll={{ x: 560 }}
      locale={{
        emptyText: (
          <Empty title="暂无防护措施记录">
            终端未上报经过验证的防护措施，因此不能认定拦截已经生效。
          </Empty>
        ),
      }}
      columns={[
        { title: "防护措施", key: "id", render: (_, c) => controlLabel(c.id) },
        {
          title: "状态",
          key: "state",
          render: (_, c) => (
            <Space size={4} wrap>
              <Tag color={c.verified ? "success" : "warning"}>
                {c.verified ? "已验证" : "未验证"}
              </Tag>
              <Tag>{controlStateLabel(c.state)}</Tag>
              {c.rebootRequired && <Tag color="warning">需重启</Tag>}
            </Space>
          ),
        },
        { title: "说明", dataIndex: "detail" },
      ]}
    />
  );
}

function Bullets({ items }: { items: string[] }) {
  return (
    <ul className="report-list">
      {items.map((v, i) => (
        <li key={i}>{v}</li>
      ))}
    </ul>
  );
}

function Metric({ tone, label, value }: { tone: Tone; label: string; value: number }) {
  return (
    <div className="report-metric">
      <span className="report-metric-label">
        <Dot tone={value ? tone : "good"} />
        {label}
      </span>
      <strong>{value}</strong>
    </div>
  );
}

/**
 * What the latest scan found. The verdict, device facts and full coverage table live elsewhere on the
 * device page, so this only lists the problems and the evidence behind them; the downloadable
 * Markdown report keeps all nine sections.
 */
export function ReportFindings({ report: r }: { report: Report }) {
  const s = r.snapshot,
    users = s.users;
  const installation = s.evidence.filter((e) =>
    ["Installation", "Process", "Extension"].includes(e.kind),
  );
  const proxy = s.evidence.filter((e) => e.kind === "Proxy");
  const sensitive = s.evidence.filter((e) => e.kind === "SensitiveFile");
  const sensitiveScopes = s.modules.filter((m) => m.module === "sensitive-files");
  const sensitiveNotes = r.sensitiveFileNotes ?? [];
  const sensitiveComplete =
    sensitiveScopes.length > 0 && sensitiveScopes.every((m) => m.status === "Complete");
  const clue = s.evidence.filter((e) => ["Clue", "BlockedAttempt"].includes(e.kind));
  const groups: {
    key: string;
    label: string;
    values: Evidence[];
    tone: Tone;
    none: string;
    notes?: string[];
  }[] = [
    {
      key: "software",
      label: "软件安装与运行",
      values: installation,
      tone: "danger",
      none: "未发现",
    },
    { key: "proxy", label: "代理设置", values: proxy, tone: "danger", none: "未发现" },
    ...(sensitive.length > 0 || sensitiveNotes.length > 0 || sensitiveScopes.length > 0
      ? [
          {
            key: "sensitive",
            label: "敏感文件",
            values: sensitive,
            tone: "danger" as Tone,
            none: sensitiveComplete ? "未发现" : "暂无命中，扫描尚未完整完成，不能据此认定没有",
            notes: sensitiveNotes,
          },
        ]
      : []),
    { key: "clue", label: "网络线索与拦截记录", values: clue, tone: "muted", none: "没有" },
  ];
  // Groups holding confirmed records start open; clues and empty groups stay closed.
  const open = groups
    .filter((g) => g.tone === "danger" && g.values.some((e) => e.confirmed))
    .map((g) => g.key);
  return (
    <div className="report">
      <div className="report-metrics">
        <Metric tone="danger" label="违规对象" value={r.reasons.length} />
        <Metric tone="warning" label="检查缺口" value={r.coverageGaps.length} />
        <Metric tone="danger" label="敏感文件" value={sensitive.length} />
        <Metric tone="muted" label="待核查线索" value={clue.length} />
      </div>
      <div className="report-meta">
        本次检查采集于 {time(s.collectedAt)}
        {r.policyName ? `，按策略“${r.policyName}”v${r.policyVersion} 判定` : ""}
        {r.reasons.length > 0 && "。同一产品在同一用户下的安装、进程和扩展记录合并计为一个违规对象"}
      </div>
      {r.coverageGaps.length > 0 && (
        <div className="report-gaps">
          <div className="report-gaps-title">
            <Dot tone="warning" />
            检查缺口（{r.coverageGaps.length}）
          </div>
          <Bullets items={r.coverageGaps} />
          <div className="report-sub">
            缺口不代表发现了新的违规，但会让结论无法判定为通过。逐项状态见“检查覆盖”。
          </div>
        </div>
      )}
      {r.reasons.length === 0 && r.coverageGaps.length === 0 && (
        <div className="report-clear">
          <Dot tone="good" />
          所有检查项均已完成，未发现确认违规。
        </div>
      )}
      <Collapse
        className="report-groups"
        defaultActiveKey={open}
        items={groups.map((g) => {
          const has = g.values.length > 0 || (g.notes?.length ?? 0) > 0;
          return {
            key: g.key,
            collapsible: has ? undefined : "disabled",
            showArrow: has,
            label: (
              <span className="report-group-label">
                <Dot tone={g.values.length ? g.tone : "good"} />
                {g.label}
                <span className="report-sub">
                  {g.values.length ? `${g.values.length} 条` : g.none}
                </span>
              </span>
            ),
            children: (
              <>
                {g.notes && g.notes.length > 0 && <Bullets items={g.notes} />}
                {g.values.length > 0 && <EvidenceTable values={g.values} users={users} />}
              </>
            ),
          };
        })}
      />
      <Collapse
        ghost
        size="small"
        items={[
          {
            key: "notes",
            label: "处理建议与适用范围",
            children: (
              <Space orientation="vertical" size={8}>
                <Bullets items={reportAdvice} />
                <Bullets items={reportLimits} />
              </Space>
            ),
          },
        ]}
      />
    </div>
  );
}
