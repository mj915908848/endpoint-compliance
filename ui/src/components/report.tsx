import { type ReactNode, useRef } from "react";
import { Collapse, List as AntList, Space, Table, Tag, Tooltip, Typography } from "antd";
import { CheckCircleFilled, CloseCircleFilled, WarningOutlined } from "@ant-design/icons";
import { Empty, time } from "./common";
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

/**
 * Pages of 20 rows. Changing page brings the section heading back into view; otherwise the reader is left wherever
 * the old page's pager was, and a page of different height leaves them far from the new rows.
 */
function usePages(count: number) {
  const ref = useRef<HTMLDivElement>(null);
  const pagination =
    count > 20
      ? {
          pageSize: 20,
          showSizeChanger: false,
          onChange: () => {
            const target = ref.current?.closest("section") ?? ref.current;
            target?.scrollIntoView({ block: "start" });
          },
        }
      : (false as const);
  return { ref, pagination };
}

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
  return (
    <div ref={ref}>
      <Table<Evidence>
        rowKey={(e, i) => `${e.objectKey}-${i}`}
        dataSource={values}
        size="small"
        pagination={pagination}
        scroll={{ x: 640 }}
        locale={{ emptyText: <Empty title={empty ?? "没有相关证据"} /> }}
        columns={[
          {
            title: "产品",
            key: "product",
            render: (_, e) => (
              <Space orientation="vertical" size={0}>
                <Typography.Text strong>{e.productName || e.productId}</Typography.Text>
                <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                  {e.productId}
                </Typography.Text>
              </Space>
            ),
          },
          {
            title: "类型",
            key: "kind",
            width: 150,
            render: (_, e) => (
              <Tag color={e.confirmed ? "error" : "warning"}>
                {e.confirmed ? "确认" : "线索"} · {evidenceLabel(e.kind)}
              </Tag>
            ),
          },
          { title: "说明", dataIndex: "summary" },
          { title: "来源", dataIndex: "source", width: 160 },
          {
            title: "范围",
            key: "scope",
            width: 140,
            render: (_, e) => <Scope scope={e.userSid} users={users} />,
          },
        ]}
      />
    </div>
  );
}

/** Files and folders whose names contain a configured keyword; only names are compared. */
export function SensitiveFileTable({
  values,
  users,
  complete,
}: {
  values: Evidence[];
  users?: UserAccount[];
  complete: boolean;
}) {
  const { ref, pagination } = usePages(values.length);
  return (
    <div ref={ref}>
      <Table<Evidence>
        rowKey={(e, i) => `${e.source}-${e.objectKey}-${i}`}
        dataSource={values}
        size="small"
        pagination={pagination}
        scroll={{ x: 640 }}
        locale={{
          emptyText: (
            <Empty
              title={
                complete
                  ? "未发现文件名包含关键词的文件或文件夹"
                  : "暂无命中记录；扫描尚未完整完成，不能据此认定没有敏感文件"
              }
            />
          ),
        }}
        columns={[
          {
            title: "路径",
            key: "path",
            render: (_, e) => <span className="mono">{e.objectKey}</span>,
          },
          { title: "说明", dataIndex: "summary" },
          {
            title: "所有者",
            key: "owner",
            width: 140,
            render: (_, e) => (e.userSid ? <Scope scope={e.userSid} users={users} /> : "未知"),
          },
          {
            title: "扫描范围",
            key: "scope",
            width: 140,
            render: (_, e) => <Scope scope={e.source} users={users} />,
          },
        ]}
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
        { title: "策略版本", key: "version", width: 90, render: (_, c) => `v${c.version}` },
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

function Section({ title, children }: { title: ReactNode; children: ReactNode }) {
  return (
    <section className="report-section">
      <Typography.Title level={5}>{title}</Typography.Title>
      {children}
    </section>
  );
}

/** One evidence group; an empty group is a single line rather than an empty table. */
function EvidenceGroup({
  title,
  values,
  empty,
  users,
}: {
  title: string;
  values: Evidence[];
  empty: string;
  users?: UserAccount[];
}) {
  return (
    <Section title={`${title}（${values.length}）`}>
      {values.length ? (
        <EvidenceTable values={values} users={users} />
      ) : (
        <Typography.Text type="secondary">{empty}</Typography.Text>
      )}
    </Section>
  );
}

function Issues({ items, icon, note }: { items: string[]; icon: ReactNode; note?: string }) {
  return (
    <>
      <AntList
        size="small"
        dataSource={items}
        renderItem={(item) => (
          <AntList.Item>
            <Space align="start">
              {icon}
              {item}
            </Space>
          </AntList.Item>
        )}
      />
      {note && (
        <Typography.Text type="secondary" style={{ fontSize: 12 }}>
          {note}
        </Typography.Text>
      )}
    </>
  );
}

/**
 * What the latest scan found. The verdict, device facts and full coverage table live elsewhere on the
 * device page, so this only lists the problems and the evidence behind them; the downloadable
 * Markdown report keeps all nine sections.
 */
export function ReportFindings({ report: r }: { report: Report }) {
  const s = r.snapshot;
  const installation = s.evidence.filter((e) =>
    ["Installation", "Process", "Extension"].includes(e.kind),
  );
  const proxy = s.evidence.filter((e) => e.kind === "Proxy");
  const sensitive = s.evidence.filter((e) => e.kind === "SensitiveFile");
  const sensitiveScopes = s.modules.filter((m) => m.module === "sensitive-files");
  const sensitiveNotes = r.sensitiveFileNotes ?? [];
  const clue = s.evidence.filter((e) => ["Clue", "BlockedAttempt"].includes(e.kind));
  return (
    <div className="report">
      <Typography.Text type="secondary">
        本次检查采集于 {time(s.collectedAt)}，按策略 v{s.policyVersion} 判定
      </Typography.Text>
      {r.reasons.length > 0 && (
        <Section title={`不通过项（${r.reasons.length}）`}>
          <Issues
            items={r.reasons}
            icon={<CloseCircleFilled style={{ color: "var(--danger)" }} />}
            note="同一产品在同一用户下的安装、进程和扩展记录合并计为一个违规对象。"
          />
        </Section>
      )}
      {r.coverageGaps.length > 0 && (
        <Section title={`检查缺口（${r.coverageGaps.length}）`}>
          <Issues
            items={r.coverageGaps}
            icon={<WarningOutlined style={{ color: "var(--warning)" }} />}
            note="缺口不代表发现了新的违规，但会让结论无法判定为通过。逐项状态见“检查覆盖”。"
          />
        </Section>
      )}
      {r.reasons.length === 0 && r.coverageGaps.length === 0 && (
        <Section title="未发现问题">
          <Space align="start">
            <CheckCircleFilled style={{ color: "var(--good)" }} />
            所有必需检查项均已完成，未发现确认违规。
          </Space>
        </Section>
      )}
      <EvidenceGroup
        title="软件安装与运行"
        values={installation}
        empty="未发现相关软件的安装或运行记录。"
        users={s.users}
      />
      {(sensitive.length > 0 || sensitiveNotes.length > 0 || sensitiveScopes.length > 0) && (
        <Section title={`敏感文件（${sensitive.length}）`}>
          {sensitiveNotes.length > 0 && <Bullets items={sensitiveNotes} />}
          <SensitiveFileTable
            values={sensitive}
            users={s.users}
            complete={
              sensitiveScopes.length > 0 && sensitiveScopes.every((m) => m.status === "Complete")
            }
          />
        </Section>
      )}
      <EvidenceGroup title="代理设置" values={proxy} empty="未发现代理设置。" users={s.users} />
      <EvidenceGroup
        title="网络线索与拦截记录"
        values={clue}
        empty="没有网络线索或拦截记录。"
        users={s.users}
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
