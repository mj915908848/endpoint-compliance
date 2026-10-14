import { type ReactNode } from "react";
import {
  Anchor,
  Descriptions,
  Flex,
  List as AntList,
  Space,
  Table,
  Tag,
  Tooltip,
  Typography,
} from "antd";
import {
  CheckCircleFilled,
  CloseCircleFilled,
  ExclamationCircleFilled,
  WarningOutlined,
} from "@ant-design/icons";
import { Empty, time, VerdictTag } from "./common";
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

/** Section titles; keep in sync with ReportRenderer.Markdown in Compliance.Core. */
export const reportSections = [
  "基本信息",
  "检查结论",
  "不通过项",
  "软件安装与运行",
  "代理设置",
  "网络线索与防护措施",
  "检查覆盖",
  "处理建议",
  "适用范围与限制",
];

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

export function EvidenceTable({
  values,
  empty,
  users,
}: {
  values: Evidence[];
  empty?: string;
  users?: UserAccount[];
}) {
  return (
    <Table<Evidence>
      rowKey={(e, i) => `${e.objectKey}-${i}`}
      dataSource={values}
      size="small"
      pagination={values.length > 20 ? { pageSize: 20 } : false}
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

function Bullets({ items, empty }: { items: string[]; empty: string }) {
  return items.length ? (
    <ul className="report-list">
      {items.map((v, i) => (
        <li key={i}>{v}</li>
      ))}
    </ul>
  ) : (
    <Typography.Text type="secondary">{empty}</Typography.Text>
  );
}

const verdictIcon = {
  PASS: <CheckCircleFilled style={{ color: "var(--good)" }} />,
  FAIL: <CloseCircleFilled style={{ color: "var(--danger)" }} />,
  UNKNOWN: <ExclamationCircleFilled style={{ color: "var(--warning)" }} />,
};

/** The device report, section for section the same as the downloadable Markdown. */
export function ReportView({ report: r }: { report: Report }) {
  const s = r.snapshot;
  const installation = s.evidence.filter((e) =>
    ["Installation", "Process", "Extension"].includes(e.kind),
  );
  const proxy = s.evidence.filter((e) => e.kind === "Proxy");
  const clue = s.evidence.filter((e) => ["Clue", "BlockedAttempt"].includes(e.kind));
  const body: ReactNode[] = [
    <Descriptions
      size="small"
      bordered
      column={{ xs: 1, md: 2 }}
      items={[
        { label: "终端", children: s.hostName },
        { label: "设备 ID", children: <span className="mono">{s.deviceId}</span> },
        { label: "平台", children: s.platform },
        { label: "采集时间", children: time(s.collectedAt) },
        { label: "策略版本", children: `v${s.policyVersion}` },
        ...(s.users?.length
          ? [
              {
                label: "用户账户",
                span: "filled" as const,
                children: s.users.map((u) => `${u.name}（${u.sid}）`).join("；"),
              },
            ]
          : []),
        {
          label: "数据来源",
          children: s.simulated ? (
            <Tag color="purple">模拟数据，不能作为实机验收依据</Tag>
          ) : (
            "终端实机采集"
          ),
        },
      ]}
    />,
    <Space orientation="vertical" size={8}>
      <Space>
        <VerdictTag verdict={r.verdict} />
        <Typography.Text strong>{r.summary}</Typography.Text>
      </Space>
      <Descriptions
        size="small"
        column={{ xs: 1, md: 3 }}
        items={[
          { label: "违规对象", children: r.violationCount },
          { label: "确认证据", children: r.evidenceCount },
          { label: "防护状态", children: r.protectionStatus },
        ]}
      />
      <Typography.Text type="secondary">
        同一产品在同一用户下的安装、进程和扩展记录合并计为一个违规对象。
      </Typography.Text>
    </Space>,
    r.reasons.length ? (
      <AntList
        size="small"
        dataSource={r.reasons}
        renderItem={(reason) => (
          <AntList.Item>
            <Space align="start">
              <CloseCircleFilled style={{ color: "var(--danger)" }} />
              {reason}
            </Space>
          </AntList.Item>
        )}
      />
    ) : (
      <Typography.Text type="secondary">
        未发现确认违规。结论的完整性以“检查覆盖”一节为准。
      </Typography.Text>
    ),
    <EvidenceTable values={installation} empty="未发现相关软件的安装或运行记录" users={s.users} />,
    <EvidenceTable values={proxy} empty="未发现代理设置" users={s.users} />,
    <Space orientation="vertical" size={12} style={{ width: "100%" }}>
      <EvidenceTable values={clue} empty="没有网络线索或拦截记录" users={s.users} />
      <ControlList controls={s.controls} />
    </Space>,
    <Space orientation="vertical" size={12} style={{ width: "100%" }}>
      {r.coverageGaps.length > 0 && (
        <AntList
          size="small"
          header={<Typography.Text strong>检查缺口</Typography.Text>}
          dataSource={r.coverageGaps}
          renderItem={(gap) => (
            <AntList.Item>
              <Space align="start">
                <WarningOutlined style={{ color: "var(--warning)" }} />
                {gap}
              </Space>
            </AntList.Item>
          )}
        />
      )}
      <CoverageTable modules={s.modules} users={s.users} />
    </Space>,
    <Bullets items={reportAdvice} empty="" />,
    <Bullets items={reportLimits} empty="" />,
  ];
  return (
    <div className="report">
      <Flex className="report-summary" gap={16} align="center">
        <span className="report-verdict-icon">{verdictIcon[r.verdict]}</span>
        <div>
          <Typography.Title level={4} style={{ margin: 0 }}>
            {r.summary}
          </Typography.Title>
          <Typography.Text type="secondary">
            {s.hostName} · 采集于 {time(s.collectedAt)} · 策略 v{s.policyVersion}
          </Typography.Text>
        </div>
      </Flex>
      <Anchor
        className="report-toc"
        direction="horizontal"
        replace
        targetOffset={80}
        items={reportSections.map((name, i) => ({
          key: String(i),
          href: `#report-${i + 1}`,
          title: `${i + 1}. ${name}`,
        }))}
      />
      {reportSections.map((name, i) => (
        <section key={name} id={`report-${i + 1}`} className="report-section">
          <Typography.Title level={5}>
            <span className="report-index">{i + 1}</span>
            {name}
          </Typography.Title>
          {body[i]}
        </section>
      ))}
    </div>
  );
}
