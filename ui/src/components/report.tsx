import { type ReactNode } from "react";
import { Badge, CoverageGuide, Empty, time, VerdictBadge } from "./common";
import { reportNames, moduleLabel, statusLabel, evidenceLabel, moduleErrorLabel } from "./labels";
import type { Control, Report, Snapshot } from "../types";

export function ControlList({ controls }: { controls: Control[] }) {
  return controls.length === 0 ? (
    <Empty title="暂无执行层证据">
      未上报已验证控制路径，不能推断阻断生效。
    </Empty>
  ) : (
    <div className="stack">
      {controls.map((c, i) => (
        <div className="control-row" key={`${c.id}-${i}`}>
          <div>
            <strong>{c.id}</strong>
            <small>
              版本 v{c.version} · {c.detail}
            </small>
          </div>
          <div className="inline">
            <Badge tone={c.verified ? "good" : "warning"}>
              {c.verified ? "已验证" : "未验证"}
            </Badge>
            <Badge>{c.state}</Badge>
            {c.rebootRequired && <Badge tone="warning">待重启</Badge>}
          </div>
        </div>
      ))}
    </div>
  );
}

export function SnapshotView({ snapshot: s }: { snapshot: Snapshot }) {
  return (
    <div className="snapshot">
      <div className="inline">
        <Badge tone={s.simulated ? "warning" : "neutral"}>
          {s.simulated ? "模拟快照" : "终端上报快照"}
        </Badge>
        <span className="muted">
          采集于 {time(s.collectedAt)} · 策略 v{s.policyVersion} · {s.platform}
        </span>
      </div>
      <h3>模块覆盖</h3>
      <CoverageGuide modules={s.modules} />
      {s.modules.length === 0 ? (
        <Empty title="没有模块结果" />
      ) : (
        <details className="module-details">
          <summary>展开原始采集记录（含账户范围和技术错误）</summary>
          <div className="chips">
            {s.modules.map((m, i) => (
              <div className="module-chip" key={i}>
                <strong>{moduleLabel(m.module)}</strong>
                <small>
                  {m.scope === "machine" ? "本机" : `用户 ${m.scope}`} · {statusLabel(m.status)} · {time(m.collectedAt)}
                </small>
                {m.error && <span className="danger-text">{moduleErrorLabel(m)}</span>}
              </div>
            ))}
          </div>
        </details>
      )}
      <h3>证据清单</h3>
      {s.evidence.length === 0 ? (
        <Empty title="没有上报证据" />
      ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>对象</th>
                <th>类型</th>
                <th>摘要</th>
                <th>来源 / 用户</th>
              </tr>
            </thead>
            <tbody>
              {s.evidence.map((e, i) => (
                <tr key={i}>
                  <td>
                    <strong>{e.productName || e.productId}</strong>
                    <small>{e.productId}</small>
                  </td>
                  <td>
                    <Badge tone={e.confirmed ? "danger" : "warning"}>
                      {e.confirmed ? "确认" : "线索"} · {evidenceLabel(e.kind)}
                    </Badge>
                  </td>
                  <td>{e.summary}</td>
                  <td>
                    {e.source}
                    <small>{e.userSid || "设备范围"}</small>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

export function ReportView({ report: r }: { report: Report }) {
  const s = r.snapshot;
  const installation = s.evidence.filter((e) =>
    ["Installation", "Process", "Extension"].includes(e.kind),
  );
  const proxy = s.evidence.filter((e) => e.kind === "Proxy");
  const clue = s.evidence.filter((e) =>
    ["Clue", "BlockedAttempt"].includes(e.kind),
  );
  const sections: ReactNode[] = [
    <dl className="facts">
      <dt>终端</dt>
      <dd>
        {s.hostName} · {s.deviceId}
      </dd>
      <dt>平台</dt>
      <dd>{s.platform}</dd>
      <dt>采集时间</dt>
      <dd>{time(s.collectedAt)}</dd>
      <dt>策略</dt>
      <dd>v{s.policyVersion}</dd>
    </dl>,
    <>
      <div className="inline">
        <VerdictBadge verdict={r.verdict} />
        <strong>{r.summary}</strong>
      </div>
      <p>
        违规对象 {r.violationCount} · 证据 {r.evidenceCount} · 防护{" "}
        {r.protectionStatus}
      </p>
      <p className="muted">同一产品的安装、进程和扩展可能产生多条证据；上面的“违规对象”已按产品与用户合并。</p>
    </>,
    <List values={r.reasons} empty="无已报告的不通过原因" />,
    <EvidenceList values={installation} />,
    <EvidenceList values={proxy} />,
    <>
      <EvidenceList values={clue} />
      <ControlList controls={s.controls} />
    </>,
    <>
      <List values={r.coverageGaps} empty="报告没有列出覆盖缺口" />
      <p className="muted">模块结果与时间见上方检查范围。</p>
    </>,
    <p>
      请按客户制度核对确认违规对象、采集缺口与执行层证据。管理员确认告警不会改变技术状态；完成处置后请求终端重新检查。
    </p>,
    <p>
      报告基于当前结构化快照。模拟采集、离线历史、未验证执行层和未覆盖网络路径均不能证明真实防护已生效。
    </p>,
  ];
  return (
    <div className="report-sections">
      {reportNames.map((name, i) => (
        <section key={name}>
          <div className="report-index">{String(i + 1).padStart(2, "0")}</div>
          <div>
            <h3>{name}</h3>
            {sections[i]}
          </div>
        </section>
      ))}
    </div>
  );
}

export function List({ values, empty }: { values: string[]; empty: string }) {
  return values.length ? (
    <ul className="plain-list">
      {values.map((v, i) => (
        <li key={i}>{v}</li>
      ))}
    </ul>
  ) : (
    <p className="muted">{empty}</p>
  );
}

export function EvidenceList({ values }: { values: Snapshot["evidence"] }) {
  return values.length ? (
    <ul className="plain-list">
      {values.map((e, i) => (
        <li key={i}>
          <strong>{e.productName}</strong> · {e.summary}{" "}
          <span className="muted">（{e.source}）</span>
        </li>
      ))}
    </ul>
  ) : (
    <p className="muted">本节没有对应证据。</p>
  );
}
