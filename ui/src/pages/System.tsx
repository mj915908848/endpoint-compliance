import { useResource } from "../useResource";
import { Badge, Empty, Panel, Fresh, PageHeading } from "../components";
import type { Status } from "../types";

export function SystemPage({ revision }: { revision: number }) {
  const status = useResource<Status>("/api/status", revision);
  const caps = Array.isArray(status.data?.networkCapabilities)
    ? status.data.networkCapabilities
    : [];
  return (
    <>
      <PageHeading
        kicker="SYSTEM / CAPABILITIES"
        title="系统状态"
        description="查看部署模式、存储与服务端声明的网络能力；真实执行覆盖仍需终端证据。"
      />
      <Panel title="运行环境">
        <Fresh error={status.error} loading={status.loading}>
          {status.data && (
            <dl className="facts">
              <dt>运行模式</dt>
              <dd>
                <Badge
                  tone={status.data.mode === "Production" ? "good" : "warning"}
                >
                  {status.data.mode}
                </Badge>
              </dd>
              <dt>存储</dt>
              <dd>{status.data.storage}</dd>
              <dt>策略密钥 ID</dt>
              <dd className="mono">{status.data.policyKeyId}</dd>
            </dl>
          )}
        </Fresh>
      </Panel>
      <Panel title="网络执行能力">
        <Fresh error={status.error} loading={status.loading}>
          {caps.length ? (
            <div className="stack">
              {caps.map((c, i) =>
                typeof c === "string" ? (
                  <div className="control-row" key={i}>
                    {c}
                  </div>
                ) : (
                  <div className="control-row" key={i}>
                    <div>
                      <strong>{c.id}</strong>
                      <small>{c.detail}</small>
                    </div>
                    <div className="inline">
                      <Badge tone={c.implemented ? "good" : "warning"}>
                        {c.implemented ? "已实现" : "未实现"}
                      </Badge>
                      <Badge tone={c.verified ? "good" : "warning"}>
                        {c.verified ? "已验证" : "未验证"}
                      </Badge>
                    </div>
                  </div>
                ),
              )}
            </div>
          ) : (
            <Empty title="未声明网络执行能力" />
          )}
        </Fresh>
      </Panel>
    </>
  );
}
