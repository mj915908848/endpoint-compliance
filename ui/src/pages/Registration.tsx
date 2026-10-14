import { useState } from "react";
import { request } from "../api";
import { ErrorNotice, time, errorText, Panel, PageHeading } from "../components";
import { role } from "../session";
import type { Session } from "../types";

export function Registration({ session }: { session: Session }) {
  const [minutes, setMinutes] = useState(15),
    [result, setResult] = useState<{ code: string; expiresAt: string } | null>(
      null,
    ),
    [error, setError] = useState<string | null>(null),
    [busy, setBusy] = useState(false);
  async function create() {
    setResult(null);
    setError(null);
    setBusy(true);
    try {
      setResult(
        await request("/api/enrollment-codes", {
          method: "POST",
          body: { expiresMinutes: minutes },
          csrfToken: session.csrfToken,
        }),
      );
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(false);
    }
  }
  return (
    <>
      <PageHeading
        kicker="ONBOARDING / ENROLLMENT"
        title="终端登记"
        description="登记码一次性显示，使用后失效。请按客户批准渠道安全交付给终端安装人员。"
      />
      <Panel title="生成一次性登记码">
        <ErrorNotice error={error} />
        {role(session, "Operator") ? (
          <>
            <label className="block-label">
              有效分钟数
              <input
                type="number"
                min="1"
                max="60"
                value={minutes}
                onChange={(e) => setMinutes(Number(e.target.value))}
              />
            </label>
            <button
              className="primary"
              disabled={busy || minutes < 1 || minutes > 60}
              onClick={create}
            >
              {busy ? "正在生成…" : "生成登记码"}
            </button>
            {result && (
              <div className="registration-code" role="status">
                <span className="eyebrow">仅本次展示 · 请立即安全保存</span>
                <strong className="mono">{result.code}</strong>
                <small>
                  到期时间：{time(result.expiresAt)}
                  。页面刷新后无法再次查看此码。
                </small>
              </div>
            )}
          </>
        ) : (
          <div className="callout">
            当前账号无登记权限。需要 Operator 角色。
          </div>
        )}
      </Panel>
    </>
  );
}
