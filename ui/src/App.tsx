import { useEffect, useState } from "react";
import { HttpError, request } from "./api";
import { ErrorNotice, Loading, Login, errorText } from "./components";
import { Alerts } from "./pages/Alerts";
import { AuditPage } from "./pages/Audit";
import { Devices } from "./pages/Devices";
import { Overview } from "./pages/Overview";
import { Policies } from "./pages/Policies";
import { Registration } from "./pages/Registration";
import { SystemPage } from "./pages/System";
import type { Session } from "./types";

type Page = "overview" | "devices" | "alerts" | "policies" | "registration" | "audit" | "system";
const pages: { id: Page; label: string; glyph: string; sub: string }[] = [
  { id: "overview", label: "总览", glyph: "◫", sub: "当前态势" },
  { id: "devices", label: "终端设备", glyph: "▤", sub: "设备与报告" },
  { id: "alerts", label: "告警中心", glyph: "◇", sub: "处置记录" },
  { id: "policies", label: "策略发布", glyph: "▣", sub: "规则与审批" },
  { id: "registration", label: "终端登记", glyph: "⊕", sub: "一次性凭据" },
  { id: "audit", label: "审计记录", glyph: "≡", sub: "管理操作" },
  { id: "system", label: "系统状态", glyph: "◉", sub: "能力边界" },
];

export function App() {
  const [session, setSession] = useState<Session | null>(null),
    [authLoading, setAuthLoading] = useState(true),
    [authError, setAuthError] = useState<string | null>(null),
    [page, setPage] = useState<Page>("overview"),
    [selectedDevice, setSelectedDevice] = useState<string | null>(null),
    [revision, setRevision] = useState(0),
    [logoutBusy, setLogoutBusy] = useState(false);
  const refresh = () => setRevision((n) => n + 1);
  async function check() {
    setAuthLoading(true);
    setAuthError(null);
    try {
      setSession(await request<Session>("/api/me"));
    } catch (e) {
      if (e instanceof HttpError && e.status === 401) setSession(null);
      else setAuthError(errorText(e));
    } finally {
      setAuthLoading(false);
    }
  }
  useEffect(() => {
    void check();
  }, []);
  async function login(username: string, password: string) {
    const result = await request<Session>("/api/auth/login", {
      method: "POST",
      body: { username, password },
    });
    setSession(result);
    setPage("overview");
    refresh();
  }
  async function logout() {
    if (!session) return;
    setLogoutBusy(true);
    try {
      await request("/api/auth/logout", {
        method: "POST",
        body: {},
        csrfToken: session.csrfToken,
      });
      setSession(null);
    } catch (e) {
      setAuthError(errorText(e));
    } finally {
      setLogoutBusy(false);
    }
  }
  if (authLoading)
    return (
      <div className="startup">
        <Loading />
      </div>
    );
  if (authError && !session)
    return (
      <div className="startup">
        <ErrorNotice error={authError} />
        <button className="secondary" onClick={check}>
          重试连接
        </button>
      </div>
    );
  if (!session) return <Login onLogin={login} />;
  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="sidebar-brand">
          <div className="brand-icon">盾</div>
          <div>
            <strong>终端合规</strong>
            <span>内网管理中心</span>
          </div>
        </div>
        <div className="sidebar-caption">工作区</div>
        <nav aria-label="主导航">
          {pages.map((p) => (
            <button
              key={p.id}
              className={`nav-item ${page === p.id ? "active" : ""}`}
              onClick={() => {
                setPage(p.id);
                if (p.id === "devices") setSelectedDevice(null);
              }}
            >
              <span className="nav-glyph">{p.glyph}</span>
              <span>
                <strong>{p.label}</strong>
                <small>{p.sub}</small>
              </span>
            </button>
          ))}
        </nav>
        <div className="sidebar-foot">
          <span className="status-dot" />
          仅连接当前内网管理端
        </div>
      </aside>
      <div className="main-shell">
        <header className="topbar">
          <div className="breadcrumb">
            管理中心 <span>/</span> {pages.find((p) => p.id === page)?.label}
          </div>
          <div className="top-actions">
            <span className="account">
              <span className="avatar">{session.username.slice(0, 1).toUpperCase()}</span>
              <span>
                <strong>{session.username}</strong>
                <small>{session.roles.join(" · ")}</small>
              </span>
            </span>
            <button className="ghost" disabled={logoutBusy} onClick={logout}>
              退出
            </button>
          </div>
        </header>
        <main className="content">
          <ErrorNotice error={authError} />
          {page === "overview" && (
            <Overview
              revision={revision}
              openDevice={(id) => {
                setSelectedDevice(id);
                setPage("devices");
              }}
              openAlerts={() => setPage("alerts")}
            />
          )}{" "}
          {page === "devices" && (
            <Devices
              key={selectedDevice ?? "list"}
              session={session}
              revision={revision}
              refresh={refresh}
              initialDevice={selectedDevice}
            />
          )}{" "}
          {page === "alerts" && <Alerts session={session} revision={revision} refresh={refresh} />}{" "}
          {page === "policies" && (
            <Policies session={session} revision={revision} refresh={refresh} />
          )}{" "}
          {page === "registration" && <Registration session={session} />}{" "}
          {page === "audit" && <AuditPage revision={revision} />}{" "}
          {page === "system" && <SystemPage revision={revision} />}
        </main>
        <footer className="footer">
          终端合规管理中心 <span>·</span> 结论、执行、防护与通知状态分别核对
        </footer>
      </div>
    </div>
  );
}
