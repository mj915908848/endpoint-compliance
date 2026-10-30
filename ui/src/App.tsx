import { useEffect, useState, type ReactNode } from "react";
import {
  Navigate,
  NavLink,
  Route,
  Routes,
  useLocation,
  useNavigate,
  useParams,
} from "react-router";
import { useQueryClient } from "@tanstack/react-query";
import { Alert, Avatar, Button, Drawer, Dropdown, Flex, Layout, Menu, Typography } from "antd";
import {
  AlertOutlined,
  AuditOutlined,
  DatabaseOutlined,
  DashboardOutlined,
  DesktopOutlined,
  FileProtectOutlined,
  KeyOutlined,
  LineChartOutlined,
  LockOutlined,
  SafetyCertificateOutlined,
  LogoutOutlined,
  SafetyOutlined,
  SettingOutlined,
  MenuOutlined,
  UpOutlined,
} from "@ant-design/icons";
import { HttpError, idleMs, markUse, onSessionLost, request } from "./api";
import {
  ErrorBoundary,
  ErrorNotice,
  errorText,
  Loading,
  Login,
  PasswordDialog,
  TwoFactorDialog,
  TwoFactorSetupForm,
} from "./components";
import { Alerts } from "./pages/Alerts";
import { AssetsPage } from "./pages/Assets";
import { AuditPage } from "./pages/Audit";
import { DeviceDetailPage } from "./pages/DeviceDetail";
import { ExceptionsPage } from "./pages/Exceptions";
import { Devices } from "./pages/Devices";
import { Overview } from "./pages/Overview";
import { Policies } from "./pages/Policies";
import { Registration } from "./pages/Registration";
import { ReportsPage } from "./pages/Reports";
import { SystemPage } from "./pages/System";
import type { Session } from "./types";

type Page = { path: string; label: string; icon: ReactNode };

// Grouped as the administrator's day goes: watch, act, look back, configure.
const groups: { label: string; pages: Page[] }[] = [
  {
    label: "监控",
    pages: [
      { path: "/", label: "总览", icon: <DashboardOutlined /> },
      { path: "/devices", label: "终端设备", icon: <DesktopOutlined /> },
      { path: "/alerts", label: "告警中心", icon: <AlertOutlined /> },
    ],
  },
  {
    label: "管控",
    pages: [
      { path: "/policies", label: "策略管理", icon: <FileProtectOutlined /> },
      { path: "/exceptions", label: "例外审批", icon: <SafetyCertificateOutlined /> },
      { path: "/registration", label: "终端登记", icon: <KeyOutlined /> },
    ],
  },
  {
    label: "资产与报表",
    pages: [
      { path: "/assets", label: "资产清单", icon: <DatabaseOutlined /> },
      { path: "/reports", label: "合规报表", icon: <LineChartOutlined /> },
      { path: "/audit", label: "审计记录", icon: <AuditOutlined /> },
    ],
  },
  {
    label: "系统",
    pages: [{ path: "/system", label: "系统设置", icon: <SettingOutlined /> }],
  },
];
const pages = groups.flatMap((g) => g.pages);

const roleLabels: Record<string, string> = {
  Reader: "只读",
  Operator: "操作员",
  Publisher: "发布人",
  Reviewer: "审核人",
  Admin: "账号管理员",
};

/** One administrator normally holds every role, so it is named as such rather than as a list. */
const accountRole = (roles: string[]) =>
  roles.includes("Operator") && roles.includes("Publisher")
    ? "管理员"
    : roles.map((r) => roleLabels[r] ?? r).join(" · ");

// "/devices/abc" belongs to "/devices"; "/" only matches itself.
function currentPage(pathname: string) {
  const section = "/" + (pathname.split("/")[1] ?? "");
  return pages.find((p) => p.path === section);
}

export const devicePath = (id: string) => `/devices/${encodeURIComponent(id)}`;

function DeviceRoute({ session }: { session: Session }) {
  const { id } = useParams();
  const navigate = useNavigate();
  return <DeviceDetailPage key={id} id={id!} session={session} back={() => navigate("/devices")} />;
}

export function App() {
  const [session, setSession] = useState<Session | null>(null),
    [authLoading, setAuthLoading] = useState(true),
    [authError, setAuthError] = useState<string | null>(null),
    [logoutBusy, setLogoutBusy] = useState(false),
    [passwordOpen, setPasswordOpen] = useState(false),
    [twoFactorOpen, setTwoFactorOpen] = useState(false),
    [signedOut, setSignedOut] = useState<string | null>(null),
    [idleWarning, setIdleWarning] = useState(false),
    [navOpen, setNavOpen] = useState(false);
  const navigate = useNavigate();
  const location = useLocation();
  const queries = useQueryClient();
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
  // Any request the server refuses for want of a session returns to the login screen.
  useEffect(() => {
    if (!session) return;
    onSessionLost(() => {
      queries.clear();
      setSession(null);
      setSignedOut("登录已过期，请重新登录。");
    });
    return () => onSessionLost(null);
  }, [session, queries]);
  // Signs out after the configured minutes without typing, clicking or scrolling in any tab; a warning shows
  // for the last minute. The server enforces the same limit, so a closed or sleeping tab is covered too.
  const idleMinutes = session?.idleMinutes ?? 0;
  useEffect(() => {
    if (!session || idleMinutes <= 0) return;
    const limit = idleMinutes * 60_000;
    const events = ["pointerdown", "pointermove", "keydown", "wheel", "touchstart"] as const;
    const use = () => markUse();
    events.forEach((e) => window.addEventListener(e, use, { passive: true }));
    markUse();
    const timer = window.setInterval(() => {
      const idle = idleMs();
      setIdleWarning(idle >= limit - 60_000);
      if (idle < limit) return;
      window.clearInterval(timer);
      // Best effort: the server ends the session by itself anyway.
      void request("/api/auth/logout", {
        method: "POST",
        body: {},
        csrfToken: session.csrfToken,
      }).catch(() => undefined);
      onSessionLost(null);
      queries.clear();
      setSession(null);
      setSignedOut(`${idleMinutes} 分钟未操作，已自动退出。`);
    }, 5_000);
    return () => {
      events.forEach((e) => window.removeEventListener(e, use));
      window.clearInterval(timer);
      setIdleWarning(false);
    };
  }, [session, idleMinutes, queries]);
  async function login(username: string, password: string, code?: string) {
    const result = await request<Session>("/api/auth/login", {
      method: "POST",
      body: code === undefined ? { username, password } : { username, password, code },
    });
    // Stay on the requested URL so a shared device link opens after login.
    queries.clear();
    setSignedOut(null);
    setSession(result);
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
      queries.clear();
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
      <Flex className="startup" vertical gap={16} align="center">
        <ErrorNotice error={authError} title="无法连接管理端" />
        <Button onClick={check}>重新连接</Button>
      </Flex>
    );
  if (!session) return <Login onLogin={login} notice={signedOut} />;
  // Says whether two-step sign-in is on after the administrator changed it.
  const reloadSession = () =>
    void request<Session>("/api/me")
      .then(setSession)
      .catch(() => undefined);
  if (session.twoFactorRequired && !session.twoFactor)
    return (
      <div className="login-screen">
        <section className="login-hero" aria-hidden="true">
          <div className="login-hero-text">
            <h1>终端合规管控平台</h1>
          </div>
        </section>
        <section className="login-side">
          <div className="login-card">
            <div className="login-head">
              <img src="/brand/logo.svg" alt="" className="login-logo" />
            </div>
            <Typography.Title level={4}>请先启用两步验证</Typography.Title>
            <Typography.Paragraph type="secondary">
              单位要求所有管理账号使用两步验证。账号 {session.username}{" "}
              还没有启用，启用后才能继续使用。
            </Typography.Paragraph>
            <TwoFactorSetupForm session={session} onDone={reloadSession} />
            <Button
              type="link"
              onClick={() => void logout()}
              style={{ paddingLeft: 0, marginTop: 8 }}
            >
              退出
            </Button>
          </div>
        </section>
      </div>
    );
  const page = currentPage(location.pathname);
  const nav = (
    <Menu
      mode="inline"
      aria-label="主导航"
      selectedKeys={page ? [page.path] : []}
      onClick={() => setNavOpen(false)}
      items={groups.map((g) => ({
        type: "group" as const,
        key: g.label,
        label: g.label,
        children: g.pages.map((p) => ({
          key: p.path,
          icon: p.icon,
          label: (
            <NavLink to={p.path} end={p.path === "/"}>
              {p.label}
            </NavLink>
          ),
        })),
      }))}
    />
  );
  const accountMenu = {
    items: [
      { key: "password", icon: <LockOutlined />, label: "修改密码" },
      {
        key: "two-factor",
        icon: <SafetyOutlined />,
        label: session.twoFactor ? "两步验证（已启用）" : "两步验证（未启用）",
      },
      { key: "logout", icon: <LogoutOutlined />, label: "退出", disabled: logoutBusy },
    ],
    onClick: ({ key }: { key: string }) => {
      setNavOpen(false);
      if (key === "password") setPasswordOpen(true);
      else if (key === "two-factor") setTwoFactorOpen(true);
      else void logout();
    },
  };
  const avatar = (
    <Avatar size={28} className="avatar">
      {session.username.slice(0, 1).toUpperCase()}
    </Avatar>
  );
  // At the foot of the sidebar, and of the navigation drawer on narrow screens.
  const account = (
    <Dropdown trigger={["click"]} placement="topLeft" menu={accountMenu}>
      <button type="button" className="sidebar-account" aria-label={`账号 ${session.username}`}>
        <Flex align="center" gap={10}>
          {avatar}
          <div className="sidebar-account-name">
            <strong>{session.username}</strong>
            <span>{accountRole(session.roles)}</span>
          </div>
          <UpOutlined className="sidebar-account-caret" />
        </Flex>
      </button>
    </Dropdown>
  );
  const brand = (
    <NavLink to="/" className="brand" aria-label="终端合规管控 首页">
      <img src="/brand/logo.svg" alt="" className="brand-logo" />
      <span className="brand-name">终端合规管控</span>
    </NavLink>
  );
  const sidebar = (
    <Flex vertical style={{ height: "100%" }}>
      {brand}
      <div className="sidebar-nav">{nav}</div>
      {account}
    </Flex>
  );
  return (
    <Layout className="app-shell" hasSider>
      <Layout.Sider width={224} className="sidebar">
        {sidebar}
      </Layout.Sider>
      <Drawer
        placement="left"
        size={248}
        open={navOpen}
        onClose={() => setNavOpen(false)}
        closable={false}
        className="sidebar sidebar-drawer"
        styles={{ body: { padding: 0 } }}
      >
        {sidebar}
      </Drawer>
      <PasswordDialog
        session={session}
        open={passwordOpen}
        onClose={() => setPasswordOpen(false)}
      />
      <TwoFactorDialog
        session={session}
        open={twoFactorOpen}
        onClose={() => setTwoFactorOpen(false)}
        onChanged={reloadSession}
      />
      <Layout className="main">
        {/* Only below the lg breakpoint, where the sidebar moves into the drawer. */}
        <header className="topbar">
          <Button
            type="text"
            className="topbar-menu"
            aria-label="打开导航"
            icon={<MenuOutlined />}
            onClick={() => setNavOpen(true)}
          />
          <span className="topbar-page">{page?.label ?? "终端合规"}</span>
        </header>
        <Layout.Content className="content">
          <ErrorNotice error={authError} />
          {idleWarning && (
            <Alert
              type="warning"
              showIcon
              title={`${idleMinutes} 分钟未操作将自动退出，移动鼠标或按任意键继续使用。`}
              style={{ marginBottom: 16 }}
            />
          )}
          <ErrorBoundary key={location.pathname}>
            <Routes>
              <Route
                path="/"
                element={
                  <Overview
                    openDevice={(id) => navigate(devicePath(id))}
                    openDevices={(filter) => navigate(`/devices?filter=${filter}`)}
                    openAlerts={() => navigate("/alerts")}
                    openExceptions={() => navigate("/exceptions")}
                  />
                }
              />
              <Route
                path="/devices"
                element={
                  <Devices session={session} openDevice={(id) => navigate(devicePath(id))} />
                }
              />
              <Route path="/devices/:id" element={<DeviceRoute session={session} />} />
              <Route
                path="/assets"
                element={<AssetsPage openDevice={(id) => navigate(devicePath(id))} />}
              />
              <Route
                path="/alerts"
                element={<Alerts session={session} openDevice={(id) => navigate(devicePath(id))} />}
              />
              <Route
                path="/exceptions"
                element={
                  <ExceptionsPage session={session} openDevice={(id) => navigate(devicePath(id))} />
                }
              />
              <Route
                path="/reports"
                element={<ReportsPage openDevice={(id) => navigate(devicePath(id))} />}
              />
              <Route path="/policies" element={<Policies session={session} />} />
              <Route path="/registration" element={<Registration session={session} />} />
              <Route path="/audit" element={<AuditPage />} />
              <Route path="/system" element={<SystemPage session={session} />} />
              <Route path="*" element={<Navigate to="/" replace />} />
            </Routes>
          </ErrorBoundary>
        </Layout.Content>
      </Layout>
    </Layout>
  );
}
