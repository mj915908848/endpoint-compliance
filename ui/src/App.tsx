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
import { Alert, Avatar, Button, Drawer, Dropdown, Flex, Layout, Menu } from "antd";
import {
  AlertOutlined,
  AuditOutlined,
  DashboardOutlined,
  DesktopOutlined,
  FileProtectOutlined,
  InfoCircleOutlined,
  KeyOutlined,
  LockOutlined,
  LogoutOutlined,
  MenuOutlined,
  UpOutlined,
  DownOutlined,
} from "@ant-design/icons";
import { HttpError, idleMs, markUse, onSessionLost, request } from "./api";
import {
  ErrorBoundary,
  ErrorNotice,
  errorText,
  Loading,
  Login,
  PasswordDialog,
} from "./components";
import { Alerts } from "./pages/Alerts";
import { AuditPage } from "./pages/Audit";
import { DeviceDetailPage } from "./pages/DeviceDetail";
import { Devices } from "./pages/Devices";
import { Overview } from "./pages/Overview";
import { Policies } from "./pages/Policies";
import { Registration } from "./pages/Registration";
import { SystemPage } from "./pages/System";
import type { Session } from "./types";

const pages: { path: string; label: string; icon: ReactNode }[] = [
  { path: "/", label: "总览", icon: <DashboardOutlined /> },
  { path: "/devices", label: "终端设备", icon: <DesktopOutlined /> },
  { path: "/alerts", label: "告警中心", icon: <AlertOutlined /> },
  { path: "/policies", label: "策略管理", icon: <FileProtectOutlined /> },
  { path: "/registration", label: "终端登记", icon: <KeyOutlined /> },
  { path: "/audit", label: "审计记录", icon: <AuditOutlined /> },
  { path: "/system", label: "系统设置", icon: <InfoCircleOutlined /> },
];

const roleLabels: Record<string, string> = {
  Reader: "只读",
  Operator: "操作员",
  Publisher: "发布人",
  Reviewer: "审核人",
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
  async function login(username: string, password: string) {
    const result = await request<Session>("/api/auth/login", {
      method: "POST",
      body: { username, password },
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
  const page = currentPage(location.pathname);
  const nav = (
    <Menu
      theme="dark"
      mode="inline"
      aria-label="主导航"
      selectedKeys={page ? [page.path] : []}
      onClick={() => setNavOpen(false)}
      items={pages.map((p) => ({
        key: p.path,
        icon: p.icon,
        label: (
          <NavLink to={p.path} end={p.path === "/"}>
            {p.label}
          </NavLink>
        ),
      }))}
    />
  );
  const accountMenu = {
    items: [
      { key: "password", icon: <LockOutlined />, label: "修改密码" },
      { key: "logout", icon: <LogoutOutlined />, label: "退出", disabled: logoutBusy },
    ],
    onClick: ({ key }: { key: string }) => {
      setNavOpen(false);
      if (key === "password") setPasswordOpen(true);
      else void logout();
    },
  };
  const avatar = (
    <Avatar size={28} className="avatar">
      {session.username.slice(0, 1).toUpperCase()}
    </Avatar>
  );
  // In the top bar on wide screens, at the foot of the navigation drawer on narrow ones.
  const topAccount = (
    <Dropdown trigger={["click"]} placement="bottomRight" menu={accountMenu}>
      <button type="button" className="top-account" aria-label={`账号 ${session.username}`}>
        {avatar}
        <span className="top-account-name">{session.username}</span>
        <span className="top-account-role">{accountRole(session.roles)}</span>
        <DownOutlined className="top-account-caret" />
      </button>
    </Dropdown>
  );
  const drawerAccount = (
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
      <img src="/brand/lockup.svg" alt="恺域科技" className="brand-lockup" />
      <span className="brand-divider" />
      <span className="brand-name">终端合规管控</span>
    </NavLink>
  );
  return (
    <Layout className="app-shell">
      <header className="topbar">
        <Button
          type="text"
          className="topbar-menu"
          aria-label="打开导航"
          icon={<MenuOutlined />}
          onClick={() => setNavOpen(true)}
        />
        {brand}
        <span className="topbar-page">{page?.label ?? "终端合规"}</span>
        <div className="topbar-end">{topAccount}</div>
      </header>
      <Drawer
        placement="left"
        size={248}
        open={navOpen}
        onClose={() => setNavOpen(false)}
        closable={false}
        className="sidebar sidebar-drawer"
        styles={{ body: { padding: 0 } }}
      >
        <Flex vertical style={{ height: "100%" }}>
          <div className="drawer-brand">
            <img src="/brand/lockup-light.svg" alt="恺域科技" />
            <span>终端合规管控</span>
          </div>
          <div className="sidebar-nav">{nav}</div>
          {drawerAccount}
        </Flex>
      </Drawer>
      <PasswordDialog
        session={session}
        open={passwordOpen}
        onClose={() => setPasswordOpen(false)}
      />
      <Layout className="below-top">
        <Layout.Sider width={208} className="sidebar">
          <div className="sidebar-nav">{nav}</div>
        </Layout.Sider>
        <Layout className="main">
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
                    />
                  }
                />
                <Route
                  path="/devices"
                  element={<Devices openDevice={(id) => navigate(devicePath(id))} />}
                />
                <Route path="/devices/:id" element={<DeviceRoute session={session} />} />
                <Route
                  path="/alerts"
                  element={
                    <Alerts session={session} openDevice={(id) => navigate(devicePath(id))} />
                  }
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
    </Layout>
  );
}
