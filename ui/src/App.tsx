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
import { Alert, Avatar, Button, Flex, Layout, Menu, Space, Typography } from "antd";
import {
  AlertOutlined,
  AuditOutlined,
  DashboardOutlined,
  DesktopOutlined,
  FileProtectOutlined,
  InfoCircleOutlined,
  KeyOutlined,
  SafetyCertificateOutlined,
} from "@ant-design/icons";
import { HttpError, idleMs, markUse, onSessionLost, request } from "./api";
import { ErrorNotice, errorText, Loading, Login, PasswordDialog } from "./components";
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
    [idleWarning, setIdleWarning] = useState(false);
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
  return (
    <Layout className="app-shell">
      <Layout.Sider breakpoint="lg" collapsedWidth={0} width={216} className="sidebar">
        <Flex className="sidebar-brand" align="center" gap={10}>
          <SafetyCertificateOutlined className="brand-icon" />
          <div>
            <strong>终端合规</strong>
            <span>内网管理中心</span>
          </div>
        </Flex>
        <Menu
          theme="dark"
          mode="inline"
          aria-label="主导航"
          selectedKeys={page ? [page.path] : []}
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
      </Layout.Sider>
      <Layout>
        <Layout.Header className="topbar">
          <Typography.Text type="secondary" className="breadcrumb">
            管理中心 / {page?.label}
          </Typography.Text>
          <Space size={12}>
            <Avatar size="small" className="avatar">
              {session.username.slice(0, 1).toUpperCase()}
            </Avatar>
            <Space orientation="vertical" size={0} className="account">
              <Typography.Text strong>{session.username}</Typography.Text>
              <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                {session.roles.map((r) => roleLabels[r] ?? r).join(" · ")}
              </Typography.Text>
            </Space>
            <Button type="text" onClick={() => setPasswordOpen(true)}>
              修改密码
            </Button>
            <Button type="text" loading={logoutBusy} onClick={logout}>
              退出
            </Button>
          </Space>
          <PasswordDialog
            session={session}
            open={passwordOpen}
            onClose={() => setPasswordOpen(false)}
          />
        </Layout.Header>
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
          <Routes>
            <Route
              path="/"
              element={
                <Overview
                  openDevice={(id) => navigate(devicePath(id))}
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
              element={<Alerts session={session} openDevice={(id) => navigate(devicePath(id))} />}
            />
            <Route path="/policies" element={<Policies session={session} />} />
            <Route path="/registration" element={<Registration session={session} />} />
            <Route path="/audit" element={<AuditPage />} />
            <Route path="/system" element={<SystemPage session={session} />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </Layout.Content>
        <Layout.Footer className="footer">
          终端合规管理中心 · 检查结论、防护状态与告警处理分别记录
        </Layout.Footer>
      </Layout>
    </Layout>
  );
}
