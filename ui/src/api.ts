export class HttpError extends Error {
  constructor(
    message: string,
    public status: number,
  ) {
    super(message);
    this.name = "HttpError";
  }
}
// When the administrator last typed, clicked or scrolled, shared between tabs so working in one keeps the
// others signed in. The server ends a session after a period without use, so requests report it.
const USE_KEY = "compliance-last-use";
let lastUse = Date.now(),
  lastSaved = 0;
export function markUse() {
  lastUse = Date.now();
  if (lastUse - lastSaved < 5_000) return;
  lastSaved = lastUse;
  try {
    localStorage.setItem(USE_KEY, String(lastUse));
  } catch {
    // Storage may be unavailable; this tab still counts its own use.
  }
}
export function idleMs() {
  let shared = 0;
  try {
    shared = Number(localStorage.getItem(USE_KEY)) || 0;
  } catch {
    shared = 0;
  }
  return Math.max(0, Date.now() - Math.max(lastUse, shared));
}

// Called when the server no longer accepts the session, from any request.
let sessionLost: (() => void) | null = null;
export function onSessionLost(handler: (() => void) | null) {
  sessionLost = handler;
}

export async function request<T>(
  path: string,
  options: {
    method?: string;
    body?: unknown;
    csrfToken?: string;
    signal?: AbortSignal;
  } = {},
): Promise<T> {
  if (!path.startsWith("/api/")) throw new Error("只允许管理端 API 路径");
  const headers = new Headers();
  if (options.body !== undefined) headers.set("Content-Type", "application/json");
  if (options.csrfToken) headers.set("X-CSRF-Token", options.csrfToken);
  headers.set("X-Idle-Seconds", String(Math.floor(idleMs() / 1000)));
  let response: Response;
  try {
    response = await fetch(path, {
      method: options.method ?? "GET",
      credentials: "same-origin",
      headers,
      body: options.body === undefined ? undefined : JSON.stringify(options.body),
      signal: options.signal,
    });
  } catch (error) {
    if (options.signal?.aborted) throw error;
    throw new Error("无法连接管理端，请检查内网服务状态");
  }
  const raw = await response.text();
  let payload: unknown = raw;
  try {
    payload = raw ? JSON.parse(raw) : null;
  } catch {
    if ((response.headers.get("Content-Type") ?? "").includes("application/json"))
      throw new Error("管理端返回无效 JSON");
  }
  if (!response.ok) {
    const error =
      payload && typeof payload === "object" && "error" in payload
        ? (payload as { error?: unknown }).error
        : null;
    if (response.status === 401 && path !== "/api/auth/login") {
      sessionLost?.();
      throw new HttpError("登录已过期，请重新登录", 401);
    }
    const message = typeof error === "string" ? error : `请求失败（HTTP ${response.status}）`;
    throw new HttpError(message, response.status);
  }
  return payload as T;
}
export function downloadReport(deviceId: string): Promise<void> {
  return downloadFile(
    `/api/devices/${encodeURIComponent(deviceId)}/report.md`,
    `终端报告-${deviceId.replace(/[^a-zA-Z0-9_-]/g, "_")}.md`,
    "报告",
  );
}
export async function downloadFile(path: string, name: string, what = "文件"): Promise<void> {
  const response = await fetch(path, {
    credentials: "same-origin",
  }).catch(() => {
    throw new Error("无法连接管理端，请检查内网服务状态");
  });
  if (!response.ok)
    throw new HttpError(`${what}下载失败（HTTP ${response.status}）`, response.status);
  const blob = await response.blob();
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = name;
  document.body.append(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}
export function downloadJson(value: unknown, name: string) {
  const blob = new Blob([JSON.stringify(value, null, 2)], {
    type: "application/json;charset=utf-8",
  });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = name;
  document.body.append(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}
