export class HttpError extends Error {
  constructor(
    message: string,
    public status: number,
  ) {
    super(message);
    this.name = "HttpError";
  }
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
    const message = typeof error === "string" ? error : `请求失败（HTTP ${response.status}）`;
    throw new HttpError(message, response.status);
  }
  return payload as T;
}
export async function downloadReport(deviceId: string): Promise<void> {
  const response = await fetch(`/api/devices/${encodeURIComponent(deviceId)}/report.md`, {
    credentials: "same-origin",
  }).catch(() => {
    throw new Error("无法连接管理端，请检查内网服务状态");
  });
  if (!response.ok) throw new HttpError(`报告下载失败（HTTP ${response.status}）`, response.status);
  const blob = await response.blob();
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = `终端报告-${deviceId.replace(/[^a-zA-Z0-9_-]/g, "_")}.md`;
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
