import type { ReactNode } from "react";
import { act, renderHook, waitFor } from "@testing-library/react";
import { QueryClientProvider } from "@tanstack/react-query";
import { afterEach, describe, it, expect, vi } from "vitest";
import { request } from "../src/api";
import { createQueryClient, POLL_MS, TIMEOUT_MESSAGE, useResource } from "../src/useResource";

function wrapper() {
  const client = createQueryClient();
  return {
    client,
    wrapper: ({ children }: { children: ReactNode }) => (
      <QueryClientProvider client={client}>{children}</QueryClientProvider>
    ),
  };
}
const json = (body: string) =>
  new Response(body, { headers: { "Content-Type": "application/json" } });
afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
});
describe("management request boundary", () => {
  it("sends sameorigin credentials and CSRF only in headers", async () => {
    let sent: RequestInit | undefined;
    vi.stubGlobal("fetch", async (_url: string, options: RequestInit) => {
      sent = options;
      return new Response('{"ok":true}', {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    });
    await request("/api/alerts/id/ack", {
      method: "POST",
      body: {},
      csrfToken: "test-token",
    });
    expect(sent?.credentials).toBe("same-origin");
    expect(new Headers(sent?.headers).get("X-CSRF-Token")).toBe("test-token");
    expect(sent?.body).toBe("{}");
  });
  it("exposes rejected operations instead of returning success data", async () => {
    vi.stubGlobal(
      "fetch",
      async () =>
        new Response('{"error":"权限不足"}', {
          status: 403,
          headers: { "Content-Type": "application/json" },
        }),
    );
    await expect(request("/api/audit")).rejects.toThrow("权限不足");
  });
  it("cannot overwrite a new device with an earlier slow response", async () => {
    const deferred = new Map<string, (r: Response) => void>();
    vi.stubGlobal(
      "fetch",
      (url: string) => new Promise<Response>((resolve) => deferred.set(url, resolve)),
    );
    const { result, rerender } = renderHook(({ path }) => useResource<{ id: string }>(path), {
      initialProps: { path: "/api/devices/old" },
      ...wrapper(),
    });
    rerender({ path: "/api/devices/new" });
    await act(async () => {
      deferred.get("/api/devices/new")?.(json('{"id":"new"}'));
    });
    await waitFor(() => expect(result.current.data?.id).toBe("new"));
    await act(async () => {
      deferred.get("/api/devices/old")?.(json('{"id":"old"}'));
    });
    expect(result.current.data?.id).toBe("new");
  });
  it("clears a previously healthy result when refresh fails", async () => {
    let call = 0;
    vi.stubGlobal("fetch", async () => {
      call++;
      return call === 1
        ? json('{"currentVerdict":"PASS"}')
        : new Response('{"error":"管理端不可用"}', {
            status: 503,
            headers: { "Content-Type": "application/json" },
          });
    });
    const { client, wrapper: Wrapper } = wrapper();
    const { result } = renderHook(() => useResource<{ currentVerdict: string }>("/api/devices"), {
      wrapper: Wrapper,
    });
    await waitFor(() => expect(result.current.data?.currentVerdict).toBe("PASS"));
    await act(() => client.invalidateQueries());
    await waitFor(() => expect(result.current.error).toBe("管理端不可用"));
    expect(result.current.data).toBeNull();
  });
  it("keeps the current data on screen while a background refresh is in flight", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    let calls = 0;
    vi.stubGlobal("fetch", () => {
      calls++;
      return calls === 1
        ? Promise.resolve(json('{"currentVerdict":"PASS"}'))
        : new Promise<Response>(() => {});
    });
    const { result } = renderHook(
      () => useResource<{ currentVerdict: string }>("/api/devices"),
      wrapper(),
    );
    await waitFor(() => expect(result.current.data?.currentVerdict).toBe("PASS"));
    await act(async () => {
      await vi.advanceTimersByTimeAsync(POLL_MS + 1);
    });
    expect(calls).toBeGreaterThan(1);
    expect(result.current.refreshing).toBe(true);
    expect(result.current.loading).toBe(false);
    expect(result.current.data?.currentVerdict).toBe("PASS");
  });
  it("drops an open PASS view when a refresh times out", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    let calls = 0;
    vi.stubGlobal("fetch", (_url: string, options: RequestInit) => {
      calls++;
      if (calls === 1) return Promise.resolve(json('{"currentVerdict":"PASS"}'));
      return new Promise<Response>((_, reject) =>
        options.signal?.addEventListener("abort", () =>
          reject(new DOMException("aborted", "AbortError")),
        ),
      );
    });
    const { result } = renderHook(
      () => useResource<{ currentVerdict: string }>("/api/devices"),
      wrapper(),
    );
    await waitFor(() => expect(result.current.data?.currentVerdict).toBe("PASS"));
    await act(async () => {
      await vi.advanceTimersByTimeAsync(POLL_MS + 12_001);
    });
    await waitFor(() => expect(result.current.error).toBe(TIMEOUT_MESSAGE));
    expect(result.current.data).toBeNull();
  });
});
