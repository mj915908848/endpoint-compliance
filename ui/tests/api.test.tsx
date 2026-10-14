import { act, renderHook, waitFor } from "@testing-library/react";
import { afterEach, describe, it, expect, vi } from "vitest";
import { request } from "../src/api";
import { useResource } from "../src/useResource";
afterEach(() => vi.unstubAllGlobals());
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
    });
    rerender({ path: "/api/devices/new" });
    await act(async () => {
      deferred.get("/api/devices/new")?.(new Response('{"id":"new"}'));
    });
    await waitFor(() => expect(result.current.data?.id).toBe("new"));
    await act(async () => {
      deferred.get("/api/devices/old")?.(new Response('{"id":"old"}'));
    });
    expect(result.current.data?.id).toBe("new");
  });
  it("clears a previously healthy result when refresh fails", async () => {
    let call = 0;
    vi.stubGlobal("fetch", async () => {
      call++;
      return call === 1
        ? new Response('{"currentVerdict":"PASS"}')
        : new Response('{"error":"管理端不可用"}', {
            status: 503,
            headers: { "Content-Type": "application/json" },
          });
    });
    const { result, rerender } = renderHook(
      ({ revision }) => useResource<{ currentVerdict: string }>("/api/devices", revision),
      { initialProps: { revision: 0 } },
    );
    await waitFor(() => expect(result.current.data?.currentVerdict).toBe("PASS"));
    rerender({ revision: 1 });
    await waitFor(() => expect(result.current.error).toBe("管理端不可用"));
    expect(result.current.data).toBeNull();
  });
  it("expires an open PASS view before refreshing when no new response arrives", async () => {
    vi.useFakeTimers();
    let calls = 0;
    vi.stubGlobal("fetch", () => {
      calls++;
      return calls === 1
        ? Promise.resolve(new Response('{"currentVerdict":"PASS"}'))
        : new Promise<Response>(() => {});
    });
    try {
      const { result } = renderHook(() => useResource<{ currentVerdict: string }>("/api/devices"));
      await act(async () => {
        await vi.advanceTimersByTimeAsync(1);
      });
      expect(result.current.data?.currentVerdict).toBe("PASS");
      await act(async () => {
        await vi.advanceTimersByTimeAsync(30_000);
      });
      expect(calls).toBeGreaterThan(1);
      expect(result.current.data).toBeNull();
    } finally {
      vi.useRealTimers();
    }
  });
});
