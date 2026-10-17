import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { AuditPage } from "../src/pages/Audit";
import { Providers } from "../src/providers";

const record = (i: number) => ({
  id: `a${String(i).padStart(4, "0")}`,
  actor: "admin",
  action: "Login",
  target: `t${i}`,
  at: new Date(Date.UTC(2026, 9, 17) - i * 1000).toISOString(),
});

afterEach(() => vi.unstubAllGlobals());

describe("audit page", () => {
  it("loads earlier records behind the newest 500 until none are left", async () => {
    const urls: string[] = [];
    vi.stubGlobal("fetch", async (url: string) => {
      urls.push(url);
      const page = url.includes("before=")
        ? Array.from({ length: 3 }, (_, i) => record(500 + i))
        : Array.from({ length: 500 }, (_, i) => record(i));
      return new Response(JSON.stringify(page), {
        headers: { "Content-Type": "application/json" },
      });
    });
    render(
      <Providers>
        <AuditPage />
      </Providers>,
    );
    await userEvent.click(await screen.findByRole("button", { name: /已显示最近 500 条/ }));
    expect(await screen.findByText("已显示全部 503 条审计记录")).toBeTruthy();
    const earlier = urls.find((u) => u.includes("before="))!;
    expect(earlier).toContain(`before=${encodeURIComponent(record(499).at)}`);
    expect(earlier).toContain("beforeId=a0499");
    await waitFor(() => expect(urls.filter((u) => u.includes("before=")).length).toBe(1));
  });
});
