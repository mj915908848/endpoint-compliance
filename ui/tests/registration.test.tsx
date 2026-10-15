import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import * as api from "../src/api";
import { codeState, Registration } from "../src/pages/Registration";
import { Providers } from "../src/providers";
import type { EnrollmentCode } from "../src/types";

const session = { username: "admin", roles: ["Reader", "Operator"], csrfToken: "t" };
const code = "a".repeat(64);
const listed: EnrollmentCode = {
  id: "c1",
  label: "研发部",
  expiresAt: "2099-01-01T00:00:00Z",
  maxUses: 30,
  uses: 3,
  createdAt: "2026-10-15T00:00:00Z",
  createdBy: "admin",
  revoked: false,
};

afterEach(() => vi.restoreAllMocks());

describe("registration", () => {
  it("creates a batch code, offers the install config and revokes codes", async () => {
    const calls: { url: string; method?: string; body?: unknown }[] = [];
    vi.stubGlobal("fetch", async (url: string, options: RequestInit = {}) => {
      calls.push({
        url,
        method: options.method,
        body: options.body ? JSON.parse(options.body as string) : undefined,
      });
      const json = (b: unknown) =>
        new Response(JSON.stringify(b), { headers: { "Content-Type": "application/json" } });
      if (options.method === "POST")
        return json({
          code,
          id: "c2",
          label: "研发部",
          expiresAt: "2099-01-01T00:00:00Z",
          maxUses: 30,
        });
      if (options.method === "DELETE") return json({ revoked: "c1" });
      return json([listed]);
    });
    const download = vi.spyOn(api, "downloadJson").mockImplementation(() => {});
    render(
      <Providers>
        <Registration session={session} />
      </Providers>,
    );
    expect(await screen.findByText("3 / 30 台")).toBeTruthy();

    await userEvent.type(screen.getByLabelText("名称"), "研发部");
    const count = screen.getByLabelText("可登记台数");
    await userEvent.clear(count);
    await userEvent.type(count, "30");
    await userEvent.click(screen.getByLabelText("有效期"));
    await userEvent.click(await screen.findByTitle("7 天"));
    await userEvent.click(screen.getByRole("button", { name: "生成登记码" }));
    expect(await screen.findByText(code)).toBeTruthy();
    expect(calls.find((c) => c.method === "POST")?.body).toEqual({
      expiresMinutes: 7 * 24 * 60,
      maxUses: 30,
      label: "研发部",
    });

    await userEvent.click(screen.getByRole("button", { name: /下载登记配置/ }));
    expect(download).toHaveBeenCalledWith(
      { serverUrl: window.location.origin, code },
      "登记配置.json",
    );

    await userEvent.click(screen.getByRole("button", { name: "撤销" }));
    const pop = await screen.findByRole("tooltip");
    await userEvent.click(within(pop).getByRole("button", { name: "撤销" }));
    await waitFor(() =>
      expect(calls.some((c) => c.method === "DELETE" && c.url === "/api/enrollment-codes/c1")).toBe(
        true,
      ),
    );
  });

  it("says why a code no longer works", () => {
    expect(codeState(listed)[0]).toBe("有效");
    expect(codeState({ ...listed, uses: 30 })[0]).toBe("已用完");
    expect(codeState({ ...listed, revoked: true })[0]).toBe("已撤销");
    expect(codeState({ ...listed, expiresAt: "2020-01-01T00:00:00Z" })[0]).toBe("已过期");
  });
});
