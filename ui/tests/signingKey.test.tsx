import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { SigningKeyPanel } from "../src/components";
import { Providers } from "../src/providers";
import type { SigningKeyState } from "../src/types";

const session = {
  username: "admin",
  roles: ["Reader", "Publisher"],
  csrfToken: "t",
  idleMinutes: 0,
};
const rotating: SigningKeyState = {
  keyId: "old-key",
  rotation: {
    nextKeyId: "new-key",
    startedAt: "2026-10-17T02:00:00Z",
    devices: 3,
    ready: 2,
    waiting: [{ id: "d-1", hostName: "PC-OFFLINE", lastHeartbeat: null }],
  },
};

type Call = { url: string; method?: string; body?: BodyInit | null };

function stub(state: SigningKeyState) {
  const calls: Call[] = [];
  vi.stubGlobal("fetch", async (url: string, options: RequestInit = {}) => {
    calls.push({ url, method: options.method, body: options.body });
    return new Response(JSON.stringify(state), {
      headers: { "Content-Type": "application/json" },
    });
  });
  return calls;
}

afterEach(() => vi.unstubAllGlobals());

describe("signing key rotation", () => {
  it("starts a rotation after confirmation", async () => {
    const calls = stub({ keyId: "old-key", rotation: null });
    render(
      <Providers>
        <SigningKeyPanel session={session} />
      </Providers>,
    );
    await userEvent.click(await screen.findByRole("button", { name: "更换密钥" }));
    await userEvent.click(await screen.findByRole("button", { name: "开始" }));
    await waitFor(() =>
      expect(
        calls.some((c) => c.url === "/api/settings/signing-key/rotation" && c.method === "POST"),
      ).toBe(true),
    );
  });

  it("shows who still waits and completes only when told the others must enroll again", async () => {
    const calls = stub(rotating);
    render(
      <Providers>
        <SigningKeyPanel session={session} />
      </Providers>,
    );
    expect(await screen.findByText("PC-OFFLINE")).toBeTruthy();
    expect(screen.getByText("2 / 3 台终端")).toBeTruthy();
    await userEvent.click(screen.getByRole("button", { name: "完成更换" }));
    expect((await screen.findAllByText("还有 1 台终端没有收到新密钥")).length).toBeGreaterThan(0);
    await userEvent.click(screen.getByRole("button", { name: "仍然完成" }));
    await waitFor(() =>
      expect(calls.some((c) => c.url === "/api/settings/signing-key/rotation/complete")).toBe(true),
    );
    const complete = calls.find((c) => c.url === "/api/settings/signing-key/rotation/complete")!;
    expect(JSON.parse(complete.body as string)).toEqual({ force: true });
  });
});
