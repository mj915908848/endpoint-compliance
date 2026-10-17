import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ClientPackagesPanel, packageVersion } from "../src/components";
import { Providers } from "../src/providers";
import type { ClientPackage } from "../src/types";

const session = {
  username: "admin",
  roles: ["Reader", "Operator", "Publisher"],
  csrfToken: "t",
  idleMinutes: 0,
};
const listed: ClientPackage = {
  version: "0.2.30",
  sha256: "a".repeat(64),
  size: 52_428_800,
  uploadedAt: "2026-10-17T02:00:00Z",
  uploadedBy: "admin",
  outdated: 3,
};

type Call = { url: string; method?: string; body?: BodyInit | null; type?: string | null };

function stub(packages: ClientPackage[]) {
  const calls: Call[] = [];
  vi.stubGlobal("fetch", async (url: string, options: RequestInit = {}) => {
    calls.push({
      url,
      method: options.method,
      body: options.body,
      type: new Headers(options.headers).get("Content-Type"),
    });
    const body =
      url === "/api/client-packages" ? packages : url.endsWith("/rollout") ? { queued: 3 } : listed;
    return new Response(JSON.stringify(body), { headers: { "Content-Type": "application/json" } });
  });
  return calls;
}

afterEach(() => vi.unstubAllGlobals());

describe("client remote upgrade", () => {
  it("reads the version from the release's file name", () => {
    expect(packageVersion("compliance-client-0.2.30-windows-x64.msi")).toBe("0.2.30");
    expect(packageVersion("client.msi")).toBe("");
  });

  it("uploads the installer as is under the version its name carries", async () => {
    const calls = stub([]);
    render(
      <Providers>
        <ClientPackagesPanel session={session} />
      </Providers>,
    );
    const file = new File(
      [new Uint8Array([0xd0, 0xcf])],
      "compliance-client-0.2.30-windows-x64.msi",
    );
    await userEvent.upload(screen.getByLabelText("选择客户端安装包"), file);
    expect((screen.getByLabelText("安装包版本") as HTMLInputElement).value).toBe("0.2.30");
    await userEvent.click(screen.getByRole("button", { name: /上传/ }));
    await waitFor(() => expect(calls.some((c) => c.method === "POST")).toBe(true));
    const post = calls.find((c) => c.method === "POST")!;
    expect(post.url).toBe("/api/client-packages?version=0.2.30");
    expect(post.type).toBe("application/octet-stream");
    expect(post.body).toBe(file);
  });

  it("sends the upgrade to outdated devices after confirmation", async () => {
    const calls = stub([listed]);
    render(
      <Providers>
        <ClientPackagesPanel session={session} />
      </Providers>,
    );
    await userEvent.click(await screen.findByRole("button", { name: "升级较旧的终端" }));
    await userEvent.click(await screen.findByRole("button", { name: "发送升级" }));
    await waitFor(() =>
      expect(calls.some((c) => c.url === "/api/client-packages/0.2.30/rollout")).toBe(true),
    );
  });
});
