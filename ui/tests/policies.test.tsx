import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { describeChanges } from "../src/components";
import { Policies } from "../src/pages/Policies";
import { Providers } from "../src/providers";
import type { Policy } from "../src/types";

const publisher = { username: "admin", roles: ["Reader", "Publisher"], csrfToken: "t" };
const reader = { username: "viewer", roles: ["Reader"], csrfToken: "t" };

const base: Policy = {
  schemaVersion: 1,
  policyId: "endpoint-compliance",
  version: 1,
  mode: "Audit",
  targetDeviceIds: [],
  issuedAt: "2026-10-14T00:00:00Z",
  expiresAt: "2027-10-14T00:00:00Z",
  denyInstalled: true,
  denyProxy: true,
  requiredModules: ["installed"],
  requiredControls: [],
  inventoryFreshMinutes: 120,
  lightweightFreshMinutes: 10,
  products: [
    {
      id: "cursor",
      name: "Cursor",
      category: "ai",
      packageIds: [],
      executableNames: ["Cursor.exe"],
      extensionIds: [],
      domains: ["cursor.com"],
      displayNames: ["Cursor"],
      adapterNames: [],
    },
  ],
  blockDomains: [],
  approvedNetworkAdapters: [],
  applicationRules: [],
};

function stub(published: Policy, template: Policy) {
  const posts: Policy[] = [];
  vi.stubGlobal("fetch", async (url: string, options: RequestInit) => {
    const json = (body: unknown) =>
      new Response(JSON.stringify(body), { headers: { "Content-Type": "application/json" } });
    if (url === "/api/policies" && options.method === "POST") {
      const doc = JSON.parse(options.body as string) as Policy;
      posts.push(doc);
      published = { ...doc, version: 2 };
      return json({ payload: JSON.stringify(published), signature: "s", keyId: "k" });
    }
    if (url === "/api/policies/current")
      return json({ payload: JSON.stringify(published), signature: "s", keyId: "k" });
    if (url === "/api/policies/template") return json(template);
    return json([]);
  });
  return posts;
}

const renderPage = (session = publisher) =>
  render(
    <Providers>
      <Policies session={session} />
    </Providers>,
  );

afterEach(() => vi.unstubAllGlobals());

describe("policy editor", () => {
  it("publishes an edit directly after showing what changes", async () => {
    const posts = stub(base, base);
    renderPage();
    const name = await screen.findByLabelText("策略名称");
    expect(screen.queryByRole("region", { name: "未发布的修改" })).toBeNull();
    const save = screen.getByRole("button", { name: "保存并发布" }) as HTMLButtonElement;
    expect(save.disabled).toBe(true);
    await userEvent.clear(name);
    await userEvent.type(name, "研发部终端规范");
    expect(save.disabled).toBe(false);
    const bar = screen.getByRole("region", { name: "未发布的修改" });
    await userEvent.click(within(bar).getByRole("button", { name: "保存并发布" }));
    expect(
      (await screen.findAllByText("策略名称：endpoint-compliance → 研发部终端规范")).length,
    ).toBeGreaterThan(0);
    const dialog = screen.getByRole("dialog");
    await userEvent.click(within(dialog).getByRole("button", { name: "发布" }));
    await waitFor(() => expect(posts).toHaveLength(1));
    expect(posts[0].policyId).toBe("研发部终端规范");
    expect(posts[0].products).toHaveLength(1);
    await waitFor(() => expect(screen.queryByRole("region", { name: "未发布的修改" })).toBeNull());
  });

  it("removes a product and can discard the change", async () => {
    stub(base, base);
    renderPage();
    await userEvent.click(await screen.findByRole("button", { name: "删除 Cursor" }));
    const pop = await screen.findByRole("tooltip");
    await userEvent.click(within(pop).getByRole("button", { name: "删除" }));
    expect(await screen.findByText("禁用产品（0）")).toBeTruthy();
    await userEvent.click(screen.getByRole("button", { name: "放弃修改" }));
    expect(await screen.findByText("禁用产品（1）")).toBeTruthy();
  });

  it("offers the newer built-in rules and keeps the deployment's own name and mode", async () => {
    const published = { ...base, policyId: "office", mode: "Enforce", targetDeviceIds: ["d1"] };
    stub(published, { ...base, approvedNetworkAdapters: ["aTrust"] });
    renderPage();
    await userEvent.click(await screen.findByRole("button", { name: /载入内置最新规则/ }));
    expect(await screen.findByText("aTrust")).toBeTruthy();
    expect((screen.getByLabelText("策略名称") as HTMLInputElement).value).toBe("office");
    expect(screen.getByRole("region", { name: "未发布的修改" })).toBeTruthy();
  });

  it("stays quiet when the published policy already has the built-in rules", async () => {
    stub(base, base);
    renderPage();
    await screen.findByLabelText("策略名称");
    await new Promise((r) => setTimeout(r, 50));
    expect(screen.queryByRole("button", { name: /载入内置最新规则/ })).toBeNull();
  });

  it("is read-only for accounts without publish permission", async () => {
    stub(base, { ...base, approvedNetworkAdapters: ["aTrust"] });
    renderPage(reader);
    expect(((await screen.findByLabelText("策略名称")) as HTMLInputElement).disabled).toBe(true);
    expect(screen.queryByRole("button", { name: "添加产品" })).toBeNull();
    expect(screen.queryByRole("button", { name: /载入内置最新规则/ })).toBeNull();
    expect(screen.getByRole("button", { name: "查看 Cursor" })).toBeTruthy();
  });
});

describe("change summary", () => {
  it("names added, removed and edited rules in plain language", () => {
    const after: Policy = {
      ...base,
      mode: "Enforce",
      products: [
        { ...base.products[0], executableNames: ["Cursor.exe", "cursor-agent.exe"] },
        { ...base.products[0], id: "kiro", name: "Kiro" },
      ],
      blockDomains: ["kiro.dev"],
      requiredModules: ["installed", "ports"],
    };
    expect(describeChanges(base, after)).toEqual([
      "运行模式：审计模式 → 强制模式",
      "新增产品：Kiro",
      "修改产品：Cursor",
      "禁止访问的域名新增：kiro.dev",
      "必需检查项新增：端口与网络接口",
    ]);
  });
});
