import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { defaultSensitiveFiles, describeChanges } from "../src/components";
import { Policies } from "../src/pages/Policies";
import { Providers } from "../src/providers";
import type { Policy } from "../src/types";

const publisher = {
  username: "admin",
  roles: ["Reader", "Publisher"],
  csrfToken: "t",
  idleMinutes: 0,
};
const reader = { username: "viewer", roles: ["Reader"], csrfToken: "t", idleMinutes: 0 };

const base: Policy = {
  schemaVersion: 1,
  policyId: "Default",
  version: 1,
  sequence: 1,
  mode: "Audit",
  targetDeviceIds: [],
  issuedAt: "2026-10-14T00:00:00Z",
  expiresAt: "2027-10-14T00:00:00Z",
  denyInstalled: true,
  denyProxy: true,
  requiredModules: ["installed"],
  requiredControls: [],
  quickCheckMinutes: 5,
  fullCheckMinutes: 60,
  inventoryFreshMinutes: 120,
  lightweightFreshMinutes: 10,
  sensitiveFiles: defaultSensitiveFiles,
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
      npmPackages: [],
      pipPackages: [],
    },
  ],
  blockDomains: [],
  approvedNetworkAdapters: [],
  applicationRules: [],
};

function stub(published: Policy, template: Policy, devices: object[] = [], history: Policy[] = []) {
  let named: Policy[] = [];
  const posts: Policy[] = [];
  const posted: string[] = [];
  const release = (doc: Policy) => ({ payload: JSON.stringify(doc), signature: "s", keyId: "k" });
  vi.stubGlobal("fetch", async (url: string, options: RequestInit) => {
    const json = (body: unknown) =>
      new Response(JSON.stringify(body), { headers: { "Content-Type": "application/json" } });
    if (url.startsWith("/api/policies/") && options.method === "POST") {
      const doc = JSON.parse(options.body as string) as Policy;
      posts.push(doc);
      posted.push(url);
      if (url === "/api/policies/new") {
        const created = { ...doc, version: 2 };
        named = [...named, created];
        return json({ key: "p-new", isDefault: false, release: release(created), devices: 1 });
      }
      published = { ...doc, version: 2 };
      return json({ key: "default", isDefault: true, release: release(published), devices: 3 });
    }
    if (url === "/api/policies")
      return json([
        { key: "default", isDefault: true, release: release(published), devices: 3 },
        ...named.map((doc, i) => ({
          key: i === named.length - 1 && posted.includes("/api/policies/new") ? "p-new" : `p-${i}`,
          isDefault: false,
          release: release(doc),
          devices: doc.targetDeviceIds.length,
        })),
      ]);
    if (url === "/api/policies/template") return json(template);
    if (url === "/api/policies/default/history")
      return json(
        history.map((doc) => ({
          version: doc.version,
          publishedAt: doc.issuedAt,
          publishedBy: "admin",
          release: release(doc),
        })),
      );
    if (url === "/api/devices") return json(devices);
    return json([]);
  });
  return Object.assign(posts, { posted });
}

const renderPage = (session = publisher) =>
  render(
    <Providers>
      <Policies session={session} />
    </Providers>,
  );

afterEach(() => vi.unstubAllGlobals());

describe("policy editor", () => {
  it("creates a named policy for chosen devices, starting from the default rules", async () => {
    const posts = stub(base, base, [
      { id: "a", hostName: "PC-A", note: "张三" },
      { id: "b", hostName: "PC-B" },
    ]);
    renderPage();
    expect(await screen.findByText("未被其他策略指定的所有终端（当前 2 台）")).toBeTruthy();
    await userEvent.click(screen.getByRole("button", { name: /新建策略/ }));
    const name = screen.getByLabelText("策略名称") as HTMLInputElement;
    expect(name.value).toBe("");
    await userEvent.type(name, "研发部");
    await userEvent.click(screen.getByLabelText("指定终端"));
    await userEvent.click(await screen.findByTitle("PC-A（张三）"));
    await userEvent.click(screen.getAllByRole("button", { name: "保存并发布" })[0]);
    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByText(/新建策略“研发部”，适用 1 台终端/)).toBeTruthy();
    await userEvent.click(within(dialog).getByRole("button", { name: "发布" }));
    await waitFor(() => expect(posts.posted).toEqual(["/api/policies/new"]));
    expect(posts[0]).toMatchObject({ policyId: "研发部", targetDeviceIds: ["a"], mode: "Audit" });
    expect(posts[0].products).toEqual(base.products);
    expect(await screen.findByText("研发部 · 1 台")).toBeTruthy();
  });

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
      (await screen.findAllByText("策略名称：Default → 研发部终端规范")).length,
    ).toBeGreaterThan(0);
    const dialog = screen.getByRole("dialog");
    await userEvent.click(within(dialog).getByRole("button", { name: "发布" }));
    await waitFor(() => expect(posts).toHaveLength(1));
    expect(posts.posted).toEqual(["/api/policies/default?baseVersion=1"]);
    expect(posts[0].policyId).toBe("研发部终端规范");
    expect(posts[0].products).toHaveLength(1);
    await waitFor(() => expect(screen.queryByRole("region", { name: "未发布的修改" })).toBeNull());
  });

  it("will not publish over a release someone else published meanwhile", async () => {
    let current = base;
    const release = (doc: Policy) => ({ payload: JSON.stringify(doc), signature: "s", keyId: "k" });
    vi.stubGlobal("fetch", async (url: string) => {
      const json = (body: unknown) =>
        new Response(JSON.stringify(body), { headers: { "Content-Type": "application/json" } });
      if (url === "/api/policies")
        return json([{ key: "default", isDefault: true, release: release(current), devices: 3 }]);
      if (url === "/api/policies/template") return json(base);
      return json([]);
    });
    renderPage();
    const name = await screen.findByLabelText("策略名称");
    await userEvent.type(name, "-mine");
    current = { ...base, version: 2, blockDomains: ["example.com"] };
    await userEvent.click(screen.getByRole("button", { name: "刷新" }));
    expect(await screen.findByText("这份策略已被他人更新为 v2，你的修改基于 v1")).toBeTruthy();
    const bar = screen.getByRole("region", { name: "未发布的修改" });
    expect(
      (within(bar).getByRole("button", { name: "保存并发布" }) as HTMLButtonElement).disabled,
    ).toBe(true);
    await userEvent.click(screen.getByRole("button", { name: "载入最新版本" }));
    expect((screen.getByLabelText("策略名称") as HTMLInputElement).value).toBe("Default");
    expect(screen.queryByRole("region", { name: "未发布的修改" })).toBeNull();
    expect(screen.queryByText(/已被他人更新/)).toBeNull();

    // With nothing edited, the page simply follows the newer release.
    current = { ...base, version: 3, policyId: "Renamed" };
    await userEvent.click(screen.getByRole("button", { name: "刷新" }));
    await waitFor(() =>
      expect((screen.getByLabelText("策略名称") as HTMLInputElement).value).toBe("Renamed"),
    );
    expect(screen.queryByText(/已被他人更新/)).toBeNull();
  });

  it("refuses policy JSON the editor cannot show, naming the field, and keeps the draft", async () => {
    stub(base, base);
    renderPage();
    const name = await screen.findByLabelText("策略名称");
    await userEvent.type(name, "-mine");
    for (const [json, problem] of [
      ['{"products": [], "blockDomains": null}', "策略.blockDomains 应为文本列表"],
      ['{"products": [{"id": "x", "name": "X"}]}', "策略.products[0].packageIds 应为文本列表"],
    ]) {
      fireEvent.click(screen.getByRole("button", { name: "以 JSON 编辑" }));
      fireEvent.change(await screen.findByLabelText("策略内容（JSON）"), {
        target: { value: json },
      });
      fireEvent.click(screen.getByRole("button", { name: "应用到编辑器" }));
      expect(await screen.findByText((text) => text.includes(problem))).toBeTruthy();
      fireEvent.click(screen.getByRole("button", { name: "取消" }));
    }
    expect((screen.getByLabelText("策略名称") as HTMLInputElement).value).toBe("Default-mine");
  });

  it("keeps the editor and unsaved changes when a refresh fails", async () => {
    const release = (doc: Policy) => ({ payload: JSON.stringify(doc), signature: "s", keyId: "k" });
    let failing = false;
    vi.stubGlobal("fetch", async (url: string) => {
      const json = (body: unknown, status = 200) =>
        new Response(JSON.stringify(body), {
          status,
          headers: { "Content-Type": "application/json" },
        });
      if (failing) return json({ error: "管理端不可用" }, 503);
      if (url === "/api/policies")
        return json([{ key: "default", isDefault: true, release: release(base), devices: 3 }]);
      if (url === "/api/policies/template") return json(base);
      return json([]);
    });
    renderPage();
    await userEvent.type(await screen.findByLabelText("策略名称"), "-mine");
    expect((screen.getByLabelText("策略名称") as HTMLInputElement).value).toBe("Default-mine");
    failing = true;
    await userEvent.click(screen.getByRole("button", { name: "刷新" }));
    expect(await screen.findByText(/刷新失败，下面是上次读取的策略/)).toBeTruthy();
    expect((screen.getByLabelText("策略名称") as HTMLInputElement).value).toBe("Default-mine");
  });

  it("shows result validity as twice the check intervals, without an input", async () => {
    stub(base, base);
    renderPage();
    expect(await screen.findByText("完整检查 120 分钟，快速检查 10 分钟")).toBeTruthy();
    expect(screen.queryByLabelText("完整检查有效期")).toBeNull();
    const quick = screen.getByLabelText("快速检查间隔");
    await userEvent.clear(quick);
    await userEvent.type(quick, "15");
    expect(screen.getByText("完整检查 120 分钟，快速检查 30 分钟")).toBeTruthy();
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

  it("brings the products panel back into view when its page changes", async () => {
    const products = Array.from({ length: 15 }, (_, i) => ({
      ...base.products[0],
      id: `p${i}`,
      name: `产品${i}`,
    }));
    stub({ ...base, products }, { ...base, products });
    const scroll = vi.fn();
    Element.prototype.scrollIntoView = scroll;
    renderPage();
    expect(await screen.findByText("产品0")).toBeTruthy();
    await userEvent.click(screen.getByTitle("2"));
    expect(await screen.findByText("产品10")).toBeTruthy();
    expect(scroll).toHaveBeenCalledWith({ block: "start" });
    expect((scroll.mock.contexts[0] as HTMLElement).classList.contains("panel")).toBe(true);
    // A narrower list starts on its first page.
    await userEvent.type(screen.getByLabelText("搜索产品"), "产品1");
    expect(await screen.findByText("产品1")).toBeTruthy();
  });

  it("restores an earlier version by publishing its content again", async () => {
    const current = { ...base, version: 2, blockDomains: ["new.example"] };
    const old = { ...base, version: 1, blockDomains: ["old.example"] };
    const posts = stub(current, current, [], [current, old]);
    renderPage();
    await userEvent.click(await screen.findByRole("button", { name: "历史版本" }));
    const dialog = await screen.findByRole("dialog");
    expect(await within(dialog).findByText("当前")).toBeTruthy();
    await userEvent.click(within(dialog).getByRole("button", { name: "恢复此版本" }));
    const bar = await screen.findByRole("region", { name: "未发布的修改" });
    await userEvent.click(within(bar).getByRole("button", { name: "保存并发布" }));
    const confirm = await screen.findByRole("dialog");
    await userEvent.click(within(confirm).getByRole("button", { name: "发布" }));
    await waitFor(() => expect(posts).toHaveLength(1));
    expect(posts[0].blockDomains).toEqual(["old.example"]);
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

describe("sensitive file rules", () => {
  it("adds a Chinese keyword rule that only alerts by default", async () => {
    const posts = stub(base, base);
    renderPage();
    await userEvent.click(await screen.findByRole("switch", { name: "启用敏感文件扫描" }));
    expect(screen.getByText("启用扫描需要至少一条规则。")).toBeTruthy();
    await userEvent.click(screen.getByRole("button", { name: /添加规则/ }));
    const dialog = await screen.findByRole("dialog");
    await userEvent.type(within(dialog).getByLabelText("规则名称"), "机密文件");
    await userEvent.type(within(dialog).getByLabelText("关键词"), "机密{enter}工资表{enter}");
    await userEvent.click(within(dialog).getByRole("button", { name: "确定" }));
    expect(await screen.findByText("敏感文件扫描（1）")).toBeTruthy();
    expect(screen.getByText("只告警")).toBeTruthy();
    const bar = screen.getByRole("region", { name: "未发布的修改" });
    await userEvent.click(within(bar).getByRole("button", { name: "保存并发布" }));
    expect((await screen.findAllByText("新增敏感文件规则：机密文件")).length).toBeGreaterThan(0);
    await userEvent.click(
      within(screen.getAllByRole("dialog").at(-1)!).getByRole("button", { name: "发布" }),
    );
    await waitFor(() => expect(posts).toHaveLength(1));
    expect(posts[0].sensitiveFiles).toMatchObject({
      enabled: true,
      scanUserProfiles: true,
      scanOtherFixedDrives: true,
      rules: [
        {
          id: "rule-1",
          name: "机密文件",
          keywords: ["机密", "工资表"],
          extensions: [],
          matchFolders: true,
          action: "Alert",
        },
      ],
    });
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
      "检查项新增：端口与网络接口",
    ]);
  });

  it("names check interval changes, treating older policies as 5 and 60 minutes", () => {
    expect(describeChanges(base, { ...base, quickCheckMinutes: 5, fullCheckMinutes: 60 })).toEqual(
      [],
    );
    expect(
      describeChanges(base, { ...base, quickCheckMinutes: 10, fullCheckMinutes: 240 }),
    ).toEqual(["检查频率：快速检查每 10 分钟，完整检查每 240 分钟"]);
  });

  it("names sensitive file keyword and action changes", () => {
    const rule = {
      id: "rule-1",
      name: "机密文件",
      keywords: ["机密"],
      extensions: [],
      matchFolders: true,
      action: "Alert" as const,
    };
    const before: Policy = {
      ...base,
      sensitiveFiles: { ...defaultSensitiveFiles, enabled: true, rules: [rule] },
    };
    const after: Policy = {
      ...base,
      sensitiveFiles: {
        ...defaultSensitiveFiles,
        enabled: true,
        rules: [{ ...rule, keywords: ["机密", "绝密"], action: "Violation" }],
      },
    };
    expect(describeChanges(before, after)).toEqual([
      "修改敏感文件规则“机密文件”：新增关键词 绝密，处理方式改为判定违规",
    ]);
    expect(describeChanges(base, before)).toEqual([
      "敏感文件扫描：启用",
      "新增敏感文件规则：机密文件",
    ]);
  });
});
