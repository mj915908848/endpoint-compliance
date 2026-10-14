import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { Policies } from "../src/pages/Policies";
import { Providers } from "../src/providers";
import type { Policy } from "../src/types";

const session = { username: "admin", roles: ["Reader", "Publisher"], csrfToken: "t" };

const base: Policy = {
  schemaVersion: 1,
  policyId: "customer-no-foreign-ai",
  version: 1,
  mode: "Audit",
  targetDeviceIds: [],
  issuedAt: "2026-10-14T00:00:00Z",
  expiresAt: "2026-11-13T00:00:00Z",
  denyInstalled: true,
  denyProxy: true,
  requiredModules: ["installed"],
  requiredControls: [],
  inventoryFreshMinutes: 120,
  lightweightFreshMinutes: 10,
  products: [],
  blockDomains: [],
  approvedNetworkAdapters: [],
  applicationRules: [],
};

function stub(published: Policy, template: Policy) {
  const calls: string[] = [];
  vi.stubGlobal("fetch", async (url: string) => {
    calls.push(url);
    const body =
      url === "/api/policies/current"
        ? { payload: JSON.stringify(published), signature: "s", keyId: "k" }
        : url === "/api/policies/template"
          ? template
          : [];
    return new Response(JSON.stringify(body), { headers: { "Content-Type": "application/json" } });
  });
  return calls;
}

const renderPage = () =>
  render(
    <Providers>
      <Policies session={session} />
    </Providers>,
  );

afterEach(() => vi.unstubAllGlobals());

describe("built-in rule updates", () => {
  it("offers the newer built-in rules and loads them as the next version", async () => {
    stub(base, { ...base, version: 1, approvedNetworkAdapters: ["aTrust"] });
    renderPage();
    const load = await screen.findByRole("button", { name: /载入内置最新规则/ });
    await userEvent.click(load);
    const editor = screen.getByLabelText("策略内容（JSON）") as HTMLTextAreaElement;
    const draft = JSON.parse(editor.value) as Policy;
    expect(draft.approvedNetworkAdapters).toEqual(["aTrust"]);
    expect(draft.version).toBe(2);
    expect(draft.mode).toBe("Audit");
  });

  it("stays quiet when the published policy already has the built-in rules", async () => {
    const calls = stub(base, base);
    renderPage();
    await waitFor(() => expect(screen.getByLabelText("策略内容（JSON）")).toBeTruthy());
    await waitFor(() => expect(calls).toContain("/api/policies/template"));
    await new Promise((r) => setTimeout(r, 50));
    expect(screen.queryByRole("button", { name: /载入内置最新规则/ })).toBeNull();
  });
});
