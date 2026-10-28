import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useState } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  defaultBaseline,
  defaultSensitiveFiles,
  defaultTamper,
  defaultUsb,
  describeChanges,
  PolicyEditor,
} from "../src/components";
import { AssetsPage } from "../src/pages/Assets";
import { Providers } from "../src/providers";
import type { Policy, UsbEventRow } from "../src/types";

const base: Policy = {
  schemaVersion: 1,
  policyId: "Default",
  version: 1,
  sequence: 1,
  mode: "Audit",
  targetDeviceIds: [],
  targetGroups: [],
  exceptions: [],
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
  baseline: defaultBaseline,
  tamper: defaultTamper,
  usb: defaultUsb,
  products: [],
  blockDomains: [],
  applicationRules: [],
  approvedNetworkAdapters: [],
};

afterEach(() => vi.unstubAllGlobals());

describe("USB storage control", () => {
  it("sets the storage access and allowed devices, and says it only records until enforced", async () => {
    let latest = base;
    function Editor() {
      const [value, setValue] = useState(base);
      return (
        <PolicyEditor
          value={value}
          devices={[]}
          readOnly={false}
          onChange={(p) => {
            latest = p;
            setValue(p);
          }}
        />
      );
    }
    render(
      <Providers>
        <Editor />
      </Providers>,
    );
    await userEvent.click(screen.getByLabelText("禁止使用：插入后停用该设备"));
    expect(latest.usb.storage).toBe("Block");
    expect(screen.getByText(/当前只记录不执行/)).toBeTruthy();

    await userEvent.type(screen.getByLabelText("放行设备标识"), "IK0");
    expect(screen.getByText("设备标识至少 4 个字符")).toBeTruthy();
    await userEvent.type(screen.getByLabelText("放行设备标识"), "042");
    await userEvent.type(screen.getByLabelText("放行设备备注"), "公司加密盘");
    await userEvent.click(screen.getByRole("button", { name: /放行/ }));
    expect(latest.usb.allowedDevices).toEqual([{ id: "IK0042", note: "公司加密盘" }]);
    expect(screen.getByText("IK0042")).toBeTruthy();

    expect(describeChanges(base, latest)).toEqual([
      "U 盘和移动硬盘：允许使用 → 禁止使用",
      "移动存储放行设备新增：IK0042",
    ]);
    // Policies published before the setting existed read as allowing everything.
    const { usb: _, ...older } = base;
    expect(describeChanges(older as Policy, base)).toEqual([]);
  });

  it("lists disks plugged into devices, with ids to copy into the allowed list", async () => {
    const rows: UsbEventRow[] = [
      {
        deviceId: "d1",
        hostName: "PC-01",
        note: "张三",
        group: "研发部",
        at: "2026-10-28T02:00:00Z",
        type: "UsbBlocked",
        instanceId: "USBSTOR\\DISK&VEN_SANDISK&PROD_ULTRA\\4C530001&0",
        detail:
          "SanDisk Ultra（30 GB，序列号 4C530001）：单位策略禁止使用 U 盘和移动硬盘，已停用该设备",
      },
    ];
    const urls: string[] = [];
    vi.stubGlobal("fetch", async (url: string) => {
      urls.push(url);
      return new Response(JSON.stringify(url.startsWith("/api/usb-events") ? rows : []), {
        headers: { "Content-Type": "application/json" },
      });
    });
    const openDevice = vi.fn();
    render(
      <Providers>
        <AssetsPage openDevice={openDevice} />
      </Providers>,
    );
    await userEvent.click(screen.getByRole("tab", { name: "移动存储记录" }));
    expect(await screen.findByText("已拦截")).toBeTruthy();
    expect(screen.getByText("USBSTOR\\DISK&VEN_SANDISK&PROD_ULTRA\\4C530001&0")).toBeTruthy();
    expect(urls).toContain("/api/usb-events?days=30");
    await userEvent.click(screen.getByText("PC-01（张三）"));
    expect(openDevice).toHaveBeenCalledWith("d1");
  });
});
