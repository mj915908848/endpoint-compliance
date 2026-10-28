import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { bytes, InventoryView } from "../src/components";
import { AssetsPage } from "../src/pages/Assets";
import { Providers } from "../src/providers";
import type {
  AssetInventory,
  AssetRow,
  DeviceInventory,
  InventoryChangeRow,
  SoftwareInstall,
  SoftwareSummary,
} from "../src/types";

const GB = 1024 ** 3;

const inventory: AssetInventory = {
  collectedAt: "2026-10-27T08:00:00Z",
  hardware: {
    manufacturer: "LENOVO",
    model: "ThinkPad T14",
    serialNumber: "PF3ABCDE",
    biosVersion: "R1MET70W",
    processor: "Intel(R) Core(TM) i7-1365U",
    cores: 10,
    logicalProcessors: 12,
    memoryBytes: 16 * GB,
  },
  operatingSystem: {
    name: "Windows 11 专业版",
    version: "10.0.22631.4317",
    displayVersion: "23H2",
    architecture: "64 位",
    installedAt: "2026-01-05T02:00:00Z",
    lastBootAt: "2026-10-27T01:00:00Z",
  },
  disks: [
    { model: "SAMSUNG MZVL2512", sizeBytes: 512_000_000_000, mediaType: "SSD", busType: "NVMe" },
  ],
  volumes: [{ name: "C:", label: "", fileSystem: "NTFS", sizeBytes: 511e9, freeBytes: 200e9 }],
  software: [
    {
      name: "7-Zip",
      version: "24.08",
      publisher: "Igor Pavlov",
      installedOn: "2026-02-01",
      scope: "machine",
    },
    { name: "WeChat", version: "3.9", publisher: "Tencent", installedOn: "", scope: "zhangsan" },
  ],
};

function stub(reply: (url: string) => unknown) {
  const urls: string[] = [];
  vi.stubGlobal("fetch", async (url: string) => {
    urls.push(url);
    return new Response(JSON.stringify(reply(url) ?? []), {
      headers: { "Content-Type": "application/json" },
    });
  });
  return urls;
}

afterEach(() => vi.unstubAllGlobals());

describe("asset inventory", () => {
  it("writes sizes the way people say them", () => {
    expect(bytes(16 * GB)).toBe("16 GB");
    expect(bytes(7.5 * GB)).toBe("7.5 GB");
    expect(bytes(512_000_000_000)).toBe("477 GB");
    expect(bytes(2048 * GB)).toBe("2 TB");
    expect(bytes(0)).toBe("");
  });

  it("shows a device's hardware, searchable software and changes", async () => {
    const data: DeviceInventory = {
      inventory,
      receivedAt: "2026-10-27T08:00:05Z",
      changes: [
        {
          at: "2026-10-27T08:00:05Z",
          kind: "SoftwareInstalled",
          subject: "WeChat",
          detail: "版本 3.9（用户 zhangsan）",
        },
      ],
    };
    render(
      <Providers>
        <InventoryView data={data} />
      </Providers>,
    );
    expect(screen.getByText("LENOVO ThinkPad T14")).toBeTruthy();
    expect(screen.getByText("PF3ABCDE")).toBeTruthy();
    expect(screen.getByText("Intel(R) Core(TM) i7-1365U（10 核 12 线程）")).toBeTruthy();
    expect(screen.getByText("Windows 11 专业版 23H2 10.0.22631.4317")).toBeTruthy();
    expect(screen.getByText("安装软件")).toBeTruthy();
    expect(screen.getByText("所有用户")).toBeTruthy();
    await userEvent.type(screen.getByLabelText("搜索软件"), "tencent");
    expect(screen.queryByText("7-Zip")).toBeNull();
    expect(screen.getAllByText("WeChat").length).toBeGreaterThan(0);
  });

  it("says when a device has not reported yet", () => {
    render(
      <Providers>
        <InventoryView data={{ inventory: null, receivedAt: null, changes: [] }} />
      </Providers>,
    );
    expect(screen.getByText("暂无资产信息")).toBeTruthy();
  });

  it("lists hardware, software by device count and recent changes", async () => {
    const asset: AssetRow = {
      deviceId: "d1",
      hostName: "PC-01",
      note: "张三",
      group: "研发部",
      hardware: inventory.hardware,
      operatingSystem: inventory.operatingSystem,
      disks: inventory.disks,
      volumes: inventory.volumes,
      softwareCount: 2,
      collectedAt: inventory.collectedAt,
      receivedAt: inventory.collectedAt,
    };
    const software: SoftwareSummary[] = [
      {
        name: "Google Chrome",
        publisher: "Google LLC",
        devices: 2,
        versions: [
          { version: "131.0", devices: 1 },
          { version: "130.0", devices: 1 },
        ],
      },
    ];
    const installs: SoftwareInstall[] = [
      {
        deviceId: "d1",
        hostName: "PC-01",
        note: "张三",
        group: "研发部",
        version: "131.0",
        scope: "machine",
        installedOn: "",
      },
    ];
    const changes: InventoryChangeRow[] = [
      {
        deviceId: "d1",
        hostName: "PC-01",
        note: "张三",
        group: "研发部",
        at: "2026-10-27T08:00:05Z",
        kind: "SoftwareRemoved",
        subject: "7-Zip",
        detail: "版本 24.08",
      },
    ];
    const urls = stub((url) =>
      url === "/api/assets"
        ? [asset]
        : url === "/api/assets/software"
          ? software
          : url.startsWith("/api/assets/software/devices")
            ? installs
            : url.startsWith("/api/assets/changes")
              ? changes
              : [],
    );
    const openDevice = vi.fn();
    render(
      <Providers>
        <AssetsPage openDevice={openDevice} />
      </Providers>,
    );
    expect(await screen.findByText("ThinkPad T14", { exact: false })).toBeTruthy();
    expect(screen.getByText("16 GB")).toBeTruthy();
    await userEvent.click(screen.getByText("PC-01（张三）"));
    expect(openDevice).toHaveBeenCalledWith("d1");

    await userEvent.click(screen.getByRole("tab", { name: "软件" }));
    await userEvent.click(await screen.findByText("Google Chrome"));
    const dialog = await screen.findByRole("dialog");
    expect(await within(dialog).findByText("131.0")).toBeTruthy();
    expect(urls).toContain("/api/assets/software/devices?name=Google%20Chrome");

    await userEvent.click(screen.getByRole("tab", { name: "变更记录" }));
    expect(await screen.findByText("卸载软件")).toBeTruthy();
    expect(urls).toContain("/api/assets/changes?days=30");
  });
});
