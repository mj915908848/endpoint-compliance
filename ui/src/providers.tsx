import { useState, type ReactNode } from "react";
import { QueryClientProvider } from "@tanstack/react-query";
import { App as AntApp, ConfigProvider } from "antd";
import zhCN from "antd/locale/zh_CN";
import { createQueryClient } from "./useResource";

// Blue primary and navy navigation, after the gateway consoles administrators already use.
const primary = "#2457e6";
const theme = {
  token: {
    colorPrimary: primary,
    colorInfo: primary,
    colorLink: primary,
    colorSuccess: "#1f9d55",
    colorError: "#e5484d",
    colorWarning: "#e8890c",
    colorBgLayout: "#eef1f6",
    colorBorderSecondary: "#e6e9f0",
    colorText: "#1f2633",
    borderRadius: 4,
    fontFamily:
      '-apple-system, BlinkMacSystemFont, "Segoe UI", "PingFang SC", "Microsoft YaHei", sans-serif',
  },
  components: {
    Card: { headerHeight: 48, headerFontSize: 15 },
    Table: {
      headerBg: "#f2f4f8",
      headerColor: "#1f2633",
      headerSplitColor: "#e1e5ee",
      cellPaddingBlock: 10,
      rowHoverBg: "#f5f8ff",
    },
    Tabs: { titleFontSize: 14 },
    Menu: {
      darkItemBg: "transparent",
      darkSubMenuItemBg: "transparent",
      darkItemSelectedBg: primary,
      darkItemSelectedColor: "#ffffff",
      darkItemColor: "rgba(255, 255, 255, 0.78)",
      darkItemHoverBg: "rgba(255, 255, 255, 0.08)",
      itemHeight: 46,
      itemMarginInline: 0,
      itemBorderRadius: 0,
      itemMarginBlock: 0,
    },
  },
};

/** Query cache, Ant Design theme/locale and message context shared by the app and its tests. */
export function Providers({ children }: { children: ReactNode }) {
  const [client] = useState(createQueryClient);
  return (
    <QueryClientProvider client={client}>
      <ConfigProvider locale={zhCN} theme={theme} button={{ autoInsertSpace: false }}>
        <AntApp>{children}</AntApp>
      </ConfigProvider>
    </QueryClientProvider>
  );
}
