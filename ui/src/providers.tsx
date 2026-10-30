import { useState, type ReactNode } from "react";
import { QueryClientProvider } from "@tanstack/react-query";
import { App as AntApp, ConfigProvider } from "antd";
import zhCN from "antd/locale/zh_CN";
import { createQueryClient } from "./useResource";

// One clear blue on a light grey page with a white, grouped sidebar.
const primary = "#2f6bff";
const theme = {
  token: {
    colorPrimary: primary,
    colorInfo: primary,
    colorLink: primary,
    colorSuccess: "#1fa463",
    colorError: "#e5484d",
    colorWarning: "#e8890c",
    colorBgLayout: "#f5f6f8",
    colorBorder: "#dadde5",
    colorBorderSecondary: "#e6e8ee",
    colorText: "#1d2330",
    colorTextSecondary: "#5d6576",
    borderRadius: 8,
    fontSize: 13,
    fontSizeHeading3: 22,
    controlHeight: 32,
    fontFamily:
      'Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", "PingFang SC", "Microsoft YaHei", sans-serif',
  },
  components: {
    Card: { headerHeight: 52, headerFontSize: 15, borderRadiusLG: 12 },
    Tabs: { titleFontSize: 14, horizontalItemGutter: 28 },
    Table: {
      headerBg: "#ffffff",
      headerColor: "#6b7385",
      headerSplitColor: "transparent",
      borderColor: "#f0f2f5",
      cellPaddingBlock: 10,
      rowHoverBg: "#f7f9fd",
      headerSortActiveBg: "#ffffff",
      headerSortHoverBg: "#f7f9fd",
      fixedHeaderSortActiveBg: "#ffffff",
    },
    Button: { primaryShadow: "none", defaultShadow: "none", dangerShadow: "none" },
    Segmented: { trackBg: "#eef0f4", itemSelectedColor: "#1d2330" },
    Collapse: { headerBg: "#fafbfc" },
    Menu: {
      itemBg: "transparent",
      subMenuItemBg: "transparent",
      itemSelectedBg: "#eef3ff",
      itemSelectedColor: primary,
      itemColor: "#3a4256",
      itemHoverBg: "#f3f5f9",
      itemHeight: 38,
      itemMarginInline: 0,
      itemMarginBlock: 2,
      itemBorderRadius: 8,
      groupTitleColor: "#7b8294",
      groupTitleFontSize: 12,
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
