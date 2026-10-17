import { useState, type ReactNode } from "react";
import { QueryClientProvider } from "@tanstack/react-query";
import { App as AntApp, ConfigProvider } from "antd";
import zhCN from "antd/locale/zh_CN";
import { createQueryClient } from "./useResource";

// One accent throughout: links and info notices take the primary teal instead of Ant Design's default blue.
const primary = "#1f6f84";
const theme = {
  token: {
    colorPrimary: primary,
    colorInfo: primary,
    colorLink: primary,
    colorSuccess: "#2f8f5b",
    colorError: "#c2413b",
    colorWarning: "#c98316",
    colorBgLayout: "#f3f6f8",
    colorBorderSecondary: "#e8edf0",
    borderRadius: 8,
    fontFamily:
      '-apple-system, BlinkMacSystemFont, "Segoe UI", "PingFang SC", "Microsoft YaHei", sans-serif',
  },
  components: {
    Card: { headerHeight: 52, headerFontSize: 15 },
    Table: {
      headerBg: "#f7f9fa",
      headerColor: "rgba(0, 0, 0, 0.55)",
      headerSplitColor: "transparent",
    },
    Menu: {
      darkItemBg: "transparent",
      darkSubMenuItemBg: "transparent",
      darkItemSelectedBg: "rgba(88, 216, 203, 0.14)",
      darkItemSelectedColor: "#ffffff",
      darkItemColor: "rgba(255, 255, 255, 0.68)",
      darkItemHoverBg: "rgba(255, 255, 255, 0.06)",
      itemHeight: 40,
      itemMarginInline: 10,
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
