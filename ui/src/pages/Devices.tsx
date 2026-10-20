import { useState } from "react";
import { useSearchParams } from "react-router";
import { App, Button, Input, Select, Space, Typography } from "antd";
import { DownloadOutlined } from "@ant-design/icons";
import { downloadFile, request } from "../api";
import { role } from "../session";
import { useResource, useRefresh } from "../useResource";
import {
  DeviceTable,
  errorText,
  Fresh,
  networkText,
  PageHeading,
  Panel,
  UpdatedAt,
} from "../components";
import type { DevicesChanged, DeviceSummary, Session } from "../types";

export function Devices({
  session,
  openDevice,
}: {
  session: Session;
  openDevice: (id: string) => void;
}) {
  const refresh = useRefresh();
  const { message, modal } = App.useApp();
  const operator = role(session, "Operator");
  // The overview links here with ?filter=, so its counts open the devices they count.
  const [params] = useSearchParams();
  const [query, setQuery] = useState(""),
    [filter, setFilter] = useState(params.get("filter") ?? "all"),
    [exporting, setExporting] = useState(false),
    [selected, setSelected] = useState<string[]>([]);
  // Archived devices come from a list of their own; every other filter reads the devices in use.
  const archived = filter === "archived";
  const data = useResource<DeviceSummary[]>(
    archived ? "/api/devices?archived=true" : "/api/devices",
  );
  const all = data.data ?? [];
  const onlineCount = all.filter((d) => d.onlineState === "Online").length;
  const visible = all.filter(
    (d) =>
      (filter === "all" ||
        archived ||
        (filter === "attention"
          ? d.onlineState !== "Online" || d.currentVerdict !== "PASS"
          : filter === "offline"
            ? d.onlineState !== "Online"
            : filter === "online"
              ? d.onlineState === "Online"
              : d.onlineState === "Online" && d.currentVerdict === filter)) &&
      `${d.hostName} ${d.note ?? ""} ${d.id} ${networkText(d)}`
        .toLowerCase()
        .includes(query.trim().toLowerCase()),
  );
  // Only devices still shown count, so a filter change never acts on devices out of sight.
  const chosen = selected.filter((id) => visible.some((d) => d.id === id));
  function act(action: "archive" | "restore" | "delete") {
    const n = chosen.length;
    const text = {
      archive: {
        title: `归档所选的 ${n} 台终端？`,
        content:
          "归档的终端不再出现在终端列表、总览统计、客户端升级和签名密钥更换中，它的告警自动恢复。终端重新上线时自动取消归档。",
        ok: "归档",
        done: (k: number) => `已归档 ${k} 台终端`,
      },
      restore: {
        title: `取消归档所选的 ${n} 台终端？`,
        content: "这些终端回到终端列表；长期未上线的仍会按系统设置再次自动归档。",
        ok: "取消归档",
        done: (k: number) => `已取消归档 ${k} 台终端`,
      },
      delete: {
        title: `删除所选的 ${n} 台终端？`,
        content:
          "将删除这些终端的检查记录、告警和待执行请求，此操作不可撤销。这些电脑上的客户端将无法再上报，如需继续管控，请重新登记。",
        ok: "删除",
        done: (k: number) => `已删除 ${k} 台终端`,
      },
    }[action];
    modal.confirm({
      title: text.title,
      content: text.content,
      okText: text.ok,
      okButtonProps: action === "delete" ? { danger: true } : undefined,
      cancelText: "取消",
      onOk: async () => {
        try {
          const r = await request<DevicesChanged>(`/api/devices/${action}`, {
            method: "POST",
            body: { ids: chosen },
            csrfToken: session.csrfToken,
          });
          void message.success(text.done(r.done));
          setSelected([]);
          refresh();
        } catch (e) {
          void message.error(errorText(e));
        }
      },
    });
  }
  async function exportList() {
    setExporting(true);
    try {
      const d = new Date();
      const stamp = `${d.getFullYear()}${String(d.getMonth() + 1).padStart(2, "0")}${String(d.getDate()).padStart(2, "0")}`;
      await downloadFile("/api/devices/export.csv", `终端列表-${stamp}.csv`, "终端列表");
    } catch (e) {
      void message.error(errorText(e));
    } finally {
      setExporting(false);
    }
  }
  return (
    <>
      <PageHeading
        title="终端设备"
        description="查看每台终端的当前结论、在线状态、证据和检查报告。"
        extra={<UpdatedAt at={data.updatedAt} refreshing={data.refreshing} />}
        action={
          <Space>
            <Button icon={<DownloadOutlined />} loading={exporting} onClick={exportList}>
              导出 Excel
            </Button>
            <Button onClick={refresh}>刷新</Button>
          </Space>
        }
      />
      <Panel
        title={
          <Space size={8} wrap>
            <span>设备清单（{visible.length}）</span>
            {all.length > 0 && (
              <Typography.Text type="secondary" style={{ fontSize: 13, fontWeight: "normal" }}>
                在线{" "}
                <Typography.Text type="success" strong>
                  {onlineCount}
                </Typography.Text>{" "}
                / 共 {all.length} 台
              </Typography.Text>
            )}
          </Space>
        }
        actions={
          <Space wrap>
            <Input.Search
              aria-label="搜索设备"
              placeholder="主机名、IP、MAC 或备注"
              allowClear
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              style={{ width: 260 }}
            />
            <Select
              aria-label="筛选状态"
              value={filter}
              onChange={(f) => {
                setFilter(f);
                setSelected([]);
              }}
              style={{ width: 150 }}
              options={[
                { value: "all", label: "全部状态" },
                { value: "online", label: "在线" },
                { value: "PASS", label: "通过" },
                { value: "FAIL", label: "不通过" },
                { value: "UNKNOWN", label: "无法判断" },
                { value: "offline", label: "失联 / 疑似失联" },
                { value: "attention", label: "需要关注" },
                { value: "archived", label: "已归档" },
              ]}
            />
          </Space>
        }
      >
        {operator && chosen.length > 0 && (
          <Space wrap className="selection-bar">
            <span>已选 {chosen.length} 台</span>
            {archived ? (
              <Button size="small" onClick={() => act("restore")}>
                取消归档
              </Button>
            ) : (
              <Button size="small" onClick={() => act("archive")}>
                归档
              </Button>
            )}
            <Button size="small" danger onClick={() => act("delete")}>
              删除
            </Button>
            <Button size="small" type="link" onClick={() => setSelected([])}>
              取消选择
            </Button>
          </Space>
        )}
        {archived && (
          <Typography.Paragraph type="secondary">
            长期未上线或手动归档的终端。它们不计入统计，不产生告警；重新上线时自动回到终端列表。
          </Typography.Paragraph>
        )}
        <Fresh error={data.error} loading={data.loading}>
          <DeviceTable
            devices={visible}
            onSelect={openDevice}
            selected={operator ? selected : undefined}
            onSelectedChange={operator ? setSelected : undefined}
          />
        </Fresh>
      </Panel>
    </>
  );
}
