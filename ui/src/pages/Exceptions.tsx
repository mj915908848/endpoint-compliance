import { useMemo, useState } from "react";
import {
  Alert,
  App,
  Button,
  Form,
  Input,
  InputNumber,
  Modal,
  Segmented,
  Select,
  Space,
  Table,
  Tag,
  Typography,
} from "antd";
import { PlusOutlined } from "@ant-design/icons";
import { request } from "../api";
import { deviceName, Empty, errorText, Fresh, PageHeading, time, UpdatedAt } from "../components";
import { role } from "../session";
import { useRefresh, useResource } from "../useResource";
import type { DeviceSummary, Policy, PolicyListItem, Session, StoredException } from "../types";

export const MAX_DAYS = 90;
const MAX_REASON = 300;

export const exceptionKindLabel = (kind: string) =>
  kind === "Product" ? "允许使用软件" : kind === "Usb" ? "放行 U 盘" : kind;

/** What state a request or exception is in now, and its tag colour. */
export function exceptionState(x: StoredException, now = Date.now()): [string, string] {
  switch (x.status) {
    case "Pending":
      return ["待审批", "orange"];
    case "Approved":
      return x.expiresAt && Date.parse(x.expiresAt) > now
        ? ["生效中", "green"]
        : ["已到期", "default"];
    case "Rejected":
      return ["已驳回", "red"];
    case "Revoked":
      return ["已撤销", "default"];
    default:
      return [x.status, "default"];
  }
}

type View = "pending" | "active" | "all";
type Action = { kind: "approve" | "reject" | "revoke"; item: StoredException };

/**
 * Requests from users of devices to use a forbidden product or a restricted USB disk for a while, and the exceptions
 * administrators granted. An approved exception travels in the signed policy and ends by itself.
 */
export function ExceptionsPage({
  session,
  openDevice,
}: {
  session: Session;
  openDevice: (id: string) => void;
}) {
  const { message } = App.useApp();
  const refresh = useRefresh();
  const publisher = role(session, "Publisher");
  const list = useResource<StoredException[]>("/api/exceptions");
  const [view, setView] = useState<View>("pending");
  const [action, setAction] = useState<Action | null>(null);
  const [creating, setCreating] = useState(false);
  const rows = useMemo(() => list.lastData ?? [], [list.lastData]);
  const pending = rows.filter((x) => x.status === "Pending");
  const shown =
    view === "pending"
      ? pending
      : view === "active"
        ? rows.filter((x) => exceptionState(x)[0] === "生效中")
        : rows;

  return (
    <>
      <PageHeading
        title="例外审批"
        description="员工在托盘菜单“申请例外”，临时使用被禁止的软件或受限的 U 盘。批准后随策略下发，有效期内不判违规、不拦截，到期自动失效。"
        extra={<UpdatedAt at={list.updatedAt} refreshing={list.refreshing} />}
        action={
          <Space>
            {publisher && (
              <Button icon={<PlusOutlined />} onClick={() => setCreating(true)}>
                新增例外
              </Button>
            )}
            <Button onClick={refresh}>刷新</Button>
          </Space>
        }
      />
      {!publisher && (
        <Alert
          type="info"
          showIcon
          style={{ marginBottom: 16 }}
          title="当前账号可以查看申请，审批需要“发布人”角色。"
        />
      )}
      <div className="panel">
        <Space orientation="vertical" size={12} style={{ width: "100%" }}>
          <Segmented<View>
            aria-label="显示"
            value={view}
            onChange={setView}
            options={[
              { value: "pending", label: `待审批（${pending.length}）` },
              { value: "active", label: "生效中" },
              { value: "all", label: "全部记录" },
            ]}
          />
          <Fresh error={list.error && !list.lastData ? list.error : null} loading={list.loading}>
            <Table<StoredException>
              size="middle"
              rowKey="id"
              dataSource={shown}
              pagination={{ pageSize: 50, hideOnSinglePage: true, showSizeChanger: false }}
              scroll={{ x: 1170 }}
              locale={{
                emptyText: (
                  <Empty title={view === "pending" ? "没有待审批的申请" : "暂无记录"}>
                    {view === "pending" &&
                      "员工提交申请后会出现在这里，同时在告警中心生成一条“例外申请”，并按告警推送设置通知。"}
                  </Empty>
                ),
              }}
              columns={[
                {
                  title: "终端",
                  key: "device",
                  fixed: "left",
                  width: 130,
                  render: (_, x) => (
                    <Space orientation="vertical" size={0}>
                      <Typography.Link onClick={() => openDevice(x.deviceId)}>
                        {deviceName(x)}
                      </Typography.Link>
                      {x.group && <Typography.Text type="secondary">{x.group}</Typography.Text>}
                    </Space>
                  ),
                },
                {
                  title: "申请内容",
                  key: "what",
                  width: 240,
                  render: (_, x) => (
                    // Plain blocks rather than Space, so a long name wraps and a device id is cut to the cell.
                    <div style={{ minWidth: 0 }}>
                      <Tag>{exceptionKindLabel(x.kind)}</Tag>
                      <Typography.Text type="secondary">{x.days} 天</Typography.Text>
                      <div style={{ overflowWrap: "anywhere" }}>{x.label}</div>
                      {x.kind === "Usb" && x.target !== x.label && (
                        <Typography.Text
                          type="secondary"
                          className="mono"
                          style={{ display: "block" }}
                          ellipsis={{ tooltip: x.target }}
                        >
                          {x.target}
                        </Typography.Text>
                      )}
                    </div>
                  ),
                },
                {
                  title: "理由",
                  key: "reason",
                  width: 200,
                  render: (_, x) => (
                    <Typography.Paragraph
                      style={{ margin: 0 }}
                      ellipsis={{ rows: 2, tooltip: x.reason }}
                    >
                      {x.reason}
                    </Typography.Paragraph>
                  ),
                },
                {
                  title: "申请",
                  key: "requested",
                  width: 160,
                  render: (_, x) => (
                    <Space orientation="vertical" size={0}>
                      <span>{x.requestedBy}</span>
                      <Typography.Text type="secondary">{time(x.requestedAt)}</Typography.Text>
                    </Space>
                  ),
                },
                {
                  title: "状态",
                  key: "state",
                  width: 160,
                  render: (_, x) => {
                    const [text, color] = exceptionState(x);
                    return (
                      <Space orientation="vertical" size={0}>
                        <Tag color={color}>{text}</Tag>
                        {x.status === "Approved" && x.expiresAt && (
                          <Typography.Text type="secondary">至 {time(x.expiresAt)}</Typography.Text>
                        )}
                      </Space>
                    );
                  },
                },
                {
                  title: "处理",
                  key: "decided",
                  width: 170,
                  render: (_, x) =>
                    x.decidedAt ? (
                      <Space orientation="vertical" size={0}>
                        <span>
                          {x.decidedBy} · {time(x.decidedAt)}
                        </span>
                        {x.decisionNote && (
                          <Typography.Text type="secondary">{x.decisionNote}</Typography.Text>
                        )}
                      </Space>
                    ) : (
                      <Typography.Text type="secondary">—</Typography.Text>
                    ),
                },
                {
                  title: "操作",
                  key: "actions",
                  fixed: "right",
                  width: 110,
                  render: (_, x) => {
                    if (!publisher) return null;
                    const state = exceptionState(x)[0];
                    if (state === "待审批")
                      return (
                        <Space size={0}>
                          <Button
                            type="link"
                            size="small"
                            onClick={() => setAction({ kind: "approve", item: x })}
                          >
                            批准
                          </Button>
                          <Button
                            type="link"
                            size="small"
                            danger
                            onClick={() => setAction({ kind: "reject", item: x })}
                          >
                            驳回
                          </Button>
                        </Space>
                      );
                    if (state === "生效中")
                      return (
                        <Button
                          type="link"
                          size="small"
                          danger
                          onClick={() => setAction({ kind: "revoke", item: x })}
                        >
                          撤销
                        </Button>
                      );
                    return null;
                  },
                },
              ]}
            />
          </Fresh>
        </Space>
      </div>
      {action && (
        <DecisionDialog
          key={action.item.id + action.kind}
          action={action}
          session={session}
          onClose={() => setAction(null)}
          onDone={(text) => {
            setAction(null);
            void message.success(text);
            refresh();
          }}
        />
      )}
      {creating && (
        <CreateDialog
          session={session}
          onClose={() => setCreating(false)}
          onDone={() => {
            setCreating(false);
            setView("active");
            void message.success("例外已生效，终端下次同步策略时收到");
            refresh();
          }}
        />
      )}
    </>
  );
}

const titles = {
  approve: "批准例外申请",
  reject: "驳回例外申请",
  revoke: "撤销例外",
} as const;

function DecisionDialog({
  action,
  session,
  onClose,
  onDone,
}: {
  action: Action;
  session: Session;
  onClose: () => void;
  onDone: (text: string) => void;
}) {
  const { kind, item } = action;
  const [days, setDays] = useState<number | null>(item.days),
    [note, setNote] = useState(""),
    [busy, setBusy] = useState(false),
    [error, setError] = useState<string | null>(null);

  async function submit() {
    setBusy(true);
    setError(null);
    try {
      await request(`/api/exceptions/${encodeURIComponent(item.id)}/${kind}`, {
        method: "POST",
        body: kind === "approve" ? { days, note } : { note },
        csrfToken: session.csrfToken,
      });
      onDone(
        kind === "approve"
          ? `已批准，${days} 天内有效；终端下次同步策略时生效并通知员工`
          : kind === "reject"
            ? "已驳回"
            : "已撤销，终端下次同步策略时恢复管控",
      );
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal
      open
      title={titles[kind]}
      okText={kind === "approve" ? "批准" : kind === "reject" ? "驳回" : "撤销"}
      okButtonProps={{ danger: kind !== "approve", disabled: kind === "approve" && !days }}
      confirmLoading={busy}
      onOk={submit}
      onCancel={onClose}
    >
      <Space orientation="vertical" size={12} style={{ width: "100%" }}>
        <div>
          <Typography.Text strong>{deviceName(item)}</Typography.Text>：
          {exceptionKindLabel(item.kind)}“{item.label}”
          {item.requestedBy && `，申请人 ${item.requestedBy}`}
        </div>
        {item.reason && <Typography.Text type="secondary">理由：{item.reason}</Typography.Text>}
        {kind === "revoke" && (
          <Alert
            type="warning"
            showIcon
            title="撤销后终端恢复按策略管控：软件重新判为违规，强制模式下进程会被结束；U 盘重新受限。"
          />
        )}
        {kind === "approve" && (
          <Form layout="vertical">
            <Form.Item
              label="有效天数"
              extra={`员工申请 ${item.days} 天，可以改短或改长，最多 ${MAX_DAYS} 天，从批准时算起。`}
            >
              <InputNumber
                aria-label="有效天数"
                precision={0}
                min={1}
                max={MAX_DAYS}
                value={days}
                onChange={setDays}
                suffix="天"
                style={{ width: 160 }}
              />
            </Form.Item>
          </Form>
        )}
        <Input.TextArea
          aria-label="说明"
          placeholder={kind === "reject" ? "驳回原因（可选，记入审计）" : "说明（可选，记入审计）"}
          maxLength={MAX_REASON}
          rows={2}
          value={note}
          onChange={(e) => setNote(e.target.value)}
        />
        {error && <Alert type="error" showIcon title={error} />}
      </Space>
    </Modal>
  );
}

/** The products of every policy, by id, for granting one without a request. */
function policyProducts(policies: PolicyListItem[]) {
  const products = new Map<string, string>();
  for (const p of policies)
    try {
      for (const product of (JSON.parse(p.release.payload) as Policy).products)
        if (!products.has(product.id)) products.set(product.id, product.name);
    } catch {
      // A release that cannot be read offers nothing.
    }
  return [...products].map(([value, label]) => ({ value, label }));
}

function CreateDialog({
  session,
  onClose,
  onDone,
}: {
  session: Session;
  onClose: () => void;
  onDone: () => void;
}) {
  const devices = useResource<DeviceSummary[]>("/api/devices");
  const policies = useResource<PolicyListItem[]>("/api/policies");
  const products = useMemo(() => policyProducts(policies.lastData ?? []), [policies.lastData]);
  const [deviceId, setDeviceId] = useState<string | null>(null),
    [kind, setKind] = useState("Product"),
    [target, setTarget] = useState<string | null>(null),
    [label, setLabel] = useState(""),
    [reason, setReason] = useState(""),
    [days, setDays] = useState<number | null>(7),
    [busy, setBusy] = useState(false),
    [error, setError] = useState<string | null>(null);
  const ready = !!deviceId && !!target?.trim() && !!reason.trim() && !!days;

  async function submit() {
    setBusy(true);
    setError(null);
    try {
      await request("/api/exceptions", {
        method: "POST",
        body: { deviceId, kind, target: target?.trim(), label: label.trim(), reason, days },
        csrfToken: session.csrfToken,
      });
      onDone();
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal
      open
      title="新增例外"
      okText="生效"
      okButtonProps={{ disabled: !ready }}
      confirmLoading={busy}
      onOk={submit}
      onCancel={onClose}
    >
      <Form layout="vertical">
        <Form.Item label="终端">
          <Select
            aria-label="终端"
            showSearch={{ optionFilterProp: "label" }}
            placeholder="选择终端"
            loading={devices.loading}
            value={deviceId}
            onChange={setDeviceId}
            options={(devices.lastData ?? []).map((d) => ({ value: d.id, label: deviceName(d) }))}
          />
        </Form.Item>
        <Form.Item label="类型">
          <Segmented
            aria-label="类型"
            value={kind}
            onChange={(v) => {
              setKind(v);
              setTarget(null);
              setLabel("");
            }}
            options={[
              { value: "Product", label: "允许使用软件" },
              { value: "Usb", label: "放行 U 盘" },
            ]}
          />
        </Form.Item>
        {kind === "Product" ? (
          <Form.Item
            label="软件"
            extra="策略中禁止的软件。有效期内这台终端上不判违规，也不会被结束进程。"
          >
            <Select
              aria-label="软件"
              showSearch={{ optionFilterProp: "label" }}
              placeholder="选择软件"
              value={target}
              onChange={setTarget}
              options={products}
            />
          </Form.Item>
        ) : (
          <>
            <Form.Item
              label="设备标识"
              extra="可以从“资产清单 → 移动存储记录”复制设备实例 ID，也可以只填其中能唯一识别的一段，如序列号。"
            >
              <Input
                aria-label="设备标识"
                className="mono"
                maxLength={256}
                value={target ?? ""}
                onChange={(e) => setTarget(e.target.value)}
              />
            </Form.Item>
            <Form.Item label="名称">
              <Input
                aria-label="名称"
                maxLength={200}
                placeholder="可选，如：财务部加密盘"
                value={label}
                onChange={(e) => setLabel(e.target.value)}
              />
            </Form.Item>
          </>
        )}
        <Form.Item label="理由">
          <Input.TextArea
            aria-label="理由"
            maxLength={MAX_REASON}
            rows={2}
            value={reason}
            onChange={(e) => setReason(e.target.value)}
          />
        </Form.Item>
        <Form.Item label="有效天数" extra={`1 到 ${MAX_DAYS} 天，到期自动失效。`}>
          <InputNumber
            aria-label="有效天数"
            precision={0}
            min={1}
            max={MAX_DAYS}
            value={days}
            onChange={setDays}
            suffix="天"
            style={{ width: 160 }}
          />
        </Form.Item>
      </Form>
      {error && <Alert type="error" showIcon title={error} />}
    </Modal>
  );
}
