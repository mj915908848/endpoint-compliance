import { useState } from "react";
import {
  App,
  Button,
  Checkbox,
  Flex,
  Form,
  Input,
  Modal,
  Popconfirm,
  Space,
  Switch,
  Table,
  Tag,
  Typography,
} from "antd";
import { PlusOutlined } from "@ant-design/icons";
import { request } from "../api";
import { useRefresh, useResource } from "../useResource";
import type { Session, UserSummary, UsersView } from "../types";
import { ErrorNotice, errorText, time } from "./common";
import { Fresh, Panel } from "./layout";

const MIN_LENGTH = 12;

/** The roles offered on the page; older accounts may also hold Reviewer, which is kept as it is. */
export const roleChoices = [
  { value: "Reader", label: "只读", hint: "查看总览、终端、告警、报告和审计记录" },
  { value: "Operator", label: "操作员", hint: "处理告警、登记和管理终端、告警推送等设置" },
  { value: "Publisher", label: "发布人", hint: "发布策略、上传客户端安装包、更换签名密钥" },
  { value: "Admin", label: "账号管理员", hint: "管理账号，要求所有账号使用两步验证" },
];

const userPath = (u: UserSummary, rest: string) =>
  `/api/users/${encodeURIComponent(u.username)}${rest}`;

const roleName = (r: string) =>
  roleChoices.find((c) => c.value === r)?.label ?? (r === "Reviewer" ? "审核人" : r);

function RoleBoxes({ value, onChange }: { value?: string[]; onChange?: (v: string[]) => void }) {
  return (
    <Checkbox.Group value={value} onChange={(v) => onChange?.(v as string[])}>
      <Flex vertical gap={6}>
        {roleChoices.map((c) => (
          <Checkbox key={c.value} value={c.value}>
            {c.label}
            <Typography.Text type="secondary" style={{ marginLeft: 8, fontSize: 12 }}>
              {c.hint}
            </Typography.Text>
          </Checkbox>
        ))}
      </Flex>
    </Checkbox.Group>
  );
}

type Editing =
  | { kind: "new" }
  | { kind: "roles"; user: UserSummary }
  | { kind: "password"; user: UserSummary };

/** Management accounts: who may sign in, with which roles, and whether two-step sign-in is required. */
export function AccountsPanel({ session }: { session: Session }) {
  const { message } = App.useApp();
  const refresh = useRefresh();
  const users = useResource<UsersView>("/api/users");
  const [form] = Form.useForm<{ username?: string; password?: string; roles?: string[] }>();
  const [editing, setEditing] = useState<Editing | null>(null),
    [busy, setBusy] = useState(false),
    [error, setError] = useState<string | null>(null),
    [dialogError, setDialogError] = useState<string | null>(null);

  async function act(path: string, method: string, body: unknown, done: string) {
    setBusy(true);
    setError(null);
    setDialogError(null);
    try {
      await request(path, { method, body, csrfToken: session.csrfToken });
      void message.success(done);
      setEditing(null);
      form.resetFields();
      refresh();
    } catch (e) {
      (editing ? setDialogError : setError)(errorText(e));
    } finally {
      setBusy(false);
    }
  }

  function open(next: Editing) {
    form.resetFields();
    setDialogError(null);
    if (next.kind === "roles") form.setFieldsValue({ roles: next.user.roles });
    if (next.kind === "new") form.setFieldsValue({ roles: ["Reader"] });
    setEditing(next);
  }

  function submit(values: { username?: string; password?: string; roles?: string[] }) {
    if (!editing) return;
    if (editing.kind === "new")
      void act(
        "/api/users",
        "POST",
        { username: values.username, password: values.password, roles: values.roles },
        `已创建账号“${values.username?.trim()}”`,
      );
    else if (editing.kind === "roles")
      void act(
        userPath(editing.user, "/roles"),
        "PUT",
        // Keeps a role the page does not offer, such as the older Reviewer.
        {
          roles: [
            ...editing.user.roles.filter((r) => !roleChoices.some((c) => c.value === r)),
            ...(values.roles ?? []),
          ],
        },
        `已修改“${editing.user.username}”的角色`,
      );
    else
      void act(
        userPath(editing.user, "/password"),
        "POST",
        { password: values.password },
        `已重置“${editing.user.username}”的密码，它在其他浏览器上的登录已退出`,
      );
  }

  const data = users.lastData;
  const required = data?.requireTwoFactor ?? false;
  const missing = (data?.users ?? []).filter((u) => !u.disabled && !u.twoFactor).length;

  return (
    <Space orientation="vertical" size={16} style={{ width: "100%" }}>
      <Panel title="两步验证">
        <Flex gap={12} align="center" wrap>
          <Switch
            aria-label="要求所有账号使用两步验证"
            checked={required}
            loading={busy && !editing}
            disabled={!data}
            onChange={(on) =>
              void act(
                "/api/settings/require-two-factor",
                "PUT",
                { required: on },
                on ? "已要求所有账号使用两步验证" : "已不再要求两步验证",
              )
            }
          />
          <span>要求所有账号使用两步验证</span>
        </Flex>
        <Typography.Paragraph type="secondary" style={{ marginTop: 12, marginBottom: 0 }}>
          开启后，还没有启用两步验证的账号登录后只能先设置，设置好才能使用其他功能
          {data && missing > 0 ? `（目前有 ${missing} 个账号未启用）` : ""}
          。开启前需先为自己的账号启用（右上角账号菜单 → 两步验证）。
        </Typography.Paragraph>
      </Panel>
      <Panel
        title={`管理账号（${data?.users.length ?? 0}）`}
        actions={
          <Button icon={<PlusOutlined />} onClick={() => open({ kind: "new" })}>
            新建账号
          </Button>
        }
      >
        <ErrorNotice error={error} />
        <Fresh error={users.error && !data ? users.error : null} loading={users.loading}>
          <Table<UserSummary>
            rowKey="username"
            size="middle"
            pagination={false}
            scroll={{ x: 760 }}
            dataSource={data?.users ?? []}
            columns={[
              {
                title: "账号",
                dataIndex: "username",
                render: (name: string, u) => (
                  <Space>
                    <span className={u.disabled ? "muted" : undefined}>{name}</span>
                    {name === session.username && <Tag>当前账号</Tag>}
                  </Space>
                ),
              },
              {
                title: "角色",
                dataIndex: "roles",
                render: (roles: string[]) => (
                  <Space size={4} wrap>
                    {roles.map((r) => (
                      <Tag key={r} color={r === "Admin" ? "blue" : undefined}>
                        {roleName(r)}
                      </Tag>
                    ))}
                  </Space>
                ),
              },
              {
                title: "两步验证",
                dataIndex: "twoFactor",
                width: 110,
                render: (on: boolean) =>
                  on ? <Tag color="success">已启用</Tag> : <Tag>未启用</Tag>,
              },
              {
                title: "状态",
                dataIndex: "disabled",
                width: 90,
                render: (disabled: boolean) =>
                  disabled ? <Tag color="error">已停用</Tag> : <Tag color="processing">正常</Tag>,
              },
              {
                title: "最近登录",
                dataIndex: "lastLoginAt",
                width: 170,
                render: (at: string | null) => (at ? time(at) : "从未登录"),
              },
              {
                title: "操作",
                key: "actions",
                width: 260,
                render: (_, u) => {
                  const self = u.username === session.username;
                  return (
                    <Space size={0} wrap>
                      <Button
                        type="link"
                        size="small"
                        onClick={() => open({ kind: "roles", user: u })}
                      >
                        修改角色
                      </Button>
                      {!self && (
                        <Button
                          type="link"
                          size="small"
                          onClick={() => open({ kind: "password", user: u })}
                        >
                          重置密码
                        </Button>
                      )}
                      {!self && u.twoFactor && (
                        <Popconfirm
                          title={`重置“${u.username}”的两步验证？`}
                          description="它下次只用密码登录，然后需要重新设置（单位要求时必须设置）。"
                          okText="重置"
                          onConfirm={() =>
                            act(
                              userPath(u, "/two-factor"),
                              "DELETE",
                              undefined,
                              `已重置“${u.username}”的两步验证`,
                            )
                          }
                        >
                          <Button type="link" size="small">
                            重置两步验证
                          </Button>
                        </Popconfirm>
                      )}
                      {!self &&
                        (u.disabled ? (
                          <Button
                            type="link"
                            size="small"
                            onClick={() =>
                              void act(userPath(u, "/enable"), "POST", {}, `已启用“${u.username}”`)
                            }
                          >
                            启用
                          </Button>
                        ) : (
                          <Popconfirm
                            title={`停用“${u.username}”？`}
                            description="停用后它不能登录，已登录的浏览器立即退出。审计记录保留。"
                            okText="停用"
                            okButtonProps={{ danger: true }}
                            onConfirm={() =>
                              act(userPath(u, "/disable"), "POST", {}, `已停用“${u.username}”`)
                            }
                          >
                            <Button type="link" size="small" danger>
                              停用
                            </Button>
                          </Popconfirm>
                        ))}
                    </Space>
                  );
                },
              },
            ]}
          />
        </Fresh>
        <Typography.Paragraph type="secondary" style={{ marginTop: 12, marginBottom: 0 }}>
          每位管理人员使用自己的账号，审计记录才能分清是谁做的。离职人员的账号请停用，不会删除，以免审计记录对不上人。
        </Typography.Paragraph>
      </Panel>
      <Modal
        title={
          editing?.kind === "new"
            ? "新建账号"
            : editing?.kind === "roles"
              ? `修改“${editing.user.username}”的角色`
              : editing
                ? `重置“${editing.user.username}”的密码`
                : ""
        }
        open={!!editing}
        onCancel={() => setEditing(null)}
        onOk={() => form.submit()}
        okText={editing?.kind === "new" ? "创建" : "保存"}
        confirmLoading={busy}
        destroyOnHidden
      >
        <Form form={form} layout="vertical" onFinish={submit} requiredMark={false}>
          {editing?.kind === "new" && (
            <Form.Item
              label="账号名"
              name="username"
              rules={[
                { required: true, whitespace: true, message: "请输入账号名" },
                { max: 100, message: "账号名最多 100 个字符" },
              ]}
            >
              <Input autoComplete="off" />
            </Form.Item>
          )}
          {editing?.kind !== "roles" && (
            <Form.Item
              label={editing?.kind === "new" ? "初始密码" : "新密码"}
              name="password"
              extra={`至少 ${MIN_LENGTH} 位。请当面或通过安全渠道告诉对方，并提醒对方登录后修改。`}
              rules={[
                { required: true, message: "请输入密码" },
                { min: MIN_LENGTH, message: `密码至少 ${MIN_LENGTH} 位` },
              ]}
            >
              <Input.Password autoComplete="new-password" />
            </Form.Item>
          )}
          {editing?.kind !== "password" && (
            <Form.Item
              label="角色"
              name="roles"
              rules={[{ required: true, type: "array", min: 1, message: "请至少选择一个角色" }]}
            >
              <RoleBoxes />
            </Form.Item>
          )}
        </Form>
        <ErrorNotice error={dialogError} />
      </Modal>
    </Space>
  );
}
