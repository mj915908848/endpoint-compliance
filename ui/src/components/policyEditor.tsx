import { useState } from "react";
import {
  Alert,
  Button,
  Checkbox,
  Col,
  Form,
  Input,
  InputNumber,
  Modal,
  Popconfirm,
  Radio,
  Row,
  Select,
  Space,
  Table,
  Tag,
  Typography,
} from "antd";
import { PlusOutlined } from "@ant-design/icons";
import type { DeviceSummary, Policy, Product } from "../types";
import { categoryLabel, controlLabel, moduleLabel } from "./labels";
import { deviceName, Empty } from "./common";
import { Panel } from "./layout";

export const modules = [
  "installed",
  "installed-paths",
  "services",
  "processes",
  "proxy",
  "proxy-env",
  "proxy-advanced",
  "extensions",
  "appx",
  "ports",
  "users",
  "cli",
];
const controls = ["application", "edge", "network"];
const categories = ["proxy", "ai", "ide_ai"];

/** The part of a policy an administrator edits; the server assigns version and validity on publish. */
const content = ({ schemaVersion, version, issuedAt, expiresAt, ...rest }: Policy) => rest;
export const sameContent = (a: Policy, b: Policy) =>
  JSON.stringify(content(a)) === JSON.stringify(content(b));

const list = (values: string[]) => values.join("、");
const added = (before: string[], after: string[]) => after.filter((x) => !before.includes(x));

/** Plain-language list of what publishing `after` changes compared with `before`. */
export function describeChanges(before: Policy, after: Policy): string[] {
  const changes: string[] = [];
  if (before.policyId !== after.policyId)
    changes.push(`策略名称：${before.policyId} → ${after.policyId}`);
  if (before.mode !== after.mode)
    changes.push(`运行模式：${modeLabel(before.mode)} → ${modeLabel(after.mode)}`);
  if (JSON.stringify(before.targetDeviceIds) !== JSON.stringify(after.targetDeviceIds))
    changes.push(
      `适用终端：${after.targetDeviceIds.length ? `${after.targetDeviceIds.length} 台指定终端` : "全部终端"}`,
    );
  const ids = (p: Policy) => p.products.map((x) => x.id);
  const name = (p: Policy) => (id: string) => p.products.find((x) => x.id === id)?.name ?? id;
  const newProducts = added(ids(before), ids(after)),
    removedProducts = added(ids(after), ids(before)),
    editedProducts = after.products.filter((x) => {
      const old = before.products.find((y) => y.id === x.id);
      return old && JSON.stringify(old) !== JSON.stringify(x);
    });
  if (newProducts.length) changes.push(`新增产品：${list(newProducts.map(name(after)))}`);
  if (removedProducts.length) changes.push(`删除产品：${list(removedProducts.map(name(before)))}`);
  if (editedProducts.length) changes.push(`修改产品：${list(editedProducts.map((x) => x.name))}`);
  const diff = (label: string, a: string[], b: string[], show = moduleLabel) => {
    const plus = added(a, b),
      minus = added(b, a);
    if (plus.length) changes.push(`${label}新增：${list(plus.map(show))}`);
    if (minus.length) changes.push(`${label}移除：${list(minus.map(show))}`);
  };
  const same = (x: string) => x;
  diff("禁止访问的域名", before.blockDomains, after.blockDomains, same);
  diff(
    "已批准的网卡",
    before.approvedNetworkAdapters ?? [],
    after.approvedNetworkAdapters ?? [],
    same,
  );
  diff("必需检查项", before.requiredModules, after.requiredModules);
  diff("必需防护措施", before.requiredControls, after.requiredControls, controlLabel);
  if (
    before.inventoryFreshMinutes !== after.inventoryFreshMinutes ||
    before.lightweightFreshMinutes !== after.lightweightFreshMinutes
  )
    changes.push(
      `检查时效：完整检查 ${after.inventoryFreshMinutes} 分钟，快速检查 ${after.lightweightFreshMinutes} 分钟`,
    );
  if (JSON.stringify(before.applicationRules) !== JSON.stringify(after.applicationRules))
    changes.push(`应用程序拦截规则：${after.applicationRules.length} 条`);
  return changes;
}

export const modeLabel = (mode: string) => (mode === "Enforce" ? "强制模式" : "审计模式");

const Hint = ({ children }: { children: React.ReactNode }) => (
  <Typography.Paragraph type="secondary" style={{ fontSize: 12, margin: "4px 0 0" }}>
    {children}
  </Typography.Paragraph>
);

const Field = ({ label, children }: { label: string; children: React.ReactNode }) => (
  <div className="policy-field">
    <Typography.Text strong>{label}</Typography.Text>
    <div style={{ marginTop: 6 }}>{children}</div>
  </div>
);

function TagInput({
  value,
  onChange,
  placeholder,
  disabled,
  label,
}: {
  value?: string[];
  onChange?: (v: string[]) => void;
  placeholder?: string;
  disabled?: boolean;
  label?: string;
}) {
  return (
    <Select
      mode="tags"
      aria-label={label}
      value={value}
      onChange={(v: string[]) => onChange?.([...new Set(v.map((x) => x.trim()).filter(Boolean))])}
      tokenSeparators={[",", "，", "\n"]}
      placeholder={placeholder}
      disabled={disabled}
      open={false}
      suffixIcon={null}
      style={{ width: "100%" }}
    />
  );
}

export function PolicyEditor({
  value,
  onChange,
  devices,
  readOnly,
}: {
  value: Policy;
  onChange: (p: Policy) => void;
  devices: DeviceSummary[];
  readOnly: boolean;
}) {
  const set = (patch: Partial<Policy>) => onChange({ ...value, ...patch });
  const targeted = value.targetDeviceIds.length > 0;
  const [allTargets, setAllTargets] = useState(!targeted);
  const productDomains = [...new Set(value.products.flatMap((p) => p.domains))];
  const missingDomains = productDomains.filter((d) => !value.blockDomains.includes(d));

  return (
    <Space orientation="vertical" size={16} style={{ width: "100%" }}>
      <Panel title="基本设置">
        <Row gutter={[24, 16]}>
          <Col xs={24} lg={12}>
            <Field label="策略名称">
              <Input
                aria-label="策略名称"
                value={value.policyId}
                maxLength={64}
                disabled={readOnly}
                onChange={(e) => set({ policyId: e.target.value })}
              />
              <Hint>用于在报告和终端上识别这份策略，例如“研发部终端规范”。</Hint>
            </Field>
          </Col>
          <Col xs={24} lg={12}>
            <Field label="运行模式">
              <Radio.Group
                value={value.mode}
                disabled={readOnly}
                onChange={(e) => set({ mode: e.target.value as string })}
                options={[
                  { value: "Audit", label: "审计模式：只检查，不拦截" },
                  { value: "Enforce", label: "强制模式：检查并拦截" },
                ]}
              />
              {value.mode === "Enforce" && (
                <Hint>
                  强制模式只能用于指定的试点终端，且这些终端需要在线、已验证所选的防护措施。
                </Hint>
              )}
            </Field>
          </Col>
          <Col xs={24} lg={12}>
            <Field label="适用终端">
              <Radio.Group
                value={allTargets && !targeted ? "all" : "some"}
                disabled={readOnly}
                onChange={(e) => {
                  const all = e.target.value === "all";
                  setAllTargets(all);
                  if (all) set({ targetDeviceIds: [] });
                }}
                options={[
                  { value: "all", label: "全部终端" },
                  { value: "some", label: "指定终端" },
                ]}
              />
              {!(allTargets && !targeted) && (
                <Select
                  mode="multiple"
                  aria-label="指定终端"
                  style={{ width: "100%", marginTop: 8 }}
                  placeholder="选择终端"
                  disabled={readOnly}
                  value={value.targetDeviceIds}
                  onChange={(ids: string[]) => set({ targetDeviceIds: ids })}
                  optionFilterProp="label"
                  options={[
                    ...devices.map((d) => ({ value: d.id, label: deviceName(d) })),
                    ...value.targetDeviceIds
                      .filter((id) => !devices.some((d) => d.id === id))
                      .map((id) => ({ value: id, label: `${id}（已删除）` })),
                  ]}
                />
              )}
            </Field>
          </Col>
          <Col xs={24} lg={12}>
            <Field label="检查结果有效期">
              <Space wrap>
                <span>完整检查</span>
                <InputNumber
                  aria-label="完整检查有效期"
                  min={1}
                  max={10080}
                  value={value.inventoryFreshMinutes}
                  disabled={readOnly}
                  onChange={(v) => v && set({ inventoryFreshMinutes: v })}
                  suffix="分钟"
                  style={{ width: 130 }}
                />
                <span>快速检查</span>
                <InputNumber
                  aria-label="快速检查有效期"
                  min={1}
                  max={1440}
                  value={value.lightweightFreshMinutes}
                  disabled={readOnly}
                  onChange={(v) => v && set({ lightweightFreshMinutes: v })}
                  suffix="分钟"
                  style={{ width: 130 }}
                />
              </Space>
              <Hint>超过有效期没有新的检查结果，终端结论显示为“无法判断”。</Hint>
            </Field>
          </Col>
        </Row>
      </Panel>

      <ProductTable
        products={value.products}
        readOnly={readOnly}
        onChange={(products) =>
          set({
            products,
            // Hash rules must point at an existing product; drop those whose product was removed.
            applicationRules: value.applicationRules.filter((r) =>
              products.some((p) => p.id === r.productId),
            ),
          })
        }
      />

      <Panel title="网络">
        <Row gutter={[24, 16]}>
          <Col xs={24} lg={12}>
            <Field label="禁止访问的域名">
              <TagInput
                label="禁止访问的域名"
                value={value.blockDomains}
                disabled={readOnly}
                placeholder="输入域名后按回车，例如 chatgpt.com"
                onChange={(blockDomains) => set({ blockDomains })}
              />
              <Hint>只填域名，会同时匹配其子域名。强制模式下写入 Edge 浏览器策略。</Hint>
              {missingDomains.length > 0 && !readOnly && (
                <Button
                  size="small"
                  style={{ marginTop: 8 }}
                  onClick={() => set({ blockDomains: [...value.blockDomains, ...missingDomains] })}
                >
                  加入产品规则中的 {missingDomains.length} 个域名
                </Button>
              )}
            </Field>
          </Col>
          <Col xs={24} lg={12}>
            <Field label="已批准的网卡">
              <TagInput
                label="已批准的网卡"
                value={value.approvedNetworkAdapters ?? []}
                disabled={readOnly}
                placeholder="输入网卡名称关键字，例如 aTrust"
                onChange={(approvedNetworkAdapters) => set({ approvedNetworkAdapters })}
              />
              <Hint>
                公司自己的 VPN 等虚拟网卡填在这里，名称或描述包含该关键字的网卡不再作为线索上报。
              </Hint>
            </Field>
          </Col>
        </Row>
      </Panel>

      <Panel title="检查要求">
        <Row gutter={[24, 16]}>
          <Col xs={24} lg={14}>
            <Field label="必需检查项">
              <Checkbox.Group
                value={value.requiredModules}
                disabled={readOnly}
                onChange={(v) => set({ requiredModules: modules.filter((m) => v.includes(m)) })}
                options={modules.map((m) => ({ value: m, label: moduleLabel(m) }))}
              />
              <Hint>这些检查项都成功读取后，结论才可能是“通过”。至少选择一项。</Hint>
            </Field>
          </Col>
          <Col xs={24} lg={10}>
            <Field label="必需防护措施">
              <Checkbox.Group
                value={value.requiredControls}
                disabled={readOnly}
                onChange={(v) => set({ requiredControls: controls.filter((c) => v.includes(c)) })}
                options={controls.map((c) => ({ value: c, label: controlLabel(c) }))}
              />
              <Hint>仅在强制模式下生效，发布前会核对试点终端是否已验证这些防护措施。</Hint>
            </Field>
          </Col>
        </Row>
      </Panel>
    </Space>
  );
}

const emptyProduct: Product = {
  id: "",
  name: "",
  category: "ai",
  packageIds: [],
  executableNames: [],
  extensionIds: [],
  domains: [],
  displayNames: [],
  adapterNames: [],
};

function ProductTable({
  products,
  onChange,
  readOnly,
}: {
  products: Product[];
  onChange: (p: Product[]) => void;
  readOnly: boolean;
}) {
  const [editing, setEditing] = useState<{ index: number; product: Product } | null>(null);
  const [search, setSearch] = useState(""),
    [category, setCategory] = useState<string | null>(null);
  const q = search.trim().toLowerCase();
  const shown = products
    .map((p, index) => ({ p, index }))
    .filter(
      ({ p }) =>
        (!category || p.category === category) &&
        (!q || `${p.id} ${p.name} ${(p.displayNames ?? []).join(" ")}`.toLowerCase().includes(q)),
    );
  const counts = (p: Product) =>
    [
      ["安装名称", p.displayNames?.length ?? 0],
      ["程序", p.executableNames.length],
      ["应用包", p.packageIds.length],
      ["扩展", p.extensionIds.length],
      ["网卡", p.adapterNames?.length ?? 0],
      ["域名", p.domains.length],
    ].filter(([, n]) => n) as [string, number][];

  return (
    <Panel
      title={`禁用产品（${products.length}）`}
      actions={
        !readOnly && (
          <Button
            icon={<PlusOutlined />}
            onClick={() => setEditing({ index: -1, product: emptyProduct })}
          >
            添加产品
          </Button>
        )
      }
    >
      <Space wrap style={{ marginBottom: 12 }}>
        <Input.Search
          allowClear
          placeholder="搜索产品名称"
          aria-label="搜索产品"
          style={{ width: 220 }}
          onChange={(e) => setSearch(e.target.value)}
        />
        <Radio.Group
          size="small"
          optionType="button"
          value={category ?? "all"}
          onChange={(e) => setCategory(e.target.value === "all" ? null : e.target.value)}
          options={[
            { value: "all", label: "全部" },
            ...categories.map((c) => ({ value: c, label: categoryLabel(c) })),
          ]}
        />
      </Space>
      <Table
        rowKey={({ p }) => p.id}
        dataSource={shown}
        size="middle"
        scroll={{ x: 640 }}
        pagination={{ pageSize: 10, hideOnSinglePage: true }}
        locale={{ emptyText: <Empty title="没有符合条件的产品" /> }}
        columns={[
          {
            title: "产品",
            key: "name",
            render: (_, { p }) => (
              <Space orientation="vertical" size={0}>
                <Typography.Text strong>{p.name}</Typography.Text>
                <Typography.Text type="secondary" className="mono" style={{ fontSize: 12 }}>
                  {p.id}
                </Typography.Text>
              </Space>
            ),
          },
          {
            title: "类别",
            key: "category",
            width: 110,
            render: (_, { p }) => <Tag>{categoryLabel(p.category)}</Tag>,
          },
          {
            title: "识别依据",
            key: "match",
            render: (_, { p }) => (
              <Space size={[4, 4]} wrap>
                {counts(p).map(([label, n]) => (
                  <Tag key={label} variant="filled">
                    {label} {n}
                  </Tag>
                ))}
              </Space>
            ),
          },
          {
            title: "操作",
            key: "actions",
            width: 140,
            render: (_, { p, index }) => (
              <Space>
                <Button
                  size="small"
                  type="link"
                  onClick={() => setEditing({ index, product: p })}
                  aria-label={`${readOnly ? "查看" : "编辑"} ${p.name}`}
                >
                  {readOnly ? "查看" : "编辑"}
                </Button>
                {!readOnly && (
                  <Popconfirm
                    title={`删除 ${p.name}？`}
                    description="发布后终端不再检查这个产品。"
                    okText="删除"
                    cancelText="取消"
                    okButtonProps={{ danger: true }}
                    onConfirm={() => onChange(products.filter((_, i) => i !== index))}
                  >
                    <Button size="small" type="link" danger aria-label={`删除 ${p.name}`}>
                      删除
                    </Button>
                  </Popconfirm>
                )}
              </Space>
            ),
          },
        ]}
      />
      {editing && (
        <ProductModal
          initial={editing.product}
          readOnly={readOnly}
          takenIds={products.filter((_, i) => i !== editing.index).map((p) => p.id)}
          onCancel={() => setEditing(null)}
          onSave={(product) => {
            onChange(
              editing.index < 0
                ? [...products, product]
                : products.map((p, i) => (i === editing.index ? product : p)),
            );
            setEditing(null);
          }}
        />
      )}
    </Panel>
  );
}

const listFields: { name: keyof Product; label: string; hint: string; placeholder: string }[] = [
  {
    name: "displayNames",
    label: "安装名称",
    hint: "“应用和功能”里显示的名称，完全一致才算命中。",
    placeholder: "例如 Clash Verge",
  },
  {
    name: "executableNames",
    label: "程序文件名",
    hint: "安装目录或运行进程中的 exe 文件名，不区分大小写。",
    placeholder: "例如 clash-verge.exe",
  },
  {
    name: "packageIds",
    label: "应用商店包名",
    hint: "Microsoft Store 应用的包名（不含版本和发布者后缀）。",
    placeholder: "例如 OpenAI.ChatGPT",
  },
  {
    name: "extensionIds",
    label: "编辑器扩展",
    hint: "VS Code 扩展 ID（发布者.名称）或 JetBrains 插件 ID。",
    placeholder: "例如 github.copilot",
  },
  {
    name: "adapterNames",
    label: "虚拟网卡关键字",
    hint: "该产品创建的虚拟网卡名称或描述中包含的文字，命中后作为线索上报。",
    placeholder: "例如 Mihomo",
  },
  {
    name: "domains",
    label: "相关域名",
    hint: "可在“网络”中一键加入禁止访问的域名。",
    placeholder: "例如 chatgpt.com",
  },
];

function ProductModal({
  initial,
  takenIds,
  readOnly,
  onSave,
  onCancel,
}: {
  initial: Product;
  takenIds: string[];
  readOnly: boolean;
  onSave: (p: Product) => void;
  onCancel: () => void;
}) {
  const [form] = Form.useForm<Product>();
  const [empty, setEmpty] = useState(false);
  const creating = !initial.id;
  return (
    <Modal
      open
      title={creating ? "添加产品" : readOnly ? initial.name : `编辑 ${initial.name}`}
      okText="确定"
      cancelText="取消"
      width={720}
      onCancel={onCancel}
      okButtonProps={{ hidden: readOnly }}
      onOk={() =>
        form.validateFields().then((v) => {
          const none = listFields.every((f) => !(v[f.name] as string[] | undefined)?.length);
          setEmpty(none);
          if (!none) onSave({ ...initial, ...v, id: v.id.trim(), name: v.name.trim() });
        })
      }
      destroyOnHidden
    >
      <Form
        form={form}
        layout="vertical"
        disabled={readOnly}
        initialValues={{ ...emptyProduct, ...initial }}
        requiredMark={false}
      >
        <Row gutter={16}>
          <Col xs={24} sm={12}>
            <Form.Item
              name="name"
              label="产品名称"
              rules={[{ required: true, whitespace: true, message: "请填写产品名称" }]}
            >
              <Input placeholder="例如 Clash / Mihomo" />
            </Form.Item>
          </Col>
          <Col xs={24} sm={12}>
            <Form.Item name="category" label="类别">
              <Select options={categories.map((c) => ({ value: c, label: categoryLabel(c) }))} />
            </Form.Item>
          </Col>
          <Col xs={24}>
            <Form.Item
              name="id"
              label="标识"
              extra="小写字母、数字和短横线，用于告警和报告中区分产品，发布后尽量不要修改。"
              rules={[
                { required: true, message: "请填写标识" },
                {
                  pattern: /^[a-z0-9][a-z0-9._-]{0,63}$/,
                  message: "只能使用小写字母、数字、点、下划线和短横线",
                },
                {
                  validator: (_, v: string) =>
                    takenIds.includes(v?.trim())
                      ? Promise.reject(new Error("已有产品使用这个标识"))
                      : Promise.resolve(),
                },
              ]}
            >
              <Input className="mono" placeholder="例如 clash" />
            </Form.Item>
          </Col>
          {listFields.map((f) => (
            <Col xs={24} sm={12} key={f.name}>
              <Form.Item name={f.name} label={f.label} extra={f.hint}>
                <TagInput label={f.label} placeholder={f.placeholder} />
              </Form.Item>
            </Col>
          ))}
        </Row>
        {!readOnly && (
          <Alert
            type={empty ? "error" : "info"}
            showIcon
            title="每个列表可输入多项：输入后按回车，或用逗号分隔。至少填写一种识别依据。"
          />
        )}
      </Form>
    </Modal>
  );
}
