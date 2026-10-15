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
  Switch,
  Table,
  Tag,
  Typography,
} from "antd";
import { PlusOutlined } from "@ant-design/icons";
import type {
  DeviceSummary,
  Policy,
  Product,
  SensitiveFilePolicy,
  SensitiveFileRule,
} from "../types";
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
const controls = ["process", "browser"];
/** Earlier policies named measures that were never implemented; show them as the ones that replaced them. */
const currentControls = (ids: string[]) =>
  controls.filter((c) =>
    ids.some((id) => id === c || (c === "process" ? id === "application" : id === "edge")),
  );

/** Matches the server default; policies published before sensitive file scanning omit the section. */
export const defaultSensitiveFiles: SensitiveFilePolicy = {
  enabled: false,
  rules: [],
  scanUserProfiles: true,
  scanOtherFixedDrives: true,
  excludePaths: ["AppData", "$Recycle.Bin", "System Volume Information", "node_modules", ".git"],
  rescanHours: 24,
  maxHitsPerScope: 200,
};
const sensitiveOf = (p: Policy) => p.sensitiveFiles ?? defaultSensitiveFiles;
export const sensitiveActionLabel = (action: string) =>
  action === "Violation" ? "判定违规" : "只告警";
const categories = ["proxy", "ai", "ide_ai"];

/** The part of a policy an administrator edits; the server assigns version and validity on publish. */
const content = ({ schemaVersion, version, issuedAt, expiresAt, ...rest }: Policy) => rest;
export const sameContent = (a: Policy, b: Policy) =>
  JSON.stringify(content(a)) === JSON.stringify(content(b));

const list = (values: string[]) => values.join("、");
const added = (before: string[], after: string[]) => after.filter((x) => !before.includes(x));

/** Plain-language list of what publishing `after` changes compared with `before`. */
/** Quick and full check intervals in minutes; policies published before these settings existed use 5 and 60. */
export const checkMinutes = (p: Policy): [number, number] => [
  p.quickCheckMinutes ?? 5,
  p.fullCheckMinutes ?? 60,
];

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
  const [qb, fb] = checkMinutes(before),
    [qa, fa] = checkMinutes(after);
  if (qb !== qa || fb !== fa)
    changes.push(`检查频率：快速检查每 ${qa} 分钟，完整检查每 ${fa} 分钟`);
  if (JSON.stringify(before.applicationRules) !== JSON.stringify(after.applicationRules))
    changes.push(`应用程序拦截规则：${after.applicationRules.length} 条`);
  const sb = sensitiveOf(before),
    sa = sensitiveOf(after);
  if (sb.enabled !== sa.enabled) changes.push(`敏感文件扫描：${sa.enabled ? "启用" : "停用"}`);
  const ruleName = (rules: SensitiveFileRule[]) => (id: string) =>
    rules.find((r) => r.id === id)?.name ?? id;
  const ruleIds = (x: SensitiveFilePolicy) => x.rules.map((r) => r.id);
  const newRules = added(ruleIds(sb), ruleIds(sa)),
    removedRules = added(ruleIds(sa), ruleIds(sb));
  if (newRules.length) changes.push(`新增敏感文件规则：${list(newRules.map(ruleName(sa.rules)))}`);
  if (removedRules.length)
    changes.push(`删除敏感文件规则：${list(removedRules.map(ruleName(sb.rules)))}`);
  for (const rule of sa.rules) {
    const old = sb.rules.find((r) => r.id === rule.id);
    if (!old || JSON.stringify(old) === JSON.stringify(rule)) continue;
    const plus = added(old.keywords, rule.keywords),
      minus = added(rule.keywords, old.keywords);
    const parts = [
      plus.length ? `新增关键词 ${list(plus)}` : "",
      minus.length ? `移除关键词 ${list(minus)}` : "",
      old.action !== rule.action ? `处理方式改为${sensitiveActionLabel(rule.action)}` : "",
    ].filter(Boolean);
    changes.push(`修改敏感文件规则“${rule.name}”${parts.length ? `：${parts.join("，")}` : ""}`);
  }
  diff("敏感文件排除目录", sb.excludePaths, sa.excludePaths, same);
  if (
    sb.scanUserProfiles !== sa.scanUserProfiles ||
    sb.scanOtherFixedDrives !== sa.scanOtherFixedDrives ||
    sb.rescanHours !== sa.rescanHours ||
    sb.maxHitsPerScope !== sa.maxHitsPerScope
  )
    changes.push(
      `敏感文件扫描范围：${[sa.scanUserProfiles && "用户目录", sa.scanOtherFixedDrives && "其他本地磁盘"].filter(Boolean).join("、") || "未选择"}，每 ${sa.rescanHours} 小时扫描一次，每个范围最多上报 ${sa.maxHitsPerScope} 项`,
    );
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
  isDefault = true,
  takenBy = new Map(),
}: {
  value: Policy;
  onChange: (p: Policy) => void;
  devices: DeviceSummary[];
  readOnly: boolean;
  /** The default policy covers every device no other policy names. */
  isDefault?: boolean;
  /** Devices already named by another policy, with that policy's name. */
  takenBy?: Map<string, string>;
}) {
  const set = (patch: Partial<Policy>) => onChange({ ...value, ...patch });
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
              <Hint>用于在报告和终端上识别这份策略，例如“研发部终端规范”。名称不能重复。</Hint>
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
                  { value: "Enforce", label: "强制模式：检查并拦截", disabled: isDefault },
                ]}
              />
              {isDefault && (
                <Hint>
                  默认策略适用于所有终端，只能使用审计模式；强制模式请新建策略并指定试点终端。
                </Hint>
              )}
              {value.mode === "Enforce" && (
                <Hint>
                  强制模式只能用于指定的试点终端，且这些终端需要在线、已验证所选的防护措施。
                </Hint>
              )}
            </Field>
          </Col>
          <Col xs={24} lg={12}>
            <Field label="适用终端">
              {isDefault ? (
                <Typography.Text>
                  未被其他策略指定的所有终端
                  {devices.length > 0 &&
                    `（当前 ${devices.filter((d) => !takenBy.has(d.id)).length} 台）`}
                </Typography.Text>
              ) : (
                <Select
                  mode="multiple"
                  aria-label="指定终端"
                  style={{ width: "100%" }}
                  placeholder="选择终端，可多选"
                  disabled={readOnly}
                  value={value.targetDeviceIds}
                  onChange={(ids: string[]) => set({ targetDeviceIds: ids })}
                  optionFilterProp="label"
                  options={[
                    ...devices.map((d) => ({
                      value: d.id,
                      label: takenBy.has(d.id)
                        ? `${deviceName(d)}（已在“${takenBy.get(d.id)}”）`
                        : deviceName(d),
                      disabled: takenBy.has(d.id),
                    })),
                    ...value.targetDeviceIds
                      .filter((id) => !devices.some((d) => d.id === id))
                      .map((id) => ({ value: id, label: `${id}（已删除）` })),
                  ]}
                />
              )}
              <Hint>
                {isDefault
                  ? "新注册的终端也使用默认策略。要让部分终端使用不同规则，请新建策略。"
                  : "一台终端只能使用一份策略；未指定的终端使用默认策略。"}
              </Hint>
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

      <SensitiveFilesPanel
        value={sensitiveOf(value)}
        readOnly={readOnly}
        onChange={(sensitiveFiles) => set({ sensitiveFiles })}
      />

      <Panel title="检查要求">
        <Field label="检查频率">
          <Space wrap>
            <span>快速检查每</span>
            <InputNumber
              aria-label="快速检查间隔"
              min={1}
              max={60}
              value={checkMinutes(value)[0]}
              disabled={readOnly}
              onChange={(v) => v && set({ quickCheckMinutes: v })}
              suffix="分钟"
              style={{ width: 120 }}
            />
            <span>，完整检查每</span>
            <InputNumber
              aria-label="完整检查间隔"
              min={10}
              max={1440}
              value={checkMinutes(value)[1]}
              disabled={readOnly}
              onChange={(v) => v && set({ fullCheckMinutes: v })}
              suffix="分钟"
              style={{ width: 130 }}
            />
          </Space>
          {checkMinutes(value)[1] < checkMinutes(value)[0] && (
            <Alert type="warning" showIcon title="完整检查的间隔不能短于快速检查。" />
          )}
          <Hint>
            快速检查：运行中的程序、端口、代理设置；完整检查另外检查已安装软件、扩展和系统服务。超过两个间隔没有新结果时，该项记为“未检查”。发布新策略或点击“请求重新检查”会立即完整检查一次。“发现即结束进程”不受此设置影响，始终每
            2 秒检查。
          </Hint>
        </Field>
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
                value={currentControls(value.requiredControls)}
                disabled={readOnly}
                onChange={(v) => set({ requiredControls: controls.filter((c) => v.includes(c)) })}
                options={controls.map((c) => ({ value: c, label: controlLabel(c) }))}
              />
              <Hint>
                仅在强制模式下执行：“发现即结束进程”每 2
                秒结束一次已核实的禁用程序并通知用户；“浏览器网址拦截”把禁止访问的域名写入 Edge 和
                Chrome 的拦截策略。发布前会核对试点终端已报告“可启用”，生效后报告“已生效”。
              </Hint>
            </Field>
          </Col>
        </Row>
      </Panel>
    </Space>
  );
}

function SensitiveFilesPanel({
  value,
  onChange,
  readOnly,
}: {
  value: SensitiveFilePolicy;
  onChange: (v: SensitiveFilePolicy) => void;
  readOnly: boolean;
}) {
  const set = (patch: Partial<SensitiveFilePolicy>) => onChange({ ...value, ...patch });
  const [editing, setEditing] = useState<{ index: number; rule: SensitiveFileRule } | null>(null);
  const nextId = () => {
    let n = value.rules.length + 1;
    while (value.rules.some((r) => r.id === `rule-${n}`)) n++;
    return `rule-${n}`;
  };
  const noScope = !value.scanUserProfiles && !value.scanOtherFixedDrives;
  // Until scanning is switched on there is nothing else to configure.
  const collapsed = !value.enabled && value.rules.length === 0;
  return (
    <Panel
      title={`敏感文件扫描（${value.rules.length}）`}
      actions={
        !readOnly &&
        !collapsed && (
          <Button
            icon={<PlusOutlined />}
            onClick={() =>
              setEditing({
                index: -1,
                rule: {
                  id: nextId(),
                  name: "",
                  keywords: [],
                  extensions: [],
                  matchFolders: true,
                  action: "Alert",
                },
              })
            }
          >
            添加规则
          </Button>
        )
      }
    >
      <Space orientation="vertical" size={16} style={{ width: "100%" }}>
        <Field label="启用扫描">
          <Switch
            aria-label="启用敏感文件扫描"
            checked={value.enabled}
            disabled={readOnly}
            onChange={(enabled) => set({ enabled })}
          />
          <Hint>
            终端在后台低优先级比对文件和文件夹名称，不读取、不上传文件内容；命中后只通知管理员，不提醒员工。
          </Hint>
          {value.enabled && value.rules.length === 0 && (
            <Alert type="warning" showIcon title="启用扫描需要至少一条规则。" />
          )}
        </Field>
        {!collapsed && (
          <SensitiveFilesSettings
            value={value}
            set={set}
            readOnly={readOnly}
            noScope={noScope}
            onEdit={(index, rule) => setEditing({ index, rule })}
          />
        )}
      </Space>
      {editing && (
        <SensitiveRuleModal
          initial={editing.rule}
          creating={editing.index < 0}
          readOnly={readOnly}
          onCancel={() => setEditing(null)}
          onSave={(rule) => {
            set({
              rules:
                editing.index < 0
                  ? [...value.rules, rule]
                  : value.rules.map((r, i) => (i === editing.index ? rule : r)),
            });
            setEditing(null);
          }}
        />
      )}
    </Panel>
  );
}

function SensitiveFilesSettings({
  value,
  set,
  readOnly,
  noScope,
  onEdit,
}: {
  value: SensitiveFilePolicy;
  set: (patch: Partial<SensitiveFilePolicy>) => void;
  readOnly: boolean;
  noScope: boolean;
  onEdit: (index: number, rule: SensitiveFileRule) => void;
}) {
  return (
    <>
      <Row gutter={[24, 16]}>
        <Col xs={24} lg={12}>
          <Field label="扫描范围">
            <Space orientation="vertical" size={4}>
              <Checkbox
                checked={value.scanUserProfiles}
                disabled={readOnly}
                onChange={(e) => set({ scanUserProfiles: e.target.checked })}
              >
                用户目录（C:\Users 下每个用户）
              </Checkbox>
              <Checkbox
                checked={value.scanOtherFixedDrives}
                disabled={readOnly}
                onChange={(e) => set({ scanOtherFixedDrives: e.target.checked })}
              >
                系统盘以外的本地磁盘（如 D 盘、E 盘）
              </Checkbox>
            </Space>
            {noScope && value.enabled && (
              <Alert type="warning" showIcon title="请至少选择一个扫描范围。" />
            )}
            <Hint>不扫描 U 盘和网络盘；链接到其他位置的文件夹不会进入。</Hint>
          </Field>
        </Col>
        <Col xs={24} lg={12}>
          <Field label="扫描频率与上报数量">
            <Space wrap>
              <span>每</span>
              <InputNumber
                aria-label="敏感文件扫描间隔"
                min={1}
                max={168}
                value={value.rescanHours}
                disabled={readOnly}
                onChange={(v) => v && set({ rescanHours: v })}
                suffix="小时"
                style={{ width: 120 }}
              />
              <span>扫描一次，每个范围最多上报</span>
              <InputNumber
                aria-label="每个范围最多上报"
                min={1}
                max={1000}
                value={value.maxHitsPerScope}
                disabled={readOnly}
                onChange={(v) => v && set({ maxHitsPerScope: v })}
                suffix="项"
                style={{ width: 110 }}
              />
            </Space>
            <Hint>修改规则后终端会立即重新扫描。</Hint>
          </Field>
        </Col>
        <Col xs={24}>
          <Field label="排除目录">
            <TagInput
              label="排除目录"
              value={value.excludePaths}
              disabled={readOnly}
              placeholder="文件夹名称，或完整路径，例如 D:\软件安装包"
              onChange={(excludePaths) => set({ excludePaths })}
            />
            <Hint>
              只写名称时，任何位置的同名文件夹都会跳过；写完整路径时只跳过该目录。Windows、Program
              Files 等系统目录始终跳过。
            </Hint>
          </Field>
        </Col>
      </Row>
      <Table
        rowKey={(r) => r.id}
        dataSource={value.rules}
        size="middle"
        scroll={{ x: 640 }}
        pagination={{ pageSize: 10, hideOnSinglePage: true }}
        locale={{ emptyText: <Empty title="还没有规则" /> }}
        columns={[
          {
            title: "规则",
            key: "name",
            render: (_, r) => <Typography.Text strong>{r.name}</Typography.Text>,
          },
          {
            title: "关键词",
            key: "keywords",
            render: (_, r) => (
              <Space size={[4, 4]} wrap>
                {r.keywords.map((k) => (
                  <Tag key={k}>{k}</Tag>
                ))}
              </Space>
            ),
          },
          {
            title: "匹配",
            key: "match",
            width: 170,
            render: (_, r) =>
              [
                r.extensions.length ? `仅 ${r.extensions.join(" ")}` : "所有文件",
                r.matchFolders && !r.extensions.length ? "含文件夹" : "",
              ]
                .filter(Boolean)
                .join("，"),
          },
          {
            title: "处理方式",
            key: "action",
            width: 110,
            render: (_, r) => (
              <Tag color={r.action === "Violation" ? "error" : "warning"}>
                {sensitiveActionLabel(r.action)}
              </Tag>
            ),
          },
          {
            title: "操作",
            key: "actions",
            width: 140,
            render: (_, r, index) => (
              <Space>
                <Button
                  size="small"
                  type="link"
                  onClick={() => onEdit(index, r)}
                  aria-label={`${readOnly ? "查看" : "编辑"} ${r.name}`}
                >
                  {readOnly ? "查看" : "编辑"}
                </Button>
                {!readOnly && (
                  <Popconfirm
                    title={`删除 ${r.name}？`}
                    description="发布后终端不再按这条规则扫描，相关告警会在下次扫描后解除。"
                    okText="删除"
                    cancelText="取消"
                    okButtonProps={{ danger: true }}
                    onConfirm={() => set({ rules: value.rules.filter((_, i) => i !== index) })}
                  >
                    <Button size="small" type="link" danger aria-label={`删除 ${r.name}`}>
                      删除
                    </Button>
                  </Popconfirm>
                )}
              </Space>
            ),
          },
        ]}
      />
    </>
  );
}

function SensitiveRuleModal({
  initial,
  creating,
  readOnly,
  onSave,
  onCancel,
}: {
  initial: SensitiveFileRule;
  creating: boolean;
  readOnly: boolean;
  onSave: (r: SensitiveFileRule) => void;
  onCancel: () => void;
}) {
  const [form] = Form.useForm<SensitiveFileRule>();
  const extensions = Form.useWatch("extensions", form) as string[] | undefined;
  return (
    <Modal
      open
      title={creating ? "添加敏感文件规则" : readOnly ? initial.name : `编辑 ${initial.name}`}
      okText="确定"
      cancelText="取消"
      width={640}
      onCancel={onCancel}
      okButtonProps={{ hidden: readOnly }}
      onOk={() =>
        form.validateFields().then((v) =>
          onSave({
            ...initial,
            ...v,
            name: v.name.trim(),
            extensions: [
              ...new Set(
                (v.extensions ?? []).map((e) => (e.startsWith(".") ? e : `.${e}`).toLowerCase()),
              ),
            ],
          }),
        )
      }
      destroyOnHidden
    >
      <Form
        form={form}
        layout="vertical"
        disabled={readOnly}
        initialValues={initial}
        requiredMark={false}
      >
        <Form.Item
          name="name"
          label="规则名称"
          rules={[
            { required: true, whitespace: true, message: "请填写规则名称" },
            { max: 64, message: "不超过 64 个字符" },
          ]}
        >
          <Input placeholder="例如 机密文件" />
        </Form.Item>
        <Form.Item
          name="keywords"
          label="关键词"
          extra="文件或文件夹名称包含任一关键词即命中。支持中文，不区分大小写和全角半角。每个 2–64 个字符。"
          rules={[
            {
              validator: (_, v: string[] | undefined) =>
                !v?.length
                  ? Promise.reject(new Error("至少填写一个关键词"))
                  : v.length > 100
                    ? Promise.reject(new Error("最多 100 个关键词"))
                    : v.some((k) => k.length < 2 || k.length > 64)
                      ? Promise.reject(new Error("每个关键词 2–64 个字符"))
                      : Promise.resolve(),
            },
          ]}
        >
          <TagInput label="关键词" placeholder="输入后按回车，例如 机密、工资表、身份证" />
        </Form.Item>
        <Form.Item
          name="extensions"
          label="只匹配这些扩展名"
          extra="留空则匹配所有文件。填写后只检查这些类型的文件，不再匹配文件夹。"
          rules={[
            {
              validator: (_, v: string[] | undefined) =>
                (v ?? []).every((e) => /^\.?[A-Za-z0-9_-]{1,16}$/.test(e))
                  ? Promise.resolve()
                  : Promise.reject(new Error("扩展名格式如 .xlsx")),
            },
          ]}
        >
          <TagInput label="扩展名" placeholder="例如 .xlsx、.docx、.pdf" />
        </Form.Item>
        <Form.Item name="matchFolders" valuePropName="checked">
          <Checkbox disabled={readOnly || !!extensions?.length}>
            同时匹配文件夹名称（命中的文件夹内不再逐个列出同一规则的文件）
          </Checkbox>
        </Form.Item>
        <Form.Item name="action" label="处理方式">
          <Radio.Group
            options={[
              { value: "Alert", label: "只告警：通知管理员，不影响终端结论" },
              { value: "Violation", label: "判定违规：通知管理员，终端结论为“不通过”" },
            ]}
          />
        </Form.Item>
      </Form>
    </Modal>
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
