import { AutoComplete, Select } from "antd";
import type { DeviceSummary } from "../types";

/** Keep in sync with DeviceGroups.MaxLength in src/Compliance.Core/DeviceGroups.cs. */
export const maxGroupLength = 64;

/** The groups devices are in, by name, with how many devices each has. */
export function groupsOf(devices: Pick<DeviceSummary, "group">[]) {
  const counts = new Map<string, number>();
  for (const d of devices) if (d.group) counts.set(d.group, (counts.get(d.group) ?? 0) + 1);
  return [...counts]
    .sort(([a], [b]) => a.localeCompare(b, "zh-CN"))
    .map(([name, count]) => ({ name, count }));
}

/** Picks an existing group or types a new one. */
export function GroupInput({
  value,
  onChange,
  groups,
  label = "分组",
  placeholder = "选择或输入分组，例如 研发部",
  disabled,
}: {
  value: string;
  onChange: (v: string) => void;
  groups: string[];
  label?: string;
  placeholder?: string;
  disabled?: boolean;
}) {
  const typed = value.trim().toLowerCase();
  return (
    <AutoComplete
      aria-label={label}
      value={value}
      onChange={onChange}
      disabled={disabled}
      maxLength={maxGroupLength}
      placeholder={placeholder}
      allowClear
      options={groups
        .filter((g) => g.toLowerCase().includes(typed))
        .map((g) => ({ value: g, label: g }))}
      style={{ width: "100%" }}
    />
  );
}

/** "全部分组", each group with its count, and "未分组" when some devices have none. */
export function GroupFilter({
  devices,
  value,
  onChange,
}: {
  devices: Pick<DeviceSummary, "group">[];
  value: string | null;
  onChange: (v: string | null) => void;
}) {
  const groups = groupsOf(devices);
  if (groups.length === 0) return null;
  const ungrouped = devices.filter((d) => !d.group).length;
  return (
    <Select
      aria-label="筛选分组"
      value={value ?? "*"}
      onChange={(v: string) => onChange(v === "*" ? null : v)}
      style={{ width: 160 }}
      options={[
        { value: "*", label: "全部分组" },
        ...groups.map((g) => ({ value: g.name, label: `${g.name}（${g.count}）` })),
        ...(ungrouped ? [{ value: "", label: `未分组（${ungrouped}）` }] : []),
      ]}
    />
  );
}

/** Whether a device passes a group filter: null shows all, "" the devices without a group. */
export const inGroup = (d: Pick<DeviceSummary, "group">, group: string | null) =>
  group === null || (d.group ?? "") === group;
