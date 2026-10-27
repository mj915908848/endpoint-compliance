import type { Policy, SensitiveFilePolicy } from "./types";

// Checks policy JSON pasted into the editor before it reaches the draft: the editor reads these fields directly, so a
// null list or a product without its lists would otherwise fail while rendering. Fields left out keep the draft's.
type Check = (value: unknown, path: string) => string | null;

const isObject = (v: unknown): v is Record<string, unknown> =>
  typeof v === "object" && v !== null && !Array.isArray(v);
const text: Check = (v, path) => (typeof v === "string" ? null : `${path} 应为文本`);
const flag: Check = (v, path) => (typeof v === "boolean" ? null : `${path} 应为 true 或 false`);
const number: Check = (v, path) =>
  typeof v === "number" && Number.isFinite(v) ? null : `${path} 应为数字`;
const texts: Check = (v, path) =>
  Array.isArray(v) && v.every((x) => typeof x === "string") ? null : `${path} 应为文本列表`;
const oneOf =
  (...allowed: string[]): Check =>
  (v, path) =>
    allowed.includes(v as string) ? null : `${path} 只能是 ${allowed.join(" 或 ")}`;

// Required fields must be present; optional ones are checked only when given.
function shape(required: Record<string, Check>, optional: Record<string, Check> = {}): Check {
  return (v, path) => {
    if (!isObject(v)) return `${path} 应为对象`;
    for (const [key, check] of Object.entries(required)) {
      const problem = check(v[key], `${path}.${key}`);
      if (problem) return problem;
    }
    for (const [key, check] of Object.entries(optional))
      if (v[key] !== undefined) {
        const problem = check(v[key], `${path}.${key}`);
        if (problem) return problem;
      }
    return null;
  };
}
const list =
  (item: Check): Check =>
  (v, path) => {
    if (!Array.isArray(v)) return `${path} 应为列表`;
    for (let i = 0; i < v.length; i++) {
      const problem = item(v[i], `${path}[${i}]`);
      if (problem) return problem;
    }
    return null;
  };

const product = shape(
  {
    id: text,
    name: text,
    packageIds: texts,
    executableNames: texts,
    extensionIds: texts,
    domains: texts,
  },
  {
    category: text,
    displayNames: texts,
    adapterNames: texts,
    npmPackages: texts,
    pipPackages: texts,
  },
);
// Settings left out keep the draft's, and rule fields left out take the server's defaults (see withDefaults).
const sensitiveFiles = shape(
  {},
  {
    enabled: flag,
    rules: list(
      shape(
        { id: text, name: text, keywords: texts },
        { extensions: texts, matchFolders: flag, action: oneOf("Alert", "Violation") },
      ),
    ),
    scanUserProfiles: flag,
    scanOtherFixedDrives: flag,
    excludePaths: texts,
    rescanHours: number,
    maxHitsPerScope: number,
  },
);
const baseline = shape(
  {},
  {
    enabled: flag,
    rules: list(
      shape({ id: text }, { action: oneOf("Alert", "Violation"), limit: number, exempt: texts }),
    ),
  },
);
const policy = shape(
  { products: list(product) },
  {
    policyId: text,
    mode: oneOf("Audit", "Enforce"),
    targetDeviceIds: texts,
    targetGroups: texts,
    requiredModules: texts,
    requiredControls: texts,
    quickCheckMinutes: number,
    fullCheckMinutes: number,
    blockDomains: texts,
    approvedNetworkAdapters: texts,
    sensitiveFiles,
    baseline,
    tamper: shape({}, { uninstallPassword: text }),
    applicationRules: list(shape({ productId: text, name: text, sha256: text, type: text })),
  },
);

/** Why the value cannot be applied to the editor, naming the field; null when it can. */
export const policyJsonProblem = (value: unknown): string | null => policy(value, "策略");

/** Merges checked JSON into the draft, filling what the editor needs and the server would default. */
export function withDefaults(draft: Policy, value: Partial<Policy>): Policy {
  const merged = { ...draft, ...value };
  if (value.sensitiveFiles) {
    const files = { ...draft.sensitiveFiles, ...value.sensitiveFiles } as SensitiveFilePolicy;
    merged.sensitiveFiles = {
      ...files,
      rules: (files.rules ?? []).map((r) => ({
        ...r,
        extensions: r.extensions ?? [],
        matchFolders: r.matchFolders ?? true,
        action: r.action ?? "Alert",
      })),
    };
  }
  if (value.baseline) {
    const checks = { ...(draft.baseline ?? { enabled: false, rules: [] }), ...value.baseline };
    merged.baseline = {
      ...checks,
      rules: (checks.rules ?? []).map((r) => ({
        ...r,
        action: r.action ?? "Alert",
        limit: r.limit ?? 0,
        exempt: r.exempt ?? [],
      })),
    };
  }
  if (value.tamper)
    merged.tamper = { ...(draft.tamper ?? { uninstallPassword: "" }), ...value.tamper };
  return merged;
}
