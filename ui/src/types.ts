export type Verdict = "PASS" | "FAIL" | "UNKNOWN";
export interface Session {
  username: string;
  roles: string[];
  csrfToken: string;
}
export interface DeviceSummary {
  id: string;
  hostName: string;
  lastHeartbeat: string | null;
  onlineState: string;
  currentVerdict: Verdict;
  lastVerdict: Verdict | null;
  lastScan: string | null;
  targetPolicyVersion: number;
  appliedPolicyVersion: number;
  protectionStatus: string;
  violationCount: number;
  simulated: boolean;
  note?: string;
  /** Name of the policy the device follows. */
  policyName?: string;
  /** Client release the device last reported; empty for clients before 0.2.8. */
  agentVersion?: string;
  /** The client is older than this server's release. */
  agentOutdated?: boolean;
}
export interface Evidence {
  productId: string;
  productName: string;
  kind: string;
  objectKey: string;
  source: string;
  summary: string;
  userSid: string | null;
  confirmed: boolean;
}
export interface ModuleResult {
  module: string;
  scope: string;
  status: string;
  collectedAt: string;
  error: string | null;
}
export interface Control {
  id: string;
  version: number;
  state: string;
  detail: string;
  verified: boolean;
  rebootRequired: boolean;
}
export interface Snapshot {
  schemaVersion: number;
  deviceId: string;
  hostName: string;
  platform: string;
  simulated: boolean;
  collectedAt: string;
  policyVersion: number;
  evidence: Evidence[];
  modules: ModuleResult[];
  controls: Control[];
  users?: UserAccount[];
}
export interface UserAccount {
  sid: string;
  name: string;
}
export interface Report {
  verdict: Verdict;
  summary: string;
  reasons: string[];
  coverageGaps: string[];
  sensitiveFileNotes?: string[];
  violationCount: number;
  evidenceCount: number;
  protectionStatus: string;
  snapshot: Snapshot;
}
export interface DeviceDetail {
  device: DeviceSummary;
  snapshot: Snapshot | null;
  controls: Control[];
  pendingCommands: number;
}
export interface Alert {
  id: string;
  deviceId: string;
  hostName: string;
  type: string;
  objectKey: string;
  summary: string;
  state: string;
  lastSequence: number;
  firstSeen: string;
  lastSeen: string;
  acknowledged: boolean;
}
export interface Product {
  id: string;
  name: string;
  category: string;
  packageIds: string[];
  executableNames: string[];
  extensionIds: string[];
  domains: string[];
  displayNames?: string[];
  adapterNames?: string[];
  browserExtensions?: string[];
  npmPackages?: string[];
  pipPackages?: string[];
}
export interface Policy {
  schemaVersion: number;
  policyId: string;
  version: number;
  mode: string;
  targetDeviceIds: string[];
  issuedAt: string;
  expiresAt: string;
  denyInstalled: boolean;
  denyProxy: boolean;
  requiredModules: string[];
  requiredControls: string[];
  quickCheckMinutes?: number;
  fullCheckMinutes?: number;
  inventoryFreshMinutes: number;
  lightweightFreshMinutes: number;
  products: Product[];
  blockDomains: string[];
  approvedNetworkAdapters?: string[];
  sensitiveFiles?: SensitiveFilePolicy;
  applicationRules: {
    productId: string;
    name: string;
    sha256: string;
    type: string;
  }[];
}
export interface SensitiveFileRule {
  id: string;
  name: string;
  keywords: string[];
  extensions: string[];
  matchFolders: boolean;
  /** "Alert" notifies administrators only; "Violation" also makes the device fail. */
  action: "Alert" | "Violation";
}
export interface SensitiveFilePolicy {
  enabled: boolean;
  rules: SensitiveFileRule[];
  scanUserProfiles: boolean;
  scanOtherFixedDrives: boolean;
  excludePaths: string[];
  rescanHours: number;
  maxHitsPerScope: number;
}
export interface SignedPolicy {
  payload: string;
  signature: string;
  keyId: string;
}
export interface Audit {
  id: string;
  actor: string;
  action: string;
  target: string;
  at: string;
}
export interface NotificationSettings {
  enabled: boolean;
  channel: string;
  webhookUrl: string;
  hasSecret: boolean;
  types: string[];
  consoleUrl: string;
}
export interface AppSettings {
  notifications: NotificationSettings;
  /** The last push attempt since the server started. */
  lastNotification: { at: string; ok: boolean; error: string; sent: number } | null;
  /** 0 keeps audit records forever. */
  auditRetentionDays: number;
}
export interface Status {
  version?: string;
  mode: string;
  storage: string;
  networkCapabilities: (
    | { id: string; implemented: boolean; verified: boolean; detail: string }
    | string
  )[];
  policyPublicKeyPem: string;
  policyKeyId: string;
}
export interface PolicyListItem {
  key: string;
  isDefault: boolean;
  release: SignedPolicy;
  /** Devices this policy currently applies to. */
  devices: number;
}

export interface EnrollmentCode {
  id: string;
  label: string;
  expiresAt: string;
  maxUses: number;
  uses: number;
  createdAt: string;
  createdBy: string;
  revoked: boolean;
}
