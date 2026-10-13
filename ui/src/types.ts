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
}
export interface Report {
  verdict: Verdict;
  summary: string;
  reasons: string[];
  coverageGaps: string[];
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
  inventoryFreshMinutes: number;
  lightweightFreshMinutes: number;
  products: Product[];
  blockDomains: string[];
  applicationRules: {
    productId: string;
    name: string;
    sha256: string;
    type: string;
  }[];
}
export interface Draft {
  id: string;
  document: Policy;
  createdBy: string;
  approvedBy: string | null;
  published: boolean;
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
export interface Status {
  mode: string;
  storage: string;
  networkCapabilities: (
    | { id: string; implemented: boolean; verified: boolean; detail: string }
    | string
  )[];
  policyPublicKeyPem: string;
  policyKeyId: string;
}
