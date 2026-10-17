// Shapes of the management API, generated from openapi.json (npm run api). The names here are the UI's own.
import type { components } from "./api.gen";

type Schemas = components["schemas"];

export type Verdict = Schemas["Verdict"];
export type Session = Schemas["SessionInfo"];
export type DeviceSummary = Schemas["DeviceSummary"];
export type NetworkAdapter = Schemas["NetworkAdapter"];
export type Evidence = Schemas["Evidence"];
export type ModuleResult = Schemas["ModuleResult"];
export type Control = Schemas["ControlState"];
export type Snapshot = Schemas["ScanSnapshot"];
export type UserAccount = Schemas["UserAccount"];
export type Report = Schemas["ComplianceReport"];
export type DeviceDetail = Schemas["DeviceDetail"];
export type Alert = Schemas["AlertSummary"];
export type Product = Schemas["ProductRule"];
export type Policy = Schemas["PolicyDocument"];
export type SensitiveFileRule = Schemas["SensitiveFileRule"];
export type SensitiveFilePolicy = Schemas["SensitiveFilePolicy"];
export type SignedPolicy = Schemas["SignedPolicy"];
export type Audit = Schemas["AuditRecord"];
export type NotificationSettings = Schemas["NotificationView"];
export type AppSettings = Schemas["AppSettings"];
export type Status = Schemas["ServerStatus"];
export type PolicyListItem = Schemas["PolicyListItem"];
export type PolicyHistoryItem = Schemas["PolicyHistoryItem"];
export type EnrollmentCode = Schemas["EnrollmentCode"];
export type TrendDay = Schemas["TrendDay"];
export type VerdictChange = Schemas["VerdictChange"];
export type ClientPackage = Schemas["ClientPackageItem"];
export type UpgradeRollout = Schemas["UpgradeRollout"];
export type SigningKeyState = Schemas["SigningKeyState"];
