export type EndpointStatus = "healthy" | "warning" | "critical" | "unknown" | "inactive";
export type EndpointActivityStatus = "active" | "inactive" | "unknown";
export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type IpObjectType = "host" | "cidr";
export type PolicyActionType =
  | "object.add_ip_to_group"
  | "object.remove_ip_from_group"
  | "adapter.add_ip_to_group"
  | "adapter.remove_ip_from_group"
  | "adapter.sync_group"
  | "adapter.post_event"
  | "http.get"
  | "http.post";

export interface EndpointSummary {
  endpoint_id: string;
  hostname: string;
  last_seen: string;
  last_collected_at: string | null;
  expected_interval_seconds: number | null;
  activity_grace_multiplier: number | null;
  activity_timeout_seconds: number | null;
  activity_status: EndpointActivityStatus;
  is_active: boolean | null;
  seconds_since_seen: number | null;
}

export interface TelemetryRecordResponse {
  id: number;
  endpoint_id: string;
  hostname: string;
  collected_at: string;
  source_ip: string | null;
  collector_type: string;
  telemetry_type: string;
  core_ipv4: string | null;
  core_os_name: string | null;
  core_os_version: string | null;
  core_os_build: string | null;
  raw_payload: {
    agent?: {
      name?: string | null;
      interval_seconds?: number | null;
      active_grace_multiplier?: number | null;
      enabled_collectors?: string[];
      transport_enabled?: boolean;
    };
    hotfixes?: Array<{ id: string; description?: string | null; installed_on?: string | null }>;
    services?: Array<{ name: string; display_name?: string | null; status?: string | null; start_type?: string | null }>;
    processes?: Array<{ pid?: number | null; name: string }>;
    antivirus_products?: Array<{ name: string; identifier?: string | null; state?: string | null }>;
    extras?: Record<string, unknown>;
  } & Record<string, unknown>;
}

export interface PolicyCondition {
  type: string;
  field: string;
  operator: string;
  value: unknown;
}

export interface Policy {
  id: number;
  name: string;
  description: string | null;
  policy_scope?: "posture" | "lifecycle";
  lifecycle_event_type?:
    | "telemetry_received"
    | "active_to_inactive"
    | null;
  target_action: "allow" | "quarantine" | "block";
  is_active: boolean;
  conditions: PolicyCondition[];
  execution?: {
    adapter?: string;
    adapter_profile?: string | null;
    object_group?: string | null;
    execution_gate?: {
      ip_group_condition?: {
        enabled?: boolean;
        group_name?: string | null;
        operator?: "exists in" | "does not exist in";
      } | null;
    } | null;
    on_compliant?: Array<{ action_type: PolicyActionType; enabled?: boolean; parameters?: Record<string, unknown> }>;
    on_non_compliant?: Array<{ action_type: PolicyActionType; enabled?: boolean; parameters?: Record<string, unknown> }>;
  } | null;
  created_at: string;
  updated_at: string;
}

export interface PolicyAssignment {
  id?: number | null;
  policy_id: number;
  assignment_type: "endpoint" | "group" | "default";
  assignment_value: string;
}

export interface EvaluationReason {
  check_type: string;
  message: string;
}

export interface ComplianceDecision {
  endpoint_id: string;
  endpoint_ip: string | null;
  policy_id: number | null;
  policy_name: string | null;
  compliant: boolean;
  recommended_action: "allow" | "quarantine" | "block";
  reasons: EvaluationReason[];
  execution_plan?: {
    adapter?: string | null;
    adapter_profile?: string | null;
    object_group?: string | null;
    execution_gate?: {
      ip_group_condition?: {
        enabled?: boolean;
        group_name?: string | null;
        operator?: "exists in" | "does not exist in";
      } | null;
    } | null;
    actions?: Array<{ action_type: PolicyActionType; enabled?: boolean; parameters?: Record<string, unknown> }>;
  };
  evaluated_at: string;
  telemetry_timestamp?: string | null;
}

export interface EnforcementResult {
  adapter: string;
  action: string;
  endpoint_id: string;
  status: string;
  details: Record<string, unknown>;
  completed_at?: string | null;
}

export interface AuditEvent {
  event_type: string;
  endpoint_id: string | null;
  payload: Record<string, unknown>;
  created_at: string;
}

export interface ServiceStatus {
  name: string;
  url: string;
  status: "healthy" | "error";
  detail: string;
}

export interface EndpointView {
  endpointId: string;
  hostname: string;
  status: EndpointStatus;
  activityStatus: EndpointActivityStatus;
  ipAddress: string | null;
  osType: string | null;
  osBuild: string | null;
  lastSeen: string;
  lastCollectedAt: string | null;
  expectedIntervalSeconds: number | null;
  activityTimeoutSeconds: number | null;
  secondsSinceSeen: number | null;
  policyName: string | null;
  policyId: number | null;
  assignedPolicies: Array<{ id: number; name: string }>;
  healthScore: number | null;
  latestTelemetry: TelemetryRecordResponse | null;
  latestDecision: ComplianceDecision | null;
  latestEnforcement: EnforcementResult | null;
}

export interface AlertView {
  id: string;
  title: string;
  severity: Severity;
  source: string;
  relatedResource: string;
  status: "open" | "investigating" | "mitigated" | "closed";
  createdAt: string;
  assignedTo: string;
}

export interface IpObject {
  id: string;
  name: string;
  description: string | null;
  type: IpObjectType;
  value: string;
  createdAt: string;
  updatedAt: string;
}

export interface IpGroup {
  id: string;
  name: string;
  description: string | null;
  memberObjectIds: string[];
  createdAt: string;
  updatedAt: string;
}

export interface AdapterConfig {
  id: number;
  name: string;
  adapter: string;
  is_active: boolean;
  settings: Record<string, unknown>;
  created_at: string;
  updated_at: string;
}

export interface AdapterProfileHealth {
  name: string;
  adapter: string;
  is_active: boolean;
  status: "healthy" | "error" | "disabled" | "unknown";
  detail: string;
  checked_at: string;
}

export interface ConditionGroup {
  id: number;
  name: string;
  group_type: "allowed_os" | "allowed_patches" | "allowed_antivirus_families";
  description: string | null;
  values: string[];
  created_at: string;
  updated_at: string;
}

export type AuthProtocol = "local" | "ldap" | "radius" | "oidc" | "oauth2" | "saml";

export interface AuthProvider {
  id: number;
  name: string;
  protocol: Exclude<AuthProtocol, "local">;
  is_enabled: boolean;
  priority: number;
  settings: Record<string, unknown>;
  created_at: string;
  updated_at: string;
}

export interface ProviderTestResult {
  ok: boolean;
  message: string;
  details: Record<string, unknown>;
}

export interface UserAccount {
  id: number;
  username: string;
  full_name: string | null;
  email: string | null;
  is_active: boolean;
  auth_source: AuthProtocol;
  external_subject: string | null;
  external_groups: string[];
  roles: string[];
  created_at: string;
  updated_at: string;
}

export interface SessionUser {
  username: string;
  full_name: string | null;
  auth_source: AuthProtocol;
  roles: string[];
}

export interface LoginResponse {
  expires_at: string;
  user: SessionUser;
}
