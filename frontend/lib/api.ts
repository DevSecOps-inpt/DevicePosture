import type {
  AdapterConfig,
  AdapterProfileHealth,
  AuditEvent,
  ComplianceDecision,
  ConditionGroup,
  EndpointSummary,
  EnforcementResult,
  IpGroup,
  IpObject,
  PolicyActionType,
  Policy,
  PolicyAssignment,
  ServiceStatus,
  TelemetryRecordResponse
} from "@/types/platform";

function defaultServiceUrl(port: number): string {
  if (typeof window !== "undefined") {
    const protocol = window.location.protocol || "http:";
    const hostname = window.location.hostname || "127.0.0.1";
    return `${protocol}//${hostname}:${port}`;
  }
  return `http://127.0.0.1:${port}`;
}

const TELEMETRY_API_URL = process.env.NEXT_PUBLIC_TELEMETRY_API_URL ?? defaultServiceUrl(8011);
const POLICY_SERVICE_URL = process.env.NEXT_PUBLIC_POLICY_SERVICE_URL ?? defaultServiceUrl(8002);
const EVALUATION_ENGINE_URL = process.env.NEXT_PUBLIC_EVALUATION_ENGINE_URL ?? defaultServiceUrl(8003);
const ENFORCEMENT_SERVICE_URL = process.env.NEXT_PUBLIC_ENFORCEMENT_SERVICE_URL ?? defaultServiceUrl(8004);

async function fetchJson<T>(input: RequestInfo | URL, init?: RequestInit): Promise<T> {
  const response = await fetch(input, {
    ...init,
    headers: {
      ...(init?.body ? { "Content-Type": "application/json" } : {}),
      ...(init?.headers ?? {})
    },
    cache: "no-store"
  });

  if (!response.ok) {
    const detail = await response.text();
    throw new Error(detail || `Request failed with status ${response.status}`);
  }

  if (response.status === 204) {
    return undefined as T;
  }

  return (await response.json()) as T;
}

async function safeFetchStatus(name: string, url: string): Promise<ServiceStatus> {
  try {
    await fetchJson<{ status: string }>(`${url}/healthz`);
    return { name, url, status: "healthy", detail: "Service responding" };
  } catch (error) {
    return {
      name,
      url,
      status: "error",
      detail: error instanceof Error ? error.message : "Health check failed"
    };
  }
}

export const api = {
  urls: {
    telemetry: TELEMETRY_API_URL,
    policy: POLICY_SERVICE_URL,
    evaluation: EVALUATION_ENGINE_URL,
    enforcement: ENFORCEMENT_SERVICE_URL
  },

  listEndpoints() {
    return fetchJson<EndpointSummary[]>(`${TELEMETRY_API_URL}/endpoints`);
  },

  getLatestTelemetry(endpointId: string) {
    return fetchJson<TelemetryRecordResponse>(`${TELEMETRY_API_URL}/endpoints/${endpointId}/latest`);
  },

  getTelemetryHistory(endpointId: string, limit = 20) {
    return fetchJson<TelemetryRecordResponse[]>(`${TELEMETRY_API_URL}/endpoints/${endpointId}/history?limit=${limit}`);
  },

  listPolicies() {
    return fetchJson<Policy[]>(`${POLICY_SERVICE_URL}/policies`);
  },

  getPolicy(policyId: number) {
    return fetchJson<Policy>(`${POLICY_SERVICE_URL}/policies/${policyId}`);
  },

  createPolicy(payload: {
    name: string;
    description: string | null;
    policy_scope?: "posture" | "lifecycle";
    lifecycle_event_type?:
      | "telemetry_received"
      | "inactive_to_active"
      | "active_to_inactive"
      | null;
    target_action: "allow" | "quarantine" | "block";
    is_active: boolean;
    conditions: Array<{ type: string; field: string; operator: string; value: unknown }>;
    execution?: {
      adapter?: string;
      adapter_profile?: string | null;
      object_group?: string | null;
      on_compliant?: Array<{ action_type: PolicyActionType; enabled?: boolean; parameters?: Record<string, unknown> }>;
      on_non_compliant?: Array<{ action_type: PolicyActionType; enabled?: boolean; parameters?: Record<string, unknown> }>;
    } | null;
  }) {
    return fetchJson<Policy>(`${POLICY_SERVICE_URL}/policies`, {
      method: "POST",
      body: JSON.stringify(payload)
    });
  },

  updatePolicy(policyId: number, payload: Partial<Omit<Policy, "id" | "created_at" | "updated_at">>) {
    return fetchJson<Policy>(`${POLICY_SERVICE_URL}/policies/${policyId}`, {
      method: "PUT",
      body: JSON.stringify(payload)
    });
  },

  deletePolicy(policyId: number) {
    return fetchJson<void>(`${POLICY_SERVICE_URL}/policies/${policyId}`, {
      method: "DELETE"
    });
  },

  listAssignments(policyId: number) {
    return fetchJson<PolicyAssignment[]>(`${POLICY_SERVICE_URL}/policies/${policyId}/assignments`);
  },

  createAssignment(policyId: number, payload: { assignment_type: "endpoint" | "group" | "default"; assignment_value: string }) {
    return fetchJson<PolicyAssignment>(`${POLICY_SERVICE_URL}/policies/${policyId}/assignments`, {
      method: "POST",
      body: JSON.stringify(payload)
    });
  },

  listConditionGroups(groupType?: ConditionGroup["group_type"]) {
    const suffix = groupType ? `?group_type=${encodeURIComponent(groupType)}` : "";
    return fetchJson<ConditionGroup[]>(`${POLICY_SERVICE_URL}/condition-groups${suffix}`);
  },

  createConditionGroup(payload: {
    name: string;
    group_type: ConditionGroup["group_type"];
    description: string | null;
    values: string[];
  }) {
    return fetchJson<ConditionGroup>(`${POLICY_SERVICE_URL}/condition-groups`, {
      method: "POST",
      body: JSON.stringify(payload)
    });
  },

  updateConditionGroup(
    groupId: number,
    payload: Partial<{
      name: string;
      group_type: ConditionGroup["group_type"];
      description: string | null;
      values: string[];
    }>
  ) {
    return fetchJson<ConditionGroup>(`${POLICY_SERVICE_URL}/condition-groups/${groupId}`, {
      method: "PUT",
      body: JSON.stringify(payload)
    });
  },

  deleteConditionGroup(groupId: number) {
    return fetchJson<void>(`${POLICY_SERVICE_URL}/condition-groups/${groupId}`, {
      method: "DELETE"
    });
  },

  resolvePolicy(endpointId: string) {
    return fetchJson<Policy | null>(`${POLICY_SERVICE_URL}/policy-match/${endpointId}`);
  },

  evaluateEndpoint(endpointId: string) {
    return fetchJson<ComplianceDecision>(`${EVALUATION_ENGINE_URL}/evaluate/${endpointId}`, {
      method: "POST"
    });
  },

  getLatestDecision(endpointId: string) {
    return fetchJson<ComplianceDecision>(`${EVALUATION_ENGINE_URL}/results/${endpointId}/latest`);
  },

  getDecisionHistory(endpointId: string) {
    return fetchJson<ComplianceDecision[]>(`${EVALUATION_ENGINE_URL}/results/${endpointId}`);
  },

  getLatestEnforcement(endpointId: string) {
    return fetchJson<EnforcementResult>(`${ENFORCEMENT_SERVICE_URL}/enforcement/${endpointId}/latest`);
  },

  listAuditEvents() {
    return fetchJson<AuditEvent[]>(`${ENFORCEMENT_SERVICE_URL}/audit-events`);
  },

  listAdapterConfigs() {
    return fetchJson<AdapterConfig[]>(`${ENFORCEMENT_SERVICE_URL}/adapters`);
  },

  listAdapterHealth() {
    return fetchJson<AdapterProfileHealth[]>(`${ENFORCEMENT_SERVICE_URL}/adapters/health`);
  },

  upsertAdapterConfig(
    name: string,
    payload: {
      adapter?: string;
      is_active?: boolean;
      settings?: Record<string, unknown>;
    }
  ) {
    return fetchJson<AdapterConfig>(`${ENFORCEMENT_SERVICE_URL}/adapters/${name}`, {
      method: "PUT",
      body: JSON.stringify(payload)
    });
  },

  deleteAdapterConfig(name: string) {
    return fetchJson<void>(`${ENFORCEMENT_SERVICE_URL}/adapters/${name}`, {
      method: "DELETE"
    });
  },

  listIpObjects() {
    return fetchJson<Array<{
      object_id: string;
      name: string;
      object_type: string;
      value: string;
      description: string | null;
      managed_by: string;
      created_at: string;
      updated_at: string;
      group_count: number;
    }>>(`${ENFORCEMENT_SERVICE_URL}/objects/ip-objects`);
  },

  createIpObject(payload: { name: string; object_type: "host" | "cidr"; value: string; description: string | null }) {
    return fetchJson(`${ENFORCEMENT_SERVICE_URL}/objects/ip-objects`, {
      method: "POST",
      body: JSON.stringify(payload)
    });
  },

  updateIpObject(objectId: string, payload: { name?: string; object_type?: "host" | "cidr"; value?: string; description?: string | null }) {
    return fetchJson(`${ENFORCEMENT_SERVICE_URL}/objects/ip-objects/${objectId}`, {
      method: "PUT",
      body: JSON.stringify(payload)
    });
  },

  deleteIpObject(objectId: string) {
    return fetchJson<void>(`${ENFORCEMENT_SERVICE_URL}/objects/ip-objects/${objectId}`, {
      method: "DELETE"
    });
  },

  listIpGroups() {
    return fetchJson<Array<{
      group_id: string;
      name: string;
      description: string | null;
      created_at: string;
      updated_at: string;
      member_count: number;
      member_object_ids: string[];
    }>>(`${ENFORCEMENT_SERVICE_URL}/objects/ip-groups`);
  },

  createIpGroup(payload: { name: string; description: string | null }) {
    return fetchJson(`${ENFORCEMENT_SERVICE_URL}/objects/ip-groups`, {
      method: "POST",
      body: JSON.stringify(payload)
    });
  },

  updateIpGroup(groupId: string, payload: { name?: string; description?: string | null }) {
    return fetchJson(`${ENFORCEMENT_SERVICE_URL}/objects/ip-groups/${groupId}`, {
      method: "PUT",
      body: JSON.stringify(payload)
    });
  },

  deleteIpGroup(groupId: string) {
    return fetchJson<void>(`${ENFORCEMENT_SERVICE_URL}/objects/ip-groups/${groupId}`, {
      method: "DELETE"
    });
  },

  addObjectToGroup(groupName: string, objectId: string) {
    return fetchJson<IpGroup>(`${ENFORCEMENT_SERVICE_URL}/objects/ip-groups/${encodeURIComponent(groupName)}/members`, {
      method: "POST",
      body: JSON.stringify({ object_id: objectId })
    });
  },

  removeObjectFromGroup(groupName: string, objectId: string) {
    return fetchJson<IpGroup>(
      `${ENFORCEMENT_SERVICE_URL}/objects/ip-groups/${encodeURIComponent(groupName)}/members/${encodeURIComponent(objectId)}`,
      {
        method: "DELETE"
      }
    );
  },

  quarantineEndpoint(endpointId: string, ipAddress: string, decision?: ComplianceDecision | null) {
    return fetchJson<EnforcementResult>(`${ENFORCEMENT_SERVICE_URL}/actions`, {
      method: "POST",
      body: JSON.stringify({
        adapter: "fortigate",
        action: "quarantine",
        endpoint_id: endpointId,
        ip_address: ipAddress,
        decision: decision ?? {}
      })
    });
  },

  async getServiceHealth() {
    return Promise.all([
      safeFetchStatus("Telemetry API", TELEMETRY_API_URL),
      safeFetchStatus("Policy Service", POLICY_SERVICE_URL),
      safeFetchStatus("Evaluation Engine", EVALUATION_ENGINE_URL),
      safeFetchStatus("Enforcement Service", ENFORCEMENT_SERVICE_URL)
    ]);
  }
};
