import type {
  AdapterConfig,
  AdapterProfileHealth,
  AuthProvider,
  AuditEvent,
  ComplianceDecision,
  ConditionGroup,
  DirectoryGroup,
  DirectoryGroupSearchResponse,
  EndpointSummary,
  EnforcementResult,
  IpGroup,
  IpObject,
  LoginResponse,
  PolicyActionType,
  Policy,
  PolicyAssignment,
  ProviderTestResult,
  ServiceStatus,
  TelemetryRecordResponse,
  UserAccount,
  SessionUser
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
const SHARED_API_KEY = process.env.NEXT_PUBLIC_POSTURE_API_KEY ?? "";

type FetchJsonOptions = {
  includeCredentials?: boolean;
};

function shouldUsePolicySessionCookie(input: RequestInfo | URL): boolean {
  const rawUrl = typeof input === "string" ? input : input.toString();
  return rawUrl.startsWith(POLICY_SERVICE_URL);
}

async function fetchJson<T>(input: RequestInfo | URL, init?: RequestInit, options?: FetchJsonOptions): Promise<T> {
  const authHeaders =
    SHARED_API_KEY.trim().length > 0 ? ({ "X-API-Key": SHARED_API_KEY.trim() } as Record<string, string>) : {};
  const includeCredentials = options?.includeCredentials ?? shouldUsePolicySessionCookie(input);
  const response = await fetch(input, {
    ...init,
    headers: {
      ...authHeaders,
      ...(init?.body ? { "Content-Type": "application/json" } : {}),
      ...(init?.headers ?? {})
    },
    credentials: includeCredentials ? "include" : "same-origin",
    cache: "no-store"
  });

  if (!response.ok) {
    const raw = await response.text();
    if (raw && response.status < 500) {
      try {
        const parsed = JSON.parse(raw) as { detail?: unknown; message?: unknown };
        const detail =
          typeof parsed.detail === "string"
            ? parsed.detail
            : typeof parsed.message === "string"
              ? parsed.message
              : null;
        throw new Error(detail ?? "Request failed");
      } catch {
        throw new Error("Request failed");
      }
    }
    if (response.status >= 500) {
      throw new Error(`Server error (${response.status}). Please check backend logs for details.`);
    }
    throw new Error(`Request failed with status ${response.status}`);
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

  getLatestTelemetryBatch(endpointIds: string[], options?: { includeRaw?: boolean }) {
    if (endpointIds.length === 0) {
      return Promise.resolve([] as TelemetryRecordResponse[]);
    }
    const params = new URLSearchParams();
    endpointIds.forEach((endpointId) => params.append("endpoint_id", endpointId));
    params.set("include_raw", options?.includeRaw ? "true" : "false");
    return fetchJson<TelemetryRecordResponse[]>(`${TELEMETRY_API_URL}/endpoints/latest-batch?${params.toString()}`);
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

  getEndpointAssignedPolicies(endpointId: string) {
    return fetchJson<Array<{
      policy_id: number;
      policy_name: string;
      policy_scope: "posture" | "lifecycle";
      lifecycle_event_type: "telemetry_received" | "active_to_inactive" | null;
      assignment_type: "endpoint" | "group" | "default";
      assignment_value: string;
    }>>(`${POLICY_SERVICE_URL}/endpoints/${endpointId}/assigned-policies`);
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
      | "active_to_inactive"
      | null;
    target_action: "allow" | "quarantine" | "block";
    is_active: boolean;
    conditions: Array<{ type: string; field: string; operator: string; value: unknown }>;
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

  resolvePolicyBatch(endpointIds: string[], groups: string[] = []) {
    if (endpointIds.length === 0) {
      return Promise.resolve({} as Record<string, Policy | null>);
    }
    const params = new URLSearchParams();
    endpointIds.forEach((endpointId) => params.append("endpoint_id", endpointId));
    groups.forEach((group) => params.append("groups", group));
    return fetchJson<Record<string, Policy | null>>(`${POLICY_SERVICE_URL}/policy-match-batch?${params.toString()}`);
  },

  getEndpointAssignedPoliciesBatch(endpointIds: string[]) {
    if (endpointIds.length === 0) {
      return Promise.resolve(
        {} as Record<
          string,
          Array<{
            policy_id: number;
            policy_name: string;
            policy_scope: "posture" | "lifecycle";
            lifecycle_event_type: "telemetry_received" | "active_to_inactive" | null;
            assignment_type: "endpoint" | "group" | "default";
            assignment_value: string;
          }>
        >
      );
    }
    const params = new URLSearchParams();
    endpointIds.forEach((endpointId) => params.append("endpoint_id", endpointId));
    return fetchJson<
      Record<
        string,
        Array<{
          policy_id: number;
          policy_name: string;
          policy_scope: "posture" | "lifecycle";
          lifecycle_event_type: "telemetry_received" | "active_to_inactive" | null;
          assignment_type: "endpoint" | "group" | "default";
          assignment_value: string;
        }>
      >
    >(`${POLICY_SERVICE_URL}/endpoints/assigned-policies-batch?${params.toString()}`);
  },

  evaluateEndpoint(endpointId: string) {
    return fetchJson<ComplianceDecision>(`${EVALUATION_ENGINE_URL}/evaluate/${endpointId}`, {
      method: "POST"
    });
  },

  getLatestDecision(endpointId: string) {
    return fetchJson<ComplianceDecision>(`${EVALUATION_ENGINE_URL}/results/${endpointId}/latest`);
  },

  getLatestDecisionBatch(endpointIds: string[]) {
    if (endpointIds.length === 0) {
      return Promise.resolve({} as Record<string, ComplianceDecision | null>);
    }
    const params = new URLSearchParams();
    endpointIds.forEach((endpointId) => params.append("endpoint_id", endpointId));
    return fetchJson<Record<string, ComplianceDecision | null>>(`${EVALUATION_ENGINE_URL}/results/latest-batch?${params.toString()}`);
  },

  getDecisionHistory(endpointId: string) {
    return fetchJson<ComplianceDecision[]>(`${EVALUATION_ENGINE_URL}/results/${endpointId}`);
  },

  getLatestEnforcement(endpointId: string) {
    return fetchJson<EnforcementResult>(`${ENFORCEMENT_SERVICE_URL}/enforcement/${endpointId}/latest`);
  },

  getLatestEnforcementBatch(endpointIds: string[]) {
    if (endpointIds.length === 0) {
      return Promise.resolve({} as Record<string, EnforcementResult | null>);
    }
    const params = new URLSearchParams();
    endpointIds.forEach((endpointId) => params.append("endpoint_id", endpointId));
    return fetchJson<Record<string, EnforcementResult | null>>(
      `${ENFORCEMENT_SERVICE_URL}/enforcement/latest-batch?${params.toString()}`
    );
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
  },

  login(payload: { username: string; password: string }) {
    return fetchJson<LoginResponse>(`${POLICY_SERVICE_URL}/auth/login`, {
      method: "POST",
      body: JSON.stringify(payload)
    });
  },

  getCurrentSessionUser() {
    return fetchJson<SessionUser>(`${POLICY_SERVICE_URL}/auth/me`);
  },

  logout() {
    return fetchJson<{ status: string }>(`${POLICY_SERVICE_URL}/auth/logout`, {
      method: "POST"
    });
  },

  listAuthProviders() {
    return fetchJson<AuthProvider[]>(`${POLICY_SERVICE_URL}/auth/providers`);
  },

  listEnabledAuthProviders() {
    return fetchJson<AuthProvider[]>(`${POLICY_SERVICE_URL}/auth/providers/enabled`);
  },

  createAuthProvider(payload: {
    name: string;
    protocol: "ldap" | "radius" | "oidc" | "oauth2" | "saml";
    is_enabled: boolean;
    priority: number;
    settings: Record<string, unknown>;
  }) {
    return fetchJson<AuthProvider>(`${POLICY_SERVICE_URL}/auth/providers`, {
      method: "POST",
      body: JSON.stringify(payload)
    });
  },

  updateAuthProvider(
    providerId: number,
    payload: Partial<{
      name: string;
      protocol: "ldap" | "radius" | "oidc" | "oauth2" | "saml";
      is_enabled: boolean;
      priority: number;
      settings: Record<string, unknown>;
    }>
  ) {
    return fetchJson<AuthProvider>(`${POLICY_SERVICE_URL}/auth/providers/${providerId}`, {
      method: "PUT",
      body: JSON.stringify(payload)
    });
  },

  deleteAuthProvider(providerId: number) {
    return fetchJson<void>(`${POLICY_SERVICE_URL}/auth/providers/${providerId}`, {
      method: "DELETE"
    });
  },

  testAuthProviderConnectivity(providerId: number) {
    return fetchJson<ProviderTestResult>(`${POLICY_SERVICE_URL}/auth/providers/${providerId}/test-connectivity`, {
      method: "POST"
    });
  },

  testAuthProviderCredentials(providerId: number, payload: { username: string; password: string }) {
    return fetchJson<ProviderTestResult>(`${POLICY_SERVICE_URL}/auth/providers/${providerId}/test-credentials`, {
      method: "POST",
      body: JSON.stringify(payload)
    });
  },

  listAuthProviderDirectoryGroups(
    providerId: number,
    options?: { computerOnly?: boolean; sync?: boolean }
  ) {
    const params = new URLSearchParams();
    if (options?.computerOnly) {
      params.set("computer_only", "true");
    }
    if (options?.sync) {
      params.set("sync", "true");
    }
    const suffix = params.toString() ? `?${params.toString()}` : "";
    return fetchJson<DirectoryGroup[]>(`${POLICY_SERVICE_URL}/auth/providers/${providerId}/directory-groups${suffix}`);
  },

  syncAuthProviderDirectoryGroups(providerId: number) {
    return fetchJson<DirectoryGroup[]>(`${POLICY_SERVICE_URL}/auth/providers/${providerId}/directory-groups/sync`, {
      method: "POST"
    });
  },

  searchAuthProviderDirectoryGroups(
    providerId: number,
    payload: {
      ldap_filter: string;
      search?: string | null;
      search_base?: string | null;
      limit?: number;
      computer_only?: boolean;
      persist?: boolean;
    }
  ) {
    return fetchJson<DirectoryGroupSearchResponse>(`${POLICY_SERVICE_URL}/auth/providers/${providerId}/directory-groups/search`, {
      method: "POST",
      body: JSON.stringify(payload)
    });
  },

  listLdapDirectoryGroups(options?: { computerOnly?: boolean; providerIds?: number[] }) {
    const params = new URLSearchParams();
    if (options?.computerOnly) {
      params.set("computer_only", "true");
    }
    for (const providerId of options?.providerIds ?? []) {
      params.append("provider_id", String(providerId));
    }
    const suffix = params.toString() ? `?${params.toString()}` : "";
    return fetchJson<DirectoryGroup[]>(`${POLICY_SERVICE_URL}/auth/directory-groups/ldap${suffix}`);
  },

  listUsers() {
    return fetchJson<UserAccount[]>(`${POLICY_SERVICE_URL}/admin/users`);
  },

  createUser(payload: {
    username: string;
    full_name: string | null;
    email: string | null;
    is_active: boolean;
    auth_source: "local" | "ldap" | "radius" | "oidc" | "oauth2" | "saml";
    external_provider_id?: number | null;
    password?: string | null;
    external_subject?: string | null;
    external_groups?: string[];
    roles?: string[];
  }) {
    return fetchJson<UserAccount>(`${POLICY_SERVICE_URL}/admin/users`, {
      method: "POST",
      body: JSON.stringify(payload)
    });
  },

  updateUser(
    userId: number,
    payload: Partial<{
      full_name: string | null;
      email: string | null;
      is_active: boolean;
      external_provider_id: number | null;
      password: string;
      external_subject: string | null;
      external_groups: string[];
      roles: string[];
    }>
  ) {
    return fetchJson<UserAccount>(`${POLICY_SERVICE_URL}/admin/users/${userId}`, {
      method: "PUT",
      body: JSON.stringify(payload)
    });
  },

  deleteUser(userId: number) {
    return fetchJson<void>(`${POLICY_SERVICE_URL}/admin/users/${userId}`, {
      method: "DELETE"
    });
  }
};
