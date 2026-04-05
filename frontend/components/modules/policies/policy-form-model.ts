import type { Policy, PolicyActionType, PolicyCondition } from "@/types/platform";

export type PolicyType = "posture" | "telemetry_received" | "inactive_to_active" | "active_to_inactive";
export type MembershipOperator = "exists in" | "does not exist in" | "contains";
export type NumericOperator =
  | "greater than"
  | "greater than or equal"
  | "less than"
  | "less than or equal";
export type GroupAction = "none" | "add" | "remove";
export type AdapterAction = "none" | "push_group" | "add_ip" | "remove_ip";
export type ExecutionIpGroupOperator = "exists in" | "does not exist in";

export const MEMBERSHIP_OPERATORS: MembershipOperator[] = ["exists in", "does not exist in", "contains"];
export const NUMERIC_OPERATORS: NumericOperator[] = [
  "greater than",
  "greater than or equal",
  "less than",
  "less than or equal"
];

export const OS_NAME_SUGGESTIONS = [
  "Microsoft Windows 11 Pro",
  "Microsoft Windows 11 Enterprise",
  "Microsoft Windows 10 Pro",
  "Microsoft Windows 10 Enterprise"
];

export const ANTIVIRUS_FAMILY_SUGGESTIONS = [
  "microsoft_defender",
  "crowdstrike",
  "sentinelone",
  "sophos",
  "mcafee",
  "bitdefender",
  "kaspersky",
  "trend_micro",
  "eset",
  "symantec"
];

export const ANTIVIRUS_STATUS_SUGGESTIONS = ["running", "enabled", "stopped", "disabled", "unknown"];

export type PolicyEditorState = {
  name: string;
  description: string;
  policyType: PolicyType;
  targetAction: "allow" | "quarantine" | "block";
  isActive: boolean;
  conditions: {
    osNameEnabled: boolean;
    osNameOperator: MembershipOperator;
    osNameValues: string;
    osNameGroupId: number | "";
    osBuildEnabled: boolean;
    osBuildOperator: NumericOperator;
    osBuildValue: string;
    patchesEnabled: boolean;
    patchesOperator: MembershipOperator;
    patchesValues: string;
    patchesGroupId: number | "";
    antivirusFamilyEnabled: boolean;
    antivirusFamilyOperator: MembershipOperator;
    antivirusFamilyValues: string;
    antivirusFamilyGroupId: number | "";
    antivirusStatusEnabled: boolean;
    antivirusStatusOperator: MembershipOperator;
    antivirusStatusValues: string;
    domainMembershipEnabled: boolean;
    domainMembershipOperator: MembershipOperator;
    domainLdapProviderId: number | "";
  };
  execution: {
    adapter: string;
    adapterProfile: string;
    objectGroup: string;
    objectOnCompliant: GroupAction;
    objectOnNonCompliant: GroupAction;
    adapterOnCompliant: AdapterAction;
    adapterOnNonCompliant: AdapterAction;
    gateEnabled: boolean;
    gateGroupName: string;
    gateOperator: ExecutionIpGroupOperator;
  };
};

export function defaultPolicyEditorState(): PolicyEditorState {
  return {
    name: "",
    description: "",
    policyType: "posture",
    targetAction: "quarantine",
    isActive: true,
    conditions: {
      osNameEnabled: true,
      osNameOperator: "exists in",
      osNameValues: "Microsoft Windows 11 Pro",
      osNameGroupId: "",
      osBuildEnabled: true,
      osBuildOperator: "greater than or equal",
      osBuildValue: "26100",
      patchesEnabled: true,
      patchesOperator: "exists in",
      patchesValues: "",
      patchesGroupId: "",
      antivirusFamilyEnabled: true,
      antivirusFamilyOperator: "exists in",
      antivirusFamilyValues: "microsoft_defender",
      antivirusFamilyGroupId: "",
      antivirusStatusEnabled: true,
      antivirusStatusOperator: "exists in",
      antivirusStatusValues: "running",
      domainMembershipEnabled: false,
      domainMembershipOperator: "exists in",
      domainLdapProviderId: ""
    },
    execution: {
      adapter: "fortigate",
      adapterProfile: "",
      objectGroup: "NON_COMPLIANT_ENDPOINTS",
      objectOnCompliant: "remove",
      objectOnNonCompliant: "add",
      adapterOnCompliant: "none",
      adapterOnNonCompliant: "push_group",
      gateEnabled: false,
      gateGroupName: "",
      gateOperator: "exists in"
    }
  };
}

function splitValues(input: string): string[] {
  return input
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

function joinValues(values: unknown): string {
  if (Array.isArray(values)) {
    return values
      .map((item) => String(item).trim())
      .filter(Boolean)
      .join(", ");
  }
  if (typeof values === "string") {
    return values;
  }
  return "";
}

function executionAction(
  actionType: PolicyActionType,
  objectGroup: string,
  extraParameters: Record<string, unknown> = {}
) {
  return {
    action_type: actionType,
    enabled: true,
    parameters: {
      ...(objectGroup ? { group_name: objectGroup } : {}),
      ...extraParameters
    }
  };
}

function resolveGroupAction(
  actions: Array<{ action_type: PolicyActionType; parameters?: Record<string, unknown> }>,
  addType: PolicyActionType,
  removeType: PolicyActionType
): GroupAction {
  if (actions.some((item) => item.action_type === addType)) {
    return "add";
  }
  if (actions.some((item) => item.action_type === removeType)) {
    return "remove";
  }
  return "none";
}

function resolveAdapterAction(
  actions: Array<{ action_type: PolicyActionType; parameters?: Record<string, unknown> }>
): AdapterAction {
  if (actions.some((item) => item.action_type === "adapter.sync_group")) {
    return "push_group";
  }
  if (actions.some((item) => item.action_type === "adapter.add_ip_to_group")) {
    return "add_ip";
  }
  if (actions.some((item) => item.action_type === "adapter.remove_ip_from_group")) {
    return "remove_ip";
  }
  return "none";
}

function parseGroupId(value: unknown): number | "" {
  if (typeof value === "number" && Number.isInteger(value)) {
    return value;
  }
  if (typeof value === "string" && /^\d+$/.test(value.trim())) {
    return Number.parseInt(value.trim(), 10);
  }
  return "";
}

function normalizeMembershipOperator(operator: string | undefined): MembershipOperator {
  const value = (operator ?? "").trim().toLowerCase();
  if (value === "does not exist in" || value === "does_not_exist_in" || value === "not_in") {
    return "does not exist in";
  }
  if (value === "contains" || value === "contains_all" || value === "contains all") {
    return "contains";
  }
  return "exists in";
}

function normalizeNumericOperator(operator: string | undefined): NumericOperator {
  const value = (operator ?? "").trim().toLowerCase();
  if (value === "greater than" || value === ">" || value === "gt") {
    return "greater than";
  }
  if (value === "less than" || value === "<" || value === "lt") {
    return "less than";
  }
  if (value === "less than or equal" || value === "<=" || value === "lte") {
    return "less than or equal";
  }
  return "greater than or equal";
}

export function policyToEditorState(policy: Policy): PolicyEditorState {
  const state = emptyPolicyEditorStateForExistingPolicy();
  state.name = policy.name;
  state.description = policy.description ?? "";
  state.policyType =
    policy.policy_scope === "lifecycle"
      ? (policy.lifecycle_event_type as Exclude<PolicyType, "posture"> | null) ?? "telemetry_received"
      : "posture";
  state.targetAction = policy.target_action;
  state.isActive = policy.is_active;

  for (const condition of policy.conditions ?? []) {
    if (condition.type === "os_version" && (condition.field === "os.name" || condition.field === "os")) {
      state.conditions.osNameEnabled = true;
      state.conditions.osNameOperator = normalizeMembershipOperator(condition.operator);
      if (typeof condition.value === "object" && condition.value !== null) {
        const raw = condition.value as Record<string, unknown>;
        state.conditions.osNameGroupId = parseGroupId(raw.group_id);
        state.conditions.osNameValues = joinValues(raw.values) || joinValues(raw.name);
      } else {
        state.conditions.osNameValues = joinValues(condition.value);
      }
      continue;
    }
    if (
      condition.type === "os_version" &&
      (condition.field === "os.build" || condition.field === "os.version" || condition.field === "build")
    ) {
      state.conditions.osBuildEnabled = true;
      state.conditions.osBuildOperator = normalizeNumericOperator(condition.operator);
      if (typeof condition.value === "object" && condition.value !== null) {
        const raw = condition.value as Record<string, unknown>;
        state.conditions.osBuildValue = String(raw.min_build ?? raw.build ?? raw.version ?? "");
      } else {
        state.conditions.osBuildValue = String(condition.value ?? "");
      }
      continue;
    }
    if (condition.type === "required_kbs") {
      state.conditions.patchesEnabled = true;
      state.conditions.patchesOperator = normalizeMembershipOperator(condition.operator);
      if (typeof condition.value === "object" && condition.value !== null) {
        const raw = condition.value as Record<string, unknown>;
        state.conditions.patchesGroupId = parseGroupId(raw.group_id);
        state.conditions.patchesValues = joinValues(raw.values) || joinValues(raw.required_kbs) || joinValues(raw.kbs);
      } else {
        state.conditions.patchesValues = joinValues(condition.value);
      }
      continue;
    }
    if (
      condition.type === "allowed_antivirus" &&
      (condition.field === "antivirus.status" || condition.field === "av.status")
    ) {
      state.conditions.antivirusStatusEnabled = true;
      state.conditions.antivirusStatusOperator = normalizeMembershipOperator(condition.operator);
      if (typeof condition.value === "object" && condition.value !== null) {
        const raw = condition.value as Record<string, unknown>;
        state.conditions.antivirusStatusValues = joinValues(raw.values) || joinValues(raw.status) || joinValues(raw.states);
      } else {
        state.conditions.antivirusStatusValues = joinValues(condition.value);
      }
      continue;
    }
    if (
      condition.type === "allowed_antivirus" &&
      (condition.field === "antivirus.family" || condition.field === "av.family")
    ) {
      state.conditions.antivirusFamilyEnabled = true;
      state.conditions.antivirusFamilyOperator = normalizeMembershipOperator(condition.operator);
      if (typeof condition.value === "object" && condition.value !== null) {
        const raw = condition.value as Record<string, unknown>;
        state.conditions.antivirusFamilyGroupId = parseGroupId(raw.group_id);
        state.conditions.antivirusFamilyValues =
          joinValues(raw.values) || joinValues(raw.identifiers) || joinValues(raw.families);
      } else {
        state.conditions.antivirusFamilyValues = joinValues(condition.value);
      }
      continue;
    }
    if (condition.type === "allowed_antivirus") {
      state.conditions.antivirusFamilyEnabled = true;
      state.conditions.antivirusFamilyOperator = normalizeMembershipOperator(condition.operator);
      state.conditions.antivirusFamilyValues = joinValues(condition.value);
      continue;
    }

    if (condition.type === "domain_membership") {
      state.conditions.domainMembershipEnabled = true;
      state.conditions.domainMembershipOperator = normalizeMembershipOperator(condition.operator);
      if (typeof condition.value === "object" && condition.value !== null) {
        const raw = condition.value as Record<string, unknown>;
        state.conditions.domainLdapProviderId = parseGroupId(raw.provider_id);
      }
      continue;
    }

    if (condition.type === "os_version" && typeof condition.value === "object" && condition.value !== null) {
      const raw = condition.value as Record<string, unknown>;
      if (typeof raw.name === "string" && raw.name.trim()) {
        state.conditions.osNameEnabled = true;
        state.conditions.osNameValues = raw.name;
        state.conditions.osNameOperator = "exists in";
      }
      const buildCandidate = raw.min_build ?? raw.build ?? raw.version;
      if (buildCandidate !== undefined && buildCandidate !== null) {
        state.conditions.osBuildEnabled = true;
        state.conditions.osBuildValue = String(buildCandidate);
        state.conditions.osBuildOperator = "greater than or equal";
      }
    }
  }

  const execution = policy.execution;
  if (execution) {
    const onCompliant = execution.on_compliant ?? [];
    const onNonCompliant = execution.on_non_compliant ?? [];
    state.execution.adapter = execution.adapter ?? "fortigate";
    state.execution.adapterProfile = execution.adapter_profile ?? "";
    state.execution.objectGroup = execution.object_group ?? "";
    state.execution.objectOnCompliant = resolveGroupAction(
      onCompliant,
      "object.add_ip_to_group",
      "object.remove_ip_from_group"
    );
    state.execution.objectOnNonCompliant = resolveGroupAction(
      onNonCompliant,
      "object.add_ip_to_group",
      "object.remove_ip_from_group"
    );
    state.execution.adapterOnCompliant = resolveAdapterAction(onCompliant);
    state.execution.adapterOnNonCompliant = resolveAdapterAction(onNonCompliant);
    const gate = execution.execution_gate?.ip_group_condition;
    if (gate) {
      state.execution.gateEnabled = Boolean(gate.enabled);
      state.execution.gateGroupName = String(gate.group_name ?? "");
      state.execution.gateOperator =
        gate.operator === "does not exist in" ? "does not exist in" : "exists in";
    }
  }

  return state;
}

export function buildPolicyConditions(state: PolicyEditorState): PolicyCondition[] {
  const conditions: PolicyCondition[] = [];

  if (state.conditions.osNameEnabled) {
    const values = splitValues(state.conditions.osNameValues);
    if (state.conditions.osNameGroupId !== "") {
      conditions.push({
        type: "os_version",
        field: "os.name",
        operator: state.conditions.osNameOperator,
        value: {
          group_id: state.conditions.osNameGroupId,
          group_type: "allowed_os"
        }
      });
    } else if (values.length > 0) {
      conditions.push({
        type: "os_version",
        field: "os.name",
        operator: state.conditions.osNameOperator,
        value: values
      });
    }
  }

  if (state.conditions.osBuildEnabled) {
    const buildValue = state.conditions.osBuildValue.trim();
    if (buildValue) {
      conditions.push({
        type: "os_version",
        field: "os.build",
        operator: state.conditions.osBuildOperator,
        value: buildValue
      });
    }
  }

  if (state.conditions.patchesEnabled) {
    const values = splitValues(state.conditions.patchesValues);
    if (state.conditions.patchesGroupId !== "") {
      conditions.push({
        type: "required_kbs",
        field: "hotfixes",
        operator: state.conditions.patchesOperator,
        value: {
          group_id: state.conditions.patchesGroupId,
          group_type: "allowed_patches"
        }
      });
    } else if (values.length > 0) {
      conditions.push({
        type: "required_kbs",
        field: "hotfixes",
        operator: state.conditions.patchesOperator,
        value: values
      });
    }
  }

  if (state.conditions.antivirusFamilyEnabled) {
    const values = splitValues(state.conditions.antivirusFamilyValues);
    if (state.conditions.antivirusFamilyGroupId !== "") {
      conditions.push({
        type: "allowed_antivirus",
        field: "antivirus.family",
        operator: state.conditions.antivirusFamilyOperator,
        value: {
          group_id: state.conditions.antivirusFamilyGroupId,
          group_type: "allowed_antivirus_families"
        }
      });
    } else if (values.length > 0) {
      conditions.push({
        type: "allowed_antivirus",
        field: "antivirus.family",
        operator: state.conditions.antivirusFamilyOperator,
        value: values
      });
    }
  }

  if (state.conditions.antivirusStatusEnabled) {
    const values = splitValues(state.conditions.antivirusStatusValues);
    if (values.length > 0) {
      conditions.push({
        type: "allowed_antivirus",
        field: "antivirus.status",
        operator: state.conditions.antivirusStatusOperator,
        value: values
      });
    }
  }

  if (state.conditions.domainMembershipEnabled && state.conditions.domainLdapProviderId !== "") {
    conditions.push({
      type: "domain_membership",
      field: "domain.joined",
      operator: state.conditions.domainMembershipOperator,
      value: {
        provider_id: state.conditions.domainLdapProviderId
      }
    });
  }

  return conditions;
}

export function buildPolicyExecution(state: PolicyEditorState): NonNullable<Policy["execution"]> {
  const onCompliant: Array<{ action_type: PolicyActionType; enabled: boolean; parameters: Record<string, unknown> }> =
    [];
  const onNonCompliant: Array<{
    action_type: PolicyActionType;
    enabled: boolean;
    parameters: Record<string, unknown>;
  }> = [];
  const objectGroup = state.execution.objectGroup.trim();

  if (state.execution.objectOnCompliant === "add") {
    onCompliant.push(executionAction("object.add_ip_to_group", objectGroup));
  }
  if (state.execution.objectOnCompliant === "remove") {
    onCompliant.push(executionAction("object.remove_ip_from_group", objectGroup));
  }
  if (state.execution.objectOnNonCompliant === "add") {
    onNonCompliant.push(executionAction("object.add_ip_to_group", objectGroup));
  }
  if (state.execution.objectOnNonCompliant === "remove") {
    onNonCompliant.push(executionAction("object.remove_ip_from_group", objectGroup));
  }

  if (state.execution.adapterOnCompliant === "push_group") {
    onCompliant.push(executionAction("adapter.sync_group", objectGroup));
  } else if (state.execution.adapterOnCompliant === "add_ip") {
    onCompliant.push(executionAction("adapter.add_ip_to_group", objectGroup));
  } else if (state.execution.adapterOnCompliant === "remove_ip") {
    onCompliant.push(executionAction("adapter.remove_ip_from_group", objectGroup));
  }
  if (state.execution.adapterOnNonCompliant === "push_group") {
    onNonCompliant.push(executionAction("adapter.sync_group", objectGroup));
  } else if (state.execution.adapterOnNonCompliant === "add_ip") {
    onNonCompliant.push(executionAction("adapter.add_ip_to_group", objectGroup));
  } else if (state.execution.adapterOnNonCompliant === "remove_ip") {
    onNonCompliant.push(executionAction("adapter.remove_ip_from_group", objectGroup));
  }

  return {
    adapter: state.execution.adapter.trim() || "fortigate",
    adapter_profile: state.execution.adapterProfile.trim() || null,
    object_group: objectGroup || null,
    execution_gate:
      state.execution.gateEnabled && state.execution.gateGroupName.trim()
        ? {
            ip_group_condition: {
              enabled: true,
              group_name: state.execution.gateGroupName.trim(),
              operator: state.execution.gateOperator
            }
          }
        : null,
    on_compliant: onCompliant,
    on_non_compliant: onNonCompliant
  };
}

export function buildPolicyPayload(state: PolicyEditorState) {
  const isLifecyclePolicy = state.policyType !== "posture";
  return {
    name: state.name.trim(),
    description: state.description.trim() || null,
    policy_scope: isLifecyclePolicy ? ("lifecycle" as const) : ("posture" as const),
    lifecycle_event_type: isLifecyclePolicy
      ? (state.policyType as Exclude<PolicyType, "posture">)
      : null,
    target_action: state.targetAction,
    is_active: state.isActive,
    conditions: buildPolicyConditions(state),
    execution: buildPolicyExecution(state)
  };
}

function emptyPolicyEditorStateForExistingPolicy(): PolicyEditorState {
  return {
    ...defaultPolicyEditorState(),
    conditions: {
      osNameEnabled: false,
      osNameOperator: "exists in",
      osNameValues: "",
      osNameGroupId: "",
      osBuildEnabled: false,
      osBuildOperator: "greater than or equal",
      osBuildValue: "",
      patchesEnabled: false,
      patchesOperator: "exists in",
      patchesValues: "",
      patchesGroupId: "",
      antivirusFamilyEnabled: false,
      antivirusFamilyOperator: "exists in",
      antivirusFamilyValues: "",
      antivirusFamilyGroupId: "",
      antivirusStatusEnabled: false,
      antivirusStatusOperator: "exists in",
      antivirusStatusValues: "",
      domainMembershipEnabled: false,
      domainMembershipOperator: "exists in",
      domainLdapProviderId: ""
    },
    execution: {
      adapter: "fortigate",
      adapterProfile: "",
      objectGroup: "",
      objectOnCompliant: "none",
      objectOnNonCompliant: "none",
      adapterOnCompliant: "none",
      adapterOnNonCompliant: "none",
      gateEnabled: false,
      gateGroupName: "",
      gateOperator: "exists in"
    }
  };
}

export function validatePolicyEditorState(state: PolicyEditorState): string | null {
  if (!state.name.trim()) {
    return "Policy name is required.";
  }
  if (state.conditions.domainMembershipEnabled && state.conditions.domainLdapProviderId === "") {
    return "Select an enabled LDAP server for the domain-join condition.";
  }
  return null;
}

export function policyTypeLabel(policy: Policy): string {
  if (policy.policy_scope !== "lifecycle") {
    return "posture";
  }
  if (policy.lifecycle_event_type === "inactive_to_active") {
    return "inactive -> active";
  }
  if (policy.lifecycle_event_type === "active_to_inactive") {
    return "active -> inactive";
  }
  return "telemetry received";
}
