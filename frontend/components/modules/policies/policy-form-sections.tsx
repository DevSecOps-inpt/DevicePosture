"use client";

import { useMemo, useState } from "react";
import type { Dispatch, SetStateAction } from "react";
import type { AdapterConfig, AuthProvider, ConditionGroup } from "@/types/platform";
import {
  ANTIVIRUS_FAMILY_SUGGESTIONS,
  ANTIVIRUS_STATUS_SUGGESTIONS,
  MEMBERSHIP_OPERATORS,
  NUMERIC_OPERATORS,
  OS_NAME_SUGGESTIONS,
  type AdapterAction,
  type GroupAction,
  type PolicyEditorState
} from "@/components/modules/policies/policy-form-model";

const inputClassName =
  "w-full rounded-xl border border-border bg-slate-900 px-3 py-2.5 text-sm text-white outline-none focus:border-teal-500";

type PolicyFormSectionsProps = {
  value: PolicyEditorState;
  onChange: Dispatch<SetStateAction<PolicyEditorState>>;
  conditionGroups?: ConditionGroup[];
  ldapProviders?: AuthProvider[];
  adapterProfiles?: AdapterConfig[];
  ipGroups?: Array<{ id: string; name: string }>;
};

function updateConditions(
  onChange: Dispatch<SetStateAction<PolicyEditorState>>,
  patch: Partial<PolicyEditorState["conditions"]>
) {
  onChange((current) => ({
    ...current,
    conditions: {
      ...current.conditions,
      ...patch
    }
  }));
}

function updateExecution(
  onChange: Dispatch<SetStateAction<PolicyEditorState>>,
  patch: Partial<PolicyEditorState["execution"]>
) {
  onChange((current) => ({
    ...current,
    execution: {
      ...current.execution,
      ...patch
    }
  }));
}

function parseValueList(value: string): string[] {
  return value
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

function serializeValueList(values: string[]): string {
  return values.join(", ");
}

function MultiValueEditor({
  value,
  onChange,
  disabled = false,
  placeholder,
  suggestions = []
}: {
  value: string;
  onChange: (next: string) => void;
  disabled?: boolean;
  placeholder: string;
  suggestions?: string[];
}) {
  const values = useMemo(() => parseValueList(value), [value]);
  const [draft, setDraft] = useState("");
  const listId = `policy-list-${placeholder.toLowerCase().replace(/[^a-z0-9]+/g, "-")}`;

  const addValue = () => {
    const candidate = draft.trim();
    if (!candidate) return;
    if (values.some((item) => item.toLowerCase() === candidate.toLowerCase())) {
      setDraft("");
      return;
    }
    onChange(serializeValueList([...values, candidate]));
    setDraft("");
  };

  const removeValue = (valueToRemove: string) => {
    onChange(serializeValueList(values.filter((item) => item !== valueToRemove)));
  };

  return (
    <div className="grid gap-2">
      <div className="flex flex-wrap gap-2">
        {values.length === 0 ? (
          <span className="text-xs text-slate-500">No values added yet.</span>
        ) : (
          values.map((item) => (
            <span
              key={item}
              className="inline-flex items-center gap-2 rounded-full border border-border bg-slate-900 px-3 py-1 text-xs text-slate-200"
            >
              {item}
              <button
                type="button"
                onClick={() => removeValue(item)}
                disabled={disabled}
                className="text-slate-400 hover:text-slate-100 disabled:opacity-40"
                aria-label={`Remove ${item}`}
              >
                x
              </button>
            </span>
          ))
        )}
      </div>
      <div className="flex gap-2">
        <input
          value={draft}
          onChange={(event) => setDraft(event.target.value)}
          onKeyDown={(event) => {
            if (event.key === "Enter") {
              event.preventDefault();
              addValue();
            }
          }}
          disabled={disabled}
          placeholder={placeholder}
          className={inputClassName}
          list={suggestions.length > 0 ? listId : undefined}
        />
        <button
          type="button"
          onClick={addValue}
          disabled={disabled || !draft.trim()}
          className="rounded-xl border border-border bg-slate-900 px-3 py-2.5 text-sm text-slate-100 disabled:opacity-40"
        >
          +
        </button>
      </div>
      {suggestions.length > 0 ? (
        <datalist id={listId}>
          {suggestions.map((item) => (
            <option key={item} value={item} />
          ))}
        </datalist>
      ) : null}
    </div>
  );
}

export function PolicyConditionsSection({
  value,
  onChange,
  conditionGroups = [],
  ldapProviders = []
}: PolicyFormSectionsProps) {
  if (value.policyType === "active_to_inactive") {
    return (
      <div className="grid gap-4 rounded-2xl border border-border bg-slate-950/40 p-4">
        <p className="text-sm font-medium text-white">Conditions</p>
        <p className="text-xs text-slate-400">
          This policy type executes on the active-to-inactive transition and does not use compliance conditions.
        </p>
      </div>
    );
  }

  const osGroups = conditionGroups.filter((group) => group.group_type === "allowed_os");
  const patchGroups = conditionGroups.filter((group) => group.group_type === "allowed_patches");
  const antivirusGroups = conditionGroups.filter(
    (group) => group.group_type === "allowed_antivirus_families"
  );

  return (
    <div className="grid gap-4 rounded-2xl border border-border bg-slate-950/40 p-4">
      <p className="text-sm font-medium text-white">Conditions</p>
      <p className="text-xs text-slate-400">
        Build policy checks using simple operators and group selectors.
      </p>

      <div className="rounded-xl border border-border bg-slate-900/40 p-3">
        <div className="flex items-center justify-between gap-3">
          <p className="text-sm text-slate-200">OS name</p>
          <label className="flex items-center gap-2 text-sm text-slate-300">
            <input
              type="checkbox"
              checked={value.conditions.osNameEnabled}
              onChange={(event) => updateConditions(onChange, { osNameEnabled: event.target.checked })}
            />
            Enabled
          </label>
        </div>
        <div className="mt-3 grid gap-3 md:grid-cols-[220px_1fr]">
          <select
            value={value.conditions.osNameOperator}
            onChange={(event) =>
              updateConditions(onChange, {
                osNameOperator: event.target.value as PolicyEditorState["conditions"]["osNameOperator"]
              })
            }
            disabled={!value.conditions.osNameEnabled}
            className={inputClassName}
          >
            {MEMBERSHIP_OPERATORS.map((operator) => (
              <option key={operator} value={operator}>
                {operator}
              </option>
            ))}
          </select>
          <div className="grid gap-2">
            <select
              value={value.conditions.osNameGroupId === "" ? "" : String(value.conditions.osNameGroupId)}
              onChange={(event) =>
                updateConditions(onChange, {
                  osNameGroupId: event.target.value ? Number(event.target.value) : ""
                })
              }
              disabled={!value.conditions.osNameEnabled}
              className={inputClassName}
            >
              <option value="">Use custom values</option>
              {osGroups.map((group) => (
                <option key={group.id} value={String(group.id)}>
                  {group.name}
                </option>
              ))}
            </select>
            <MultiValueEditor
              value={value.conditions.osNameValues}
              onChange={(next) => updateConditions(onChange, { osNameValues: next })}
              disabled={!value.conditions.osNameEnabled || value.conditions.osNameGroupId !== ""}
              placeholder="OS value"
              suggestions={OS_NAME_SUGGESTIONS}
            />
          </div>
        </div>
      </div>

      <div className="rounded-xl border border-border bg-slate-900/40 p-3">
        <div className="flex items-center justify-between gap-3">
          <p className="text-sm text-slate-200">OS build/version</p>
          <label className="flex items-center gap-2 text-sm text-slate-300">
            <input
              type="checkbox"
              checked={value.conditions.osBuildEnabled}
              onChange={(event) => updateConditions(onChange, { osBuildEnabled: event.target.checked })}
            />
            Enabled
          </label>
        </div>
        <div className="mt-3 grid gap-3 md:grid-cols-[220px_1fr]">
          <select
            value={value.conditions.osBuildOperator}
            onChange={(event) =>
              updateConditions(onChange, {
                osBuildOperator: event.target.value as PolicyEditorState["conditions"]["osBuildOperator"]
              })
            }
            disabled={!value.conditions.osBuildEnabled}
            className={inputClassName}
          >
            {NUMERIC_OPERATORS.map((operator) => (
              <option key={operator} value={operator}>
                {operator}
              </option>
            ))}
          </select>
          <input
            value={value.conditions.osBuildValue}
            onChange={(event) => updateConditions(onChange, { osBuildValue: event.target.value })}
            disabled={!value.conditions.osBuildEnabled}
            placeholder="Build/version threshold, for example 10.0.26100"
            className={inputClassName}
          />
        </div>
      </div>

      <div className="rounded-xl border border-border bg-slate-900/40 p-3">
        <div className="flex items-center justify-between gap-3">
          <p className="text-sm text-slate-200">Allowed patches group</p>
          <label className="flex items-center gap-2 text-sm text-slate-300">
            <input
              type="checkbox"
              checked={value.conditions.patchesEnabled}
              onChange={(event) => updateConditions(onChange, { patchesEnabled: event.target.checked })}
            />
            Enabled
          </label>
        </div>
        <div className="mt-3 grid gap-3 md:grid-cols-[220px_1fr]">
          <select
            value={value.conditions.patchesOperator}
            onChange={(event) =>
              updateConditions(onChange, {
                patchesOperator: event.target.value as PolicyEditorState["conditions"]["patchesOperator"]
              })
            }
            disabled={!value.conditions.patchesEnabled}
            className={inputClassName}
          >
            {MEMBERSHIP_OPERATORS.map((operator) => (
              <option key={operator} value={operator}>
                {operator}
              </option>
            ))}
          </select>
          <div className="grid gap-2">
            <select
              value={value.conditions.patchesGroupId === "" ? "" : String(value.conditions.patchesGroupId)}
              onChange={(event) =>
                updateConditions(onChange, {
                  patchesGroupId: event.target.value ? Number(event.target.value) : ""
                })
              }
              disabled={!value.conditions.patchesEnabled}
              className={inputClassName}
            >
              <option value="">Use custom values</option>
              {patchGroups.map((group) => (
                <option key={group.id} value={String(group.id)}>
                  {group.name}
                </option>
              ))}
            </select>
            <MultiValueEditor
              value={value.conditions.patchesValues}
              onChange={(next) => updateConditions(onChange, { patchesValues: next })}
              disabled={!value.conditions.patchesEnabled || value.conditions.patchesGroupId !== ""}
              placeholder="KB value, for example KB5066128"
            />
          </div>
        </div>
      </div>

      <div className="rounded-xl border border-border bg-slate-900/40 p-3">
        <div className="flex items-center justify-between gap-3">
          <p className="text-sm text-slate-200">Allowed antivirus families group</p>
          <label className="flex items-center gap-2 text-sm text-slate-300">
            <input
              type="checkbox"
              checked={value.conditions.antivirusFamilyEnabled}
              onChange={(event) => updateConditions(onChange, { antivirusFamilyEnabled: event.target.checked })}
            />
            Enabled
          </label>
        </div>
        <div className="mt-3 grid gap-3 md:grid-cols-[220px_1fr]">
          <select
            value={value.conditions.antivirusFamilyOperator}
            onChange={(event) =>
              updateConditions(onChange, {
                antivirusFamilyOperator: event.target.value as PolicyEditorState["conditions"]["antivirusFamilyOperator"]
              })
            }
            disabled={!value.conditions.antivirusFamilyEnabled}
            className={inputClassName}
          >
            {MEMBERSHIP_OPERATORS.map((operator) => (
              <option key={operator} value={operator}>
                {operator}
              </option>
            ))}
          </select>
          <div className="grid gap-2">
            <select
              value={
                value.conditions.antivirusFamilyGroupId === ""
                  ? ""
                  : String(value.conditions.antivirusFamilyGroupId)
              }
              onChange={(event) =>
                updateConditions(onChange, {
                  antivirusFamilyGroupId: event.target.value ? Number(event.target.value) : ""
                })
              }
              disabled={!value.conditions.antivirusFamilyEnabled}
              className={inputClassName}
            >
              <option value="">Use custom values</option>
              {antivirusGroups.map((group) => (
                <option key={group.id} value={String(group.id)}>
                  {group.name}
                </option>
              ))}
            </select>
            <MultiValueEditor
              value={value.conditions.antivirusFamilyValues}
              onChange={(next) => updateConditions(onChange, { antivirusFamilyValues: next })}
              disabled={!value.conditions.antivirusFamilyEnabled || value.conditions.antivirusFamilyGroupId !== ""}
              placeholder="Antivirus family"
              suggestions={ANTIVIRUS_FAMILY_SUGGESTIONS}
            />
          </div>
        </div>
      </div>

      <div className="rounded-xl border border-border bg-slate-900/40 p-3">
        <div className="flex items-center justify-between gap-3">
          <p className="text-sm text-slate-200">Antivirus status</p>
          <label className="flex items-center gap-2 text-sm text-slate-300">
            <input
              type="checkbox"
              checked={value.conditions.antivirusStatusEnabled}
              onChange={(event) => updateConditions(onChange, { antivirusStatusEnabled: event.target.checked })}
            />
            Enabled
          </label>
        </div>
        <div className="mt-3 grid gap-3 md:grid-cols-[220px_1fr]">
          <select
            value={value.conditions.antivirusStatusOperator}
            onChange={(event) =>
              updateConditions(onChange, {
                antivirusStatusOperator: event.target.value as PolicyEditorState["conditions"]["antivirusStatusOperator"]
              })
            }
            disabled={!value.conditions.antivirusStatusEnabled}
            className={inputClassName}
          >
            {MEMBERSHIP_OPERATORS.map((operator) => (
              <option key={operator} value={operator}>
                {operator}
              </option>
            ))}
          </select>
          <div className="grid gap-2">
            <MultiValueEditor
              value={value.conditions.antivirusStatusValues}
              onChange={(next) => updateConditions(onChange, { antivirusStatusValues: next })}
              disabled={!value.conditions.antivirusStatusEnabled}
              placeholder="Antivirus status"
              suggestions={ANTIVIRUS_STATUS_SUGGESTIONS}
            />
          </div>
        </div>
      </div>

      <div className="rounded-xl border border-border bg-slate-900/40 p-3">
        <div className="flex items-center justify-between gap-3">
          <p className="text-sm text-slate-200">Domain join in LDAP tree</p>
          <label className="flex items-center gap-2 text-sm text-slate-300">
            <input
              type="checkbox"
              checked={value.conditions.domainMembershipEnabled}
              onChange={(event) =>
                updateConditions(onChange, { domainMembershipEnabled: event.target.checked })
              }
            />
            Enabled
          </label>
        </div>
        <p className="mt-2 text-xs text-slate-500">
          Select one enabled LDAP server. Backend verifies the endpoint is domain-joined and within that server tree.
        </p>
        <div className="mt-3 grid gap-3 md:grid-cols-[220px_1fr]">
          <select
            value={value.conditions.domainMembershipOperator}
            onChange={(event) =>
              updateConditions(onChange, {
                domainMembershipOperator: event.target.value as PolicyEditorState["conditions"]["domainMembershipOperator"]
              })
            }
            disabled={!value.conditions.domainMembershipEnabled}
            className={inputClassName}
          >
            {MEMBERSHIP_OPERATORS.map((operator) => (
              <option key={operator} value={operator}>
                {operator}
              </option>
            ))}
          </select>
          <select
            value={
              value.conditions.domainLdapProviderId === ""
                ? ""
                : String(value.conditions.domainLdapProviderId)
            }
            onChange={(event) =>
              updateConditions(onChange, {
                domainLdapProviderId: event.target.value ? Number(event.target.value) : ""
              })
            }
            disabled={!value.conditions.domainMembershipEnabled}
            className={inputClassName}
          >
            <option value="">Select enabled LDAP server</option>
            {ldapProviders.map((provider) => (
              <option key={provider.id} value={String(provider.id)}>
                {provider.name}
              </option>
            ))}
          </select>
        </div>
        {value.conditions.domainMembershipEnabled && ldapProviders.length === 0 ? (
          <p className="mt-2 text-xs text-amber-300">
            No enabled LDAP provider found. Configure one in Extensions first.
          </p>
        ) : null}
      </div>
    </div>
  );
}

function ObjectActionSelect({
  value,
  onChange,
  label,
  disabled = false
}: {
  value: GroupAction;
  onChange: (next: GroupAction) => void;
  label: string;
  disabled?: boolean;
}) {
  return (
    <label className="space-y-2">
      <span className="text-sm text-slate-300">{label}</span>
      <select
        value={value}
        onChange={(event) => onChange(event.target.value as GroupAction)}
        disabled={disabled}
        className={inputClassName}
      >
        <option value="none">No action</option>
        <option value="add">Add IP to group</option>
        <option value="remove">Remove IP from group</option>
      </select>
    </label>
  );
}

function AdapterActionSelect({
  value,
  onChange,
  label,
  disabled = false
}: {
  value: AdapterAction;
  onChange: (next: AdapterAction) => void;
  label: string;
  disabled?: boolean;
}) {
  return (
    <label className="space-y-2">
      <span className="text-sm text-slate-300">{label}</span>
      <select
        value={value}
        onChange={(event) => onChange(event.target.value as AdapterAction)}
        disabled={disabled}
        className={inputClassName}
      >
        <option value="none">No action</option>
        <option value="add_ip">Add IP to group</option>
        <option value="remove_ip">Remove IP from group</option>
        <option value="push_group">Push new IP group</option>
      </select>
    </label>
  );
}

export function PolicyExecutionSection({
  value,
  onChange,
  adapterProfiles = [],
  ipGroups = []
}: PolicyFormSectionsProps) {
  const isActiveToInactivePolicy = value.policyType === "active_to_inactive";
  const transitionObjectAction =
    value.execution.objectOnNonCompliant !== "none"
      ? value.execution.objectOnNonCompliant
      : value.execution.objectOnCompliant;
  const transitionAdapterAction =
    value.execution.adapterOnNonCompliant !== "none"
      ? value.execution.adapterOnNonCompliant
      : value.execution.adapterOnCompliant;

  return (
    <div className="grid gap-4 rounded-2xl border border-border bg-slate-950/40 p-4">
      <p className="text-sm font-medium text-white">Adapter and execution</p>
      <p className="text-xs text-slate-400">
        Backend manages adapter API calls from the selected profile. No manual API endpoint input is required.
      </p>

      <div className="grid gap-4 md:grid-cols-2">
        <label className="space-y-2">
          <span className="text-sm text-slate-300">Adapter profile</span>
          <select
            value={value.execution.adapterProfile}
            onChange={(event) => {
              const selectedProfile = adapterProfiles.find((profile) => profile.name === event.target.value);
              updateExecution(onChange, {
                adapterProfile: event.target.value,
                adapter: selectedProfile?.adapter ?? "fortigate"
              });
            }}
            className={inputClassName}
          >
            <option value="">Default active profile</option>
            {adapterProfiles.map((profile) => (
              <option key={profile.name} value={profile.name}>
                {profile.name} ({profile.adapter})
              </option>
            ))}
          </select>
        </label>
        <label className="space-y-2">
          <span className="text-sm text-slate-300">Object group (policy target)</span>
          <div className="grid gap-2">
            <select
              value={value.execution.objectGroupId}
              onChange={(event) => {
                const selectedId = event.target.value;
                const selectedGroup = ipGroups.find((group) => group.id === selectedId);
                updateExecution(onChange, {
                  objectGroupId: selectedId,
                  objectGroup: selectedGroup?.name ?? value.execution.objectGroup
                });
              }}
              className={inputClassName}
            >
              <option value="">Select group by ID (rename-safe)</option>
              {ipGroups.map((group) => (
                <option key={group.id} value={group.id}>
                  {group.name} ({group.id})
                </option>
              ))}
            </select>
            <input
              value={value.execution.objectGroup}
              onChange={(event) =>
                updateExecution(onChange, {
                  objectGroup: event.target.value,
                  objectGroupId: ""
                })
              }
              className={inputClassName}
              placeholder="Or enter group name manually"
            />
          </div>
        </label>
      </div>

      {isActiveToInactivePolicy ? (
        <div className="grid gap-4 md:grid-cols-2">
          <ObjectActionSelect
            label="On active -> inactive: object action"
            value={transitionObjectAction}
            onChange={(next) =>
              updateExecution(onChange, {
                objectOnCompliant: next,
                objectOnNonCompliant: next
              })
            }
          />
          <AdapterActionSelect
            label="On active -> inactive: adapter action"
            value={transitionAdapterAction}
            onChange={(next) =>
              updateExecution(onChange, {
                adapterOnCompliant: next,
                adapterOnNonCompliant: next
              })
            }
          />
        </div>
      ) : (
        <div className="grid gap-4 md:grid-cols-2">
          <ObjectActionSelect
            label="On compliant: object action"
            value={value.execution.objectOnCompliant}
            onChange={(next) => updateExecution(onChange, { objectOnCompliant: next })}
          />
          <ObjectActionSelect
            label="On non-compliant: object action"
            value={value.execution.objectOnNonCompliant}
            onChange={(next) => updateExecution(onChange, { objectOnNonCompliant: next })}
          />
          <AdapterActionSelect
            label="On compliant: adapter action"
            value={value.execution.adapterOnCompliant}
            onChange={(next) => updateExecution(onChange, { adapterOnCompliant: next })}
          />
          <AdapterActionSelect
            label="On non-compliant: adapter action"
            value={value.execution.adapterOnNonCompliant}
            onChange={(next) => updateExecution(onChange, { adapterOnNonCompliant: next })}
          />
        </div>
      )}

      <div className="rounded-xl border border-border bg-slate-900/40 p-3">
        <div className="flex items-center justify-between gap-3">
          <p className="text-sm text-slate-200">Execution IP condition: endpoint IP group membership</p>
          <label className="flex items-center gap-2 text-sm text-slate-300">
            <input
              type="checkbox"
              checked={value.execution.gateEnabled}
              onChange={(event) => updateExecution(onChange, { gateEnabled: event.target.checked })}
            />
            Enabled
          </label>
        </div>
        <p className="mt-2 text-xs text-slate-500">
          This gate controls whether policy actions run. It does not affect compliance checks.
        </p>
        <div className="mt-3 grid gap-3 md:grid-cols-[220px_1fr]">
          <select
            value={value.execution.gateOperator}
            onChange={(event) =>
              updateExecution(onChange, {
                gateOperator: event.target.value as PolicyEditorState["execution"]["gateOperator"]
              })
            }
            disabled={!value.execution.gateEnabled}
            className={inputClassName}
          >
            <option value="exists in">exists in</option>
            <option value="does not exist in">does not exist in</option>
          </select>
          <div className="grid gap-2">
            <select
              value={value.execution.gateGroupName}
              onChange={(event) => updateExecution(onChange, { gateGroupName: event.target.value })}
              disabled={!value.execution.gateEnabled}
              className={inputClassName}
            >
              <option value="">Select an IP group</option>
              {ipGroups.map((group) => (
                <option key={group.name} value={group.name}>
                  {group.name}
                </option>
              ))}
            </select>
            <input
              value={value.execution.gateGroupName}
              onChange={(event) => updateExecution(onChange, { gateGroupName: event.target.value })}
              disabled={!value.execution.gateEnabled}
              placeholder="Or enter IP group name manually"
              className={inputClassName}
            />
          </div>
        </div>
      </div>
    </div>
  );
}
