"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { ArrowLeft, Copy, Save, ToggleLeft, Trash2 } from "lucide-react";
import { api } from "@/lib/api";
import type {
  AdapterConfig,
  ConditionGroup,
  EndpointSummary,
  IpGroup,
  Policy,
  PolicyAssignment
} from "@/types/platform";
import { Button } from "@/components/ui/button";
import { Card, CardBody, CardHeader, CardTitle } from "@/components/ui/card";
import { DataTable } from "@/components/ui/data-table";
import { EmptyState } from "@/components/ui/empty-state";
import { Modal } from "@/components/ui/modal";
import { PageHeader } from "@/components/ui/page-header";
import { StatusBadge } from "@/components/ui/status-badge";
import { useToast } from "@/components/ui/toast-provider";
import { formatDateTime } from "@/lib/utils";
import {
  buildPolicyPayload,
  defaultPolicyEditorState,
  policyToEditorState,
  policyTypeLabel,
  type PolicyEditorState
} from "@/components/modules/policies/policy-form-model";
import {
  PolicyConditionsSection,
  PolicyExecutionSection
} from "@/components/modules/policies/policy-form-sections";

export function PolicyDetailPage({ policyId }: { policyId: string }) {
  const router = useRouter();
  const id = Number(policyId);
  const { pushToast } = useToast();
  const [loading, setLoading] = useState(true);
  const [policy, setPolicy] = useState<Policy | null>(null);
  const [assignments, setAssignments] = useState<PolicyAssignment[]>([]);
  const [assignmentModalOpen, setAssignmentModalOpen] = useState(false);
  const [endpointOptions, setEndpointOptions] = useState<EndpointSummary[]>([]);
  const [assignmentEndpointId, setAssignmentEndpointId] = useState("");
  const [formState, setFormState] = useState<PolicyEditorState>(defaultPolicyEditorState());
  const [conditionGroups, setConditionGroups] = useState<ConditionGroup[]>([]);
  const [adapterProfiles, setAdapterProfiles] = useState<AdapterConfig[]>([]);
  const [ipGroups, setIpGroups] = useState<IpGroup[]>([]);

  const loadData = async () => {
    setLoading(true);
    try {
      const [loadedPolicy, loadedAssignments, endpoints] = await Promise.all([
        api.getPolicy(id),
        api.listAssignments(id).catch(() => []),
        api.listEndpoints().catch(() => [])
      ]);
      const [groups, adapters, groupsForExecutionGate] = await Promise.all([
        api.listConditionGroups().catch(() => []),
        api.listAdapterConfigs().catch(() => []),
        api.listIpGroups().catch(() => [])
      ]);
      setPolicy(loadedPolicy);
      setAssignments(loadedAssignments);
      setEndpointOptions(endpoints);
      if (!assignmentEndpointId && endpoints.length > 0) {
        setAssignmentEndpointId(endpoints[0].endpoint_id);
      }
      setConditionGroups(groups);
      setAdapterProfiles(adapters);
      setIpGroups(
        groupsForExecutionGate.map((group) => ({
          id: group.group_id,
          name: group.name,
          description: group.description,
          memberObjectIds: group.member_object_ids,
          createdAt: group.created_at,
          updatedAt: group.updated_at
        }))
      );
      setFormState(policyToEditorState(loadedPolicy));
    } catch (error) {
      pushToast({
        tone: "error",
        title: "Failed to load policy",
        description: error instanceof Error ? error.message : "Unknown error"
      });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (!Number.isNaN(id)) {
      loadData();
    }
  }, [id]);

  if (!loading && !policy) {
    return (
      <EmptyState
        icon={Trash2}
        title="Policy not found"
        description="The requested policy does not exist in policy-service."
        action={<Button onClick={() => router.push("/policies")}>Return to policies</Button>}
      />
    );
  }

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="Policy Detail"
        title={policy?.name ?? "Policy"}
        description={policy ? `Type: ${policyTypeLabel(policy)}` : "Edit policy rules and adapter actions."}
        actions={
          <>
            <Button variant="ghost" onClick={() => router.push("/policies")}>
              <ArrowLeft className="mr-2 h-4 w-4" />
              Back to list
            </Button>
            <Button
              variant="secondary"
              onClick={async () => {
                if (!policy) return;
                try {
                  const duplicate = await api.createPolicy({
                    name: `${policy.name} copy`,
                    description: policy.description,
                    policy_scope: policy.policy_scope ?? "posture",
                    lifecycle_event_type: policy.lifecycle_event_type ?? null,
                    target_action: policy.target_action,
                    is_active: false,
                    conditions: policy.conditions,
                    execution: policy.execution ?? null
                  });
                  pushToast({ tone: "success", title: "Policy duplicated" });
                  router.push(`/policies/${duplicate.id}`);
                } catch (error) {
                  pushToast({
                    tone: "error",
                    title: "Failed to duplicate policy",
                    description: error instanceof Error ? error.message : "Unknown error"
                  });
                }
              }}
              disabled={!policy}
            >
              <Copy className="mr-2 h-4 w-4" />
              Duplicate
            </Button>
            <Button
              variant="secondary"
              onClick={async () => {
                if (!policy) return;
                try {
                  const updated = await api.updatePolicy(policy.id, { is_active: !policy.is_active });
                  setPolicy(updated);
                  setFormState((current) => ({ ...current, isActive: updated.is_active }));
                  pushToast({ tone: "success", title: updated.is_active ? "Policy enabled" : "Policy disabled" });
                } catch (error) {
                  pushToast({
                    tone: "error",
                    title: "Failed to update policy status",
                    description: error instanceof Error ? error.message : "Unknown error"
                  });
                }
              }}
              disabled={!policy}
            >
              <ToggleLeft className="mr-2 h-4 w-4" />
              {policy?.is_active ? "Disable" : "Enable"}
            </Button>
            <Button
              onClick={async () => {
                if (!policy) return;
                try {
                  const payload = buildPolicyPayload(formState);
                  const updated = await api.updatePolicy(policy.id, payload);
                  setPolicy(updated);
                  setFormState(policyToEditorState(updated));
                  pushToast({ tone: "success", title: "Policy saved" });
                } catch (error) {
                  pushToast({
                    tone: "error",
                    title: "Failed to save policy",
                    description: error instanceof Error ? error.message : "Unknown error"
                  });
                }
              }}
              disabled={!policy || !formState.name.trim()}
            >
              <Save className="mr-2 h-4 w-4" />
              Save changes
            </Button>
          </>
        }
      />

      <div className="grid gap-6 xl:grid-cols-[1.15fr_1fr]">
        <Card>
          <CardHeader>
            <div>
              <CardTitle>Policy definition</CardTitle>
              <p className="mt-1 text-sm text-slate-400">
                Friendly fields for conditions and adapter actions.
              </p>
            </div>
            {policy ? <StatusBadge value={policy.is_active ? "healthy" : "disabled"} /> : null}
          </CardHeader>
          <CardBody className="grid gap-4">
            <label className="space-y-2">
              <span className="text-sm text-slate-300">Policy name</span>
              <input
                value={formState.name}
                onChange={(event) => setFormState((current) => ({ ...current, name: event.target.value }))}
                className="w-full rounded-xl border border-border bg-slate-900 px-3 py-2.5 text-sm text-white outline-none focus:border-teal-500"
              />
            </label>
            <label className="space-y-2">
              <span className="text-sm text-slate-300">Description</span>
              <textarea
                value={formState.description}
                onChange={(event) => setFormState((current) => ({ ...current, description: event.target.value }))}
                rows={3}
                className="w-full rounded-xl border border-border bg-slate-900 px-3 py-2.5 text-sm text-white outline-none focus:border-teal-500"
              />
            </label>
            <div className="grid gap-4 md:grid-cols-2">
              <label className="space-y-2">
                <span className="text-sm text-slate-300">Policy type</span>
                <select
                  value={formState.policyType}
                  onChange={(event) =>
                    setFormState((current) => ({
                      ...current,
                      policyType: event.target.value as PolicyEditorState["policyType"]
                    }))
                  }
                  className="w-full rounded-xl border border-border bg-slate-900 px-3 py-2.5 text-sm text-white outline-none focus:border-teal-500"
                >
                  <option value="posture">posture</option>
                  <option value="telemetry_received">lifecycle: telemetry received</option>
                  <option value="inactive_to_active">lifecycle: inactive to active</option>
                  <option value="active_to_inactive">lifecycle: active to inactive</option>
                </select>
              </label>
              <label className="space-y-2">
                <span className="text-sm text-slate-300">Target action</span>
                <select
                  value={formState.targetAction}
                  onChange={(event) =>
                    setFormState((current) => ({
                      ...current,
                      targetAction: event.target.value as PolicyEditorState["targetAction"]
                    }))
                  }
                  className="w-full rounded-xl border border-border bg-slate-900 px-3 py-2.5 text-sm text-white outline-none focus:border-teal-500"
                >
                  <option value="allow">allow</option>
                  <option value="quarantine">quarantine</option>
                  <option value="block">block</option>
                </select>
              </label>
              <label className="flex items-center gap-3 rounded-xl border border-border bg-slate-900 px-3 py-2.5">
                <input
                  type="checkbox"
                  checked={formState.isActive}
                  onChange={(event) => setFormState((current) => ({ ...current, isActive: event.target.checked }))}
                />
                <span className="text-sm text-slate-300">Policy is active</span>
              </label>
            </div>

            <PolicyConditionsSection
              value={formState}
              onChange={setFormState}
              conditionGroups={conditionGroups}
            />
            <PolicyExecutionSection
              value={formState}
              onChange={setFormState}
              adapterProfiles={adapterProfiles}
              ipGroups={ipGroups}
            />
          </CardBody>
        </Card>

        <Card>
          <CardHeader>
            <div>
              <CardTitle>Policy metadata</CardTitle>
              <p className="mt-1 text-sm text-slate-400">Stored metadata and assignment actions.</p>
            </div>
          </CardHeader>
          <CardBody className="space-y-3">
            {policy ? (
              <>
                <div className="rounded-2xl border border-border bg-slate-950/35 p-4">
                  <p className="text-xs uppercase tracking-[0.16em] text-slate-500">Created at</p>
                  <p className="mt-2 text-sm text-slate-100">{formatDateTime(policy.created_at)}</p>
                </div>
                <div className="rounded-2xl border border-border bg-slate-950/35 p-4">
                  <p className="text-xs uppercase tracking-[0.16em] text-slate-500">Updated at</p>
                  <p className="mt-2 text-sm text-slate-100">{formatDateTime(policy.updated_at)}</p>
                </div>
                <div className="rounded-2xl border border-border bg-slate-950/35 p-4">
                  <p className="text-xs uppercase tracking-[0.16em] text-slate-500">Conditions configured</p>
                  <p className="mt-2 text-sm text-slate-100">{policy.conditions.length}</p>
                </div>
                <div className="flex gap-3">
                  <Button
                    variant="secondary"
                    onClick={() => setAssignmentModalOpen(true)}
                    disabled={endpointOptions.length === 0}
                  >
                    Assign endpoint
                  </Button>
                  <Button
                    variant="danger"
                    onClick={async () => {
                      if (!policy) return;
                      try {
                        await api.deletePolicy(policy.id);
                        pushToast({ tone: "success", title: "Policy deleted" });
                        router.push("/policies");
                      } catch (error) {
                        pushToast({
                          tone: "error",
                          title: "Failed to delete policy",
                          description: error instanceof Error ? error.message : "Unknown error"
                        });
                      }
                    }}
                  >
                    <Trash2 className="mr-2 h-4 w-4" />
                    Delete
                  </Button>
                </div>
              </>
            ) : null}
          </CardBody>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <div>
            <CardTitle>Assignments</CardTitle>
            <p className="mt-1 text-sm text-slate-400">Attach this policy to endpoints, groups, or default scope.</p>
          </div>
        </CardHeader>
        <CardBody>
          <DataTable
            data={assignments}
            getRowKey={(assignment) =>
              `${assignment.id ?? "assignment"}-${assignment.assignment_type}-${assignment.assignment_value}`
            }
            columns={[
              {
                id: "type",
                header: "Assignment type",
                cell: (assignment) => assignment.assignment_type,
                sortAccessor: (assignment) => assignment.assignment_type
              },
              {
                id: "value",
                header: "Assignment value",
                cell: (assignment) => {
                  if (assignment.assignment_type !== "endpoint") {
                    return assignment.assignment_value;
                  }
                  const endpoint = endpointOptions.find(
                    (item) => item.endpoint_id === assignment.assignment_value
                  );
                  return endpoint
                    ? `${endpoint.hostname} (${endpoint.endpoint_id})`
                    : assignment.assignment_value;
                },
                sortAccessor: (assignment) => assignment.assignment_value
              }
            ]}
          />
        </CardBody>
      </Card>

      <Modal
        open={assignmentModalOpen}
        title="Assign endpoint"
        description="Select an available endpoint and attach this policy."
        onClose={() => setAssignmentModalOpen(false)}
        footer={
          <>
            <Button variant="ghost" onClick={() => setAssignmentModalOpen(false)}>
              Cancel
            </Button>
            <Button
              onClick={async () => {
                if (!policy) return;
                try {
                  await api.createAssignment(policy.id, {
                    assignment_type: "endpoint",
                    assignment_value: assignmentEndpointId
                  });
                  pushToast({ tone: "success", title: "Endpoint assigned" });
                  setAssignmentModalOpen(false);
                  setAssignments(await api.listAssignments(policy.id));
                } catch (error) {
                  pushToast({
                    tone: "error",
                    title: "Failed to assign endpoint",
                    description: error instanceof Error ? error.message : "Unknown error"
                  });
                }
              }}
              disabled={!assignmentEndpointId}
            >
              Assign endpoint
            </Button>
          </>
        }
      >
        <div className="grid gap-4">
          <label className="space-y-2">
            <span className="text-sm text-slate-300">Available endpoints</span>
            <select
              value={assignmentEndpointId}
              onChange={(event) => setAssignmentEndpointId(event.target.value)}
              className="w-full rounded-xl border border-border bg-slate-900 px-3 py-2.5 text-sm text-white outline-none focus:border-teal-500"
            >
              {endpointOptions.map((endpoint) => (
                <option key={endpoint.endpoint_id} value={endpoint.endpoint_id}>
                  {endpoint.hostname} ({endpoint.endpoint_id})
                </option>
              ))}
            </select>
          </label>
        </div>
      </Modal>
    </div>
  );
}
