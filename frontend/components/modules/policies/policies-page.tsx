"use client";

import { useEffect, useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import { Plus, RefreshCcw } from "lucide-react";
import { api } from "@/lib/api";
import type { AdapterConfig, ConditionGroup, Policy } from "@/types/platform";
import { Button } from "@/components/ui/button";
import { Card, CardBody } from "@/components/ui/card";
import { DataTable } from "@/components/ui/data-table";
import { EmptyState } from "@/components/ui/empty-state";
import { FilterBar } from "@/components/ui/filter-bar";
import { Modal } from "@/components/ui/modal";
import { PageHeader } from "@/components/ui/page-header";
import { StatusBadge } from "@/components/ui/status-badge";
import { useToast } from "@/components/ui/toast-provider";
import { formatDate } from "@/lib/utils";
import {
  buildPolicyPayload,
  defaultPolicyEditorState,
  policyTypeLabel,
  type PolicyEditorState
} from "@/components/modules/policies/policy-form-model";
import {
  PolicyConditionsSection,
  PolicyExecutionSection
} from "@/components/modules/policies/policy-form-sections";

export function PoliciesPage() {
  const router = useRouter();
  const { pushToast } = useToast();
  const [items, setItems] = useState<Policy[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState("all");
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [draft, setDraft] = useState<PolicyEditorState>(defaultPolicyEditorState());
  const [conditionGroups, setConditionGroups] = useState<ConditionGroup[]>([]);
  const [adapterProfiles, setAdapterProfiles] = useState<AdapterConfig[]>([]);

  const loadPolicies = async () => {
    setLoading(true);
    try {
      const [policies, groups, adapters] = await Promise.all([
        api.listPolicies(),
        api.listConditionGroups().catch(() => []),
        api.listAdapterConfigs().catch(() => [])
      ]);
      setItems(policies);
      setConditionGroups(groups);
      setAdapterProfiles(adapters);
    } catch (error) {
      pushToast({
        tone: "error",
        title: "Failed to load policies",
        description: error instanceof Error ? error.message : "Unknown error"
      });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadPolicies();
  }, []);

  const filtered = useMemo(() => {
    return items.filter((policy) => {
      const matchesSearch =
        policy.name.toLowerCase().includes(search.toLowerCase()) ||
        (policy.description ?? "").toLowerCase().includes(search.toLowerCase());
      const matchesStatus =
        statusFilter === "all" || (statusFilter === "enabled" ? policy.is_active : !policy.is_active);
      return matchesSearch && matchesStatus;
    });
  }, [items, search, statusFilter]);

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="Policy Management"
        title="Policies"
        description="Create readable endpoint policies with guided fields and operator selections."
        actions={
          <>
            <Button variant="secondary" onClick={loadPolicies} disabled={loading}>
              <RefreshCcw className="mr-2 h-4 w-4" />
              {loading ? "Refreshing..." : "Refresh"}
            </Button>
            <Button onClick={() => setIsModalOpen(true)}>
              <Plus className="mr-2 h-4 w-4" />
              Create policy
            </Button>
          </>
        }
      />

      <FilterBar
        searchValue={search}
        onSearchChange={setSearch}
        searchPlaceholder="Search by policy name or description"
        filters={[
          {
            id: "status",
            label: "Status",
            value: statusFilter,
            onChange: setStatusFilter,
            options: [
              { label: "All statuses", value: "all" },
              { label: "Enabled", value: "enabled" },
              { label: "Disabled", value: "disabled" }
            ]
          }
        ]}
      />

      <Card>
        <CardBody className="p-0">
          {filtered.length === 0 && !loading ? (
            <EmptyState
              icon={Plus}
              title="No policies available"
              description="Create your first policy to start endpoint checks and adapter actions."
              action={<Button onClick={() => setIsModalOpen(true)}>Create policy</Button>}
            />
          ) : (
            <DataTable
              data={filtered}
              getRowKey={(policy) => String(policy.id)}
              onRowClick={(policy) => router.push(`/policies/${policy.id}`)}
              columns={[
                {
                  id: "name",
                  header: "Policy",
                  cell: (policy) => (
                    <div>
                      <div className="font-medium text-white">{policy.name}</div>
                      <div className="text-xs uppercase tracking-[0.16em] text-slate-500">#{policy.id}</div>
                    </div>
                  ),
                  sortAccessor: (policy) => policy.name
                },
                {
                  id: "type",
                  header: "Type",
                  cell: (policy) => policyTypeLabel(policy),
                  sortAccessor: (policy) => policy.policy_scope ?? "posture"
                },
                {
                  id: "status",
                  header: "Status",
                  cell: (policy) => <StatusBadge value={policy.is_active ? "healthy" : "disabled"} />,
                  sortAccessor: (policy) => String(policy.is_active)
                },
                {
                  id: "action",
                  header: "Target action",
                  cell: (policy) => policy.target_action,
                  sortAccessor: (policy) => policy.target_action
                },
                {
                  id: "conditions",
                  header: "Conditions",
                  cell: (policy) => policy.conditions.length,
                  sortAccessor: (policy) => policy.conditions.length
                },
                {
                  id: "updated",
                  header: "Updated",
                  cell: (policy) => formatDate(policy.updated_at),
                  sortAccessor: (policy) => policy.updated_at
                }
              ]}
            />
          )}
        </CardBody>
      </Card>

      <Modal
        open={isModalOpen}
        title="Create policy"
        description="Configure conditions and adapter actions using friendly fields."
        onClose={() => setIsModalOpen(false)}
        footer={
          <>
            <Button variant="ghost" onClick={() => setIsModalOpen(false)}>
              Cancel
            </Button>
            <Button
              onClick={async () => {
                try {
                  const payload = buildPolicyPayload(draft);
                  await api.createPolicy(payload);
                  pushToast({ tone: "success", title: "Policy created" });
                  setIsModalOpen(false);
                  setDraft(defaultPolicyEditorState());
                  await loadPolicies();
                } catch (error) {
                  pushToast({
                    tone: "error",
                    title: "Failed to create policy",
                    description: error instanceof Error ? error.message : "Unknown error"
                  });
                }
              }}
              disabled={!draft.name.trim()}
            >
              Save policy
            </Button>
          </>
        }
      >
        <div className="grid gap-4">
          <label className="space-y-2">
            <span className="text-sm text-slate-300">Policy name</span>
            <input
              value={draft.name}
              onChange={(event) => setDraft((current) => ({ ...current, name: event.target.value }))}
              className="w-full rounded-xl border border-border bg-slate-900 px-3 py-2.5 text-sm text-white outline-none focus:border-teal-500"
            />
          </label>
          <label className="space-y-2">
            <span className="text-sm text-slate-300">Description</span>
            <textarea
              value={draft.description}
              onChange={(event) => setDraft((current) => ({ ...current, description: event.target.value }))}
              rows={3}
              className="w-full rounded-xl border border-border bg-slate-900 px-3 py-2.5 text-sm text-white outline-none focus:border-teal-500"
            />
          </label>
          <div className="grid gap-4 md:grid-cols-2">
            <label className="space-y-2">
              <span className="text-sm text-slate-300">Policy type</span>
              <select
                value={draft.policyType}
                onChange={(event) =>
                  setDraft((current) => ({
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
                value={draft.targetAction}
                onChange={(event) =>
                  setDraft((current) => ({
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
                checked={draft.isActive}
                onChange={(event) => setDraft((current) => ({ ...current, isActive: event.target.checked }))}
              />
              <span className="text-sm text-slate-300">Policy is active</span>
            </label>
          </div>

          <PolicyConditionsSection
            value={draft}
            onChange={setDraft}
            conditionGroups={conditionGroups}
          />
          <PolicyExecutionSection
            value={draft}
            onChange={setDraft}
            adapterProfiles={adapterProfiles}
          />
        </div>
      </Modal>
    </div>
  );
}
