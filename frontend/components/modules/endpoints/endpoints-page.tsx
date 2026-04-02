"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { RefreshCcw, ShieldAlert } from "lucide-react";
import { api } from "@/lib/api";
import { buildEndpointView } from "@/lib/platform-data";
import type { EndpointView } from "@/types/platform";
import { Button } from "@/components/ui/button";
import { Card, CardBody } from "@/components/ui/card";
import { DataTable } from "@/components/ui/data-table";
import { EmptyState } from "@/components/ui/empty-state";
import { FilterBar } from "@/components/ui/filter-bar";
import { PageHeader } from "@/components/ui/page-header";
import { StatusBadge } from "@/components/ui/status-badge";
import { useToast } from "@/components/ui/toast-provider";
import { relativeTime, relativeTimeFromSeconds } from "@/lib/utils";

export function EndpointsPage() {
  const router = useRouter();
  const { pushToast } = useToast();
  const [items, setItems] = useState<EndpointView[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState("all");
  const [osFilter, setOsFilter] = useState("all");
  const [policyFilter, setPolicyFilter] = useState("all");
  const [selected, setSelected] = useState<string[]>([]);

  async function loadData({ silent = false }: { silent?: boolean } = {}) {
    if (!silent) {
      setLoading(true);
    }
    try {
      const endpointSummaries = await api.listEndpoints();
      const views: EndpointView[] = [];

      for (const endpoint of endpointSummaries) {
        const telemetry = await api.getLatestTelemetry(endpoint.endpoint_id).catch(() => null);
        const decision = await api.getLatestDecision(endpoint.endpoint_id).catch(() => null);
        const policy = await api.resolvePolicy(endpoint.endpoint_id).catch(() => null);
        const enforcement = await api.getLatestEnforcement(endpoint.endpoint_id).catch(() => null);
        views.push(
          buildEndpointView({
            endpoint,
            telemetry,
            policy,
            decision,
            enforcement
          })
        );
      }

      setItems(views);
    } catch (error) {
      if (!silent) {
        pushToast({
          tone: "error",
          title: "Failed to load endpoints",
          description: error instanceof Error ? error.message : "Unknown error"
        });
      }
    } finally {
      if (!silent) {
        setLoading(false);
      }
    }
  }

  useEffect(() => {
    void loadData();
    const timer = window.setInterval(() => {
      void loadData({ silent: true });
    }, 5000);

    return () => window.clearInterval(timer);
  }, []);

  const osTypes: string[] = [];
  const policyNames: string[] = [];

  for (const item of items) {
    if (item.osType && !osTypes.includes(item.osType)) {
      osTypes.push(item.osType);
    }
    if (item.policyName && !policyNames.includes(item.policyName)) {
      policyNames.push(item.policyName);
    }
  }

  const filtered = items.filter((endpoint) => {
    const matchesSearch =
      endpoint.hostname.toLowerCase().includes(search.toLowerCase()) ||
      endpoint.endpointId.toLowerCase().includes(search.toLowerCase()) ||
      (endpoint.ipAddress ?? "").includes(search);

    const matchesStatus = statusFilter === "all" || endpoint.activityStatus === statusFilter;
    const matchesOs = osFilter === "all" || endpoint.osType === osFilter;
    const matchesPolicy = policyFilter === "all" || endpoint.policyName === policyFilter;

    return matchesSearch && matchesStatus && matchesOs && matchesPolicy;
  });

  function toggleSelection(id: string) {
    setSelected((current) => {
      if (current.includes(id)) {
        return current.filter((item) => item !== id);
      }
      return [...current, id];
    });
  }

  async function evaluateSelection() {
    if (selected.length === 0) {
      pushToast({ tone: "info", title: "No endpoints selected" });
      return;
    }

    let success = 0;
    for (const endpointId of selected) {
      try {
        await api.evaluateEndpoint(endpointId);
        success += 1;
      } catch (_error) {
      }
    }

    pushToast({
      tone: success === selected.length ? "success" : "info",
      title: `Evaluated ${success} of ${selected.length} selected endpoints`
    });

    await loadData();
  }

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="Resource Management"
        title="Endpoints"
        description="This view shows live endpoint inventory from telemetry-api and refreshes automatically every 5 seconds."
        actions={
          <>
            <Button variant="secondary" onClick={evaluateSelection} disabled={loading || selected.length === 0}>
              <ShieldAlert className="mr-2 h-4 w-4" />
              Evaluate selected
            </Button>
            <Button onClick={() => void loadData()} disabled={loading}>
              <RefreshCcw className="mr-2 h-4 w-4" />
              {loading ? "Refreshing..." : "Refresh"}
            </Button>
          </>
        }
      />

      <FilterBar
        searchValue={search}
        onSearchChange={setSearch}
        searchPlaceholder="Search by endpoint name, identifier, or IP"
        filters={[
          {
            id: "status",
            label: "Status",
            value: statusFilter,
            onChange: setStatusFilter,
            options: [
              { label: "All statuses", value: "all" },
              { label: "Active", value: "active" },
              { label: "Inactive", value: "inactive" },
              { label: "Unknown", value: "unknown" }
            ]
          },
          {
            id: "os",
            label: "OS / Type",
            value: osFilter,
            onChange: setOsFilter,
            options: [{ label: "All OS types", value: "all" }, ...osTypes.map((item) => ({ label: item, value: item }))]
          },
          {
            id: "policy",
            label: "Policy",
            value: policyFilter,
            onChange: setPolicyFilter,
            options: [{ label: "All policies", value: "all" }, ...policyNames.map((item) => ({ label: item, value: item }))]
          }
        ]}
      />

      <Card>
        <CardBody className="p-0">
          {filtered.length === 0 && !loading ? (
            <EmptyState
              icon={ShieldAlert}
              title="No endpoints available"
              description="Run a collector and submit telemetry to telemetry-api. Endpoints will appear here automatically as devices report in."
              action={
                <Button variant="secondary" onClick={() => void loadData()}>
                  Refresh inventory
                </Button>
              }
            />
          ) : (
            <DataTable
              data={filtered}
              getRowKey={(endpoint) => endpoint.endpointId}
              onRowClick={(endpoint) => router.push(`/endpoints/${endpoint.endpointId}`)}
              columns={[
                {
                  id: "select",
                  header: "",
                  cell: (endpoint) => (
                    <input
                      type="checkbox"
                      checked={selected.includes(endpoint.endpointId)}
                      onChange={(event) => {
                        event.stopPropagation();
                        toggleSelection(endpoint.endpointId);
                      }}
                      onClick={(event) => event.stopPropagation()}
                      className="h-4 w-4 rounded border-border bg-slate-950"
                    />
                  )
                },
                {
                  id: "name",
                  header: "Endpoint",
                  cell: (endpoint) => (
                    <div>
                      <div className="font-medium text-white">{endpoint.hostname}</div>
                      <div className="text-xs uppercase tracking-[0.16em] text-slate-500">{endpoint.endpointId}</div>
                    </div>
                  ),
                  sortAccessor: (endpoint) => endpoint.hostname
                },
                {
                  id: "status",
                  header: "Status",
                  cell: (endpoint) => <StatusBadge value={endpoint.activityStatus} />,
                  sortAccessor: (endpoint) => endpoint.activityStatus
                },
                {
                  id: "ip",
                  header: "IP",
                  cell: (endpoint) => endpoint.ipAddress ?? "Unavailable",
                  sortAccessor: (endpoint) => endpoint.ipAddress ?? ""
                },
                {
                  id: "os",
                  header: "OS / Type",
                  cell: (endpoint) => endpoint.osType ?? "Unavailable",
                  sortAccessor: (endpoint) => endpoint.osType ?? ""
                },
                {
                  id: "lastSeen",
                  header: "Last seen",
                  cell: (endpoint) =>
                    endpoint.secondsSinceSeen !== null && endpoint.secondsSinceSeen !== undefined
                      ? relativeTimeFromSeconds(endpoint.secondsSinceSeen)
                      : relativeTime(endpoint.lastSeen),
                  sortAccessor: (endpoint) => endpoint.lastSeen
                },
                {
                  id: "interval",
                  header: "Expected cadence",
                  cell: (endpoint) =>
                    endpoint.expectedIntervalSeconds !== null ? `${endpoint.expectedIntervalSeconds}s` : "Unavailable",
                  sortAccessor: (endpoint) => endpoint.expectedIntervalSeconds ?? -1
                },
                {
                  id: "policy",
                  header: "Assigned policy",
                  cell: (endpoint) => endpoint.policyName ?? "Unassigned",
                  sortAccessor: (endpoint) => endpoint.policyName ?? ""
                }
              ]}
            />
          )}
        </CardBody>
      </Card>
    </div>
  );
}
