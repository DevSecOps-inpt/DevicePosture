"use client";

import { useEffect, useMemo, useState } from "react";
import { AlertTriangle, RefreshCcw } from "lucide-react";
import { api } from "@/lib/api";
import { buildAlertsFromEndpoints, buildEndpointView } from "@/lib/platform-data";
import type { AlertView } from "@/types/platform";
import { Button } from "@/components/ui/button";
import { Card, CardBody } from "@/components/ui/card";
import { DataTable } from "@/components/ui/data-table";
import { EmptyState } from "@/components/ui/empty-state";
import { FilterBar } from "@/components/ui/filter-bar";
import { PageHeader } from "@/components/ui/page-header";
import { StatusBadge } from "@/components/ui/status-badge";
import { useToast } from "@/components/ui/toast-provider";
import { formatDateTime } from "@/lib/utils";

export function AlertsPage() {
  const { pushToast } = useToast();
  const [alerts, setAlerts] = useState<AlertView[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState("all");

  const loadAlerts = async () => {
    setLoading(true);
    try {
      const endpointSummaries = await api.listEndpoints();
      const endpoints = await Promise.all(
        endpointSummaries.map(async (endpoint) => {
          const [telemetry, decision, policy, enforcement] = await Promise.all([
            api.getLatestTelemetry(endpoint.endpoint_id).catch(() => null),
            api.getLatestDecision(endpoint.endpoint_id).catch(() => null),
            api.resolvePolicy(endpoint.endpoint_id).catch(() => null),
            api.getLatestEnforcement(endpoint.endpoint_id).catch(() => null)
          ]);
          return buildEndpointView({ endpoint, telemetry, policy, decision, enforcement });
        })
      );
      setAlerts(buildAlertsFromEndpoints(endpoints));
    } catch (error) {
      pushToast({
        tone: "error",
        title: "Failed to load alerts",
        description: error instanceof Error ? error.message : "Unknown error"
      });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadAlerts();
  }, []);

  const filtered = useMemo(() => {
    return alerts.filter((alert) => {
      const matchesSearch =
        alert.title.toLowerCase().includes(search.toLowerCase()) ||
        alert.relatedResource.toLowerCase().includes(search.toLowerCase());
      return matchesSearch && (severityFilter === "all" || alert.severity === severityFilter);
    });
  }, [alerts, search, severityFilter]);

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="Findings"
        title="Alerts / Findings"
        description="Findings are derived from compliance decisions returned by the evaluation engine."
        actions={
          <Button variant="secondary" onClick={loadAlerts} disabled={loading}>
            <RefreshCcw className="mr-2 h-4 w-4" />
            {loading ? "Refreshing..." : "Refresh"}
          </Button>
        }
      />

      <FilterBar
        searchValue={search}
        onSearchChange={setSearch}
        searchPlaceholder="Search by title or related endpoint"
        filters={[
          {
            id: "severity",
            label: "Severity",
            value: severityFilter,
            onChange: setSeverityFilter,
            options: [
              { label: "All severities", value: "all" },
              { label: "Critical", value: "critical" },
              { label: "High", value: "high" },
              { label: "Medium", value: "medium" }
            ]
          }
        ]}
      />

      {filtered.length === 0 && !loading ? (
        <EmptyState
          icon={AlertTriangle}
          title="No active findings"
          description="Alerts will appear here when endpoints have non-compliant evaluation results."
        />
      ) : (
        <Card>
          <CardBody className="p-0">
            <DataTable
              data={filtered}
              getRowKey={(alert) => alert.id}
              columns={[
                { id: "severity", header: "Severity", cell: (alert) => <StatusBadge value={alert.severity} />, sortAccessor: (alert) => alert.severity },
                { id: "title", header: "Title", cell: (alert) => alert.title, sortAccessor: (alert) => alert.title },
                { id: "source", header: "Source", cell: (alert) => alert.source, sortAccessor: (alert) => alert.source },
                { id: "resource", header: "Related resource", cell: (alert) => alert.relatedResource, sortAccessor: (alert) => alert.relatedResource },
                { id: "status", header: "Status", cell: (alert) => <StatusBadge value={alert.status} />, sortAccessor: (alert) => alert.status },
                { id: "created", header: "Created", cell: (alert) => formatDateTime(alert.createdAt), sortAccessor: (alert) => alert.createdAt }
              ]}
            />
          </CardBody>
        </Card>
      )}
    </div>
  );
}
