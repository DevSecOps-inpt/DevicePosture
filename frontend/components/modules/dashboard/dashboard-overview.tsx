"use client";

import { useEffect, useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import { Activity, AlertTriangle, ListChecks, RefreshCcw, ShieldCheck, Workflow } from "lucide-react";
import { api } from "@/lib/api";
import { buildAlertsFromEndpoints, buildEndpointView } from "@/lib/platform-data";
import type { AuditEvent, EndpointView, ServiceStatus } from "@/types/platform";
import { Button } from "@/components/ui/button";
import { Card, CardBody, CardHeader, CardTitle } from "@/components/ui/card";
import { DataTable } from "@/components/ui/data-table";
import { EmptyState } from "@/components/ui/empty-state";
import { MetricCard } from "@/components/ui/metric-card";
import { PageHeader } from "@/components/ui/page-header";
import { StatusBadge } from "@/components/ui/status-badge";
import { useToast } from "@/components/ui/toast-provider";
import { formatDateTime, relativeTime } from "@/lib/utils";

export function DashboardOverview() {
  const router = useRouter();
  const { pushToast } = useToast();
  const [loading, setLoading] = useState(true);
  const [endpoints, setEndpoints] = useState<EndpointView[]>([]);
  const [policiesCount, setPoliciesCount] = useState(0);
  const [auditEvents, setAuditEvents] = useState<AuditEvent[]>([]);
  const [serviceHealth, setServiceHealth] = useState<ServiceStatus[]>([]);

  const loadData = async ({ silent = false }: { silent?: boolean } = {}) => {
    if (!silent) {
      setLoading(true);
    }
    try {
      const [endpointSummaries, policies, health, events] = await Promise.all([
        api.listEndpoints(),
        api.listPolicies(),
        api.getServiceHealth(),
        api.listAuditEvents().catch(() => [])
      ]);

      const endpointViews = await Promise.all(
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

      setEndpoints(endpointViews);
      setPoliciesCount(policies.filter((policy) => policy.is_active).length);
      setServiceHealth(health);
      setAuditEvents(events);
    } catch (error) {
      if (!silent) {
        pushToast({
          tone: "error",
          title: "Failed to load dashboard",
          description: error instanceof Error ? error.message : "Unknown error"
        });
      }
    } finally {
      if (!silent) {
        setLoading(false);
      }
    }
  };

  useEffect(() => {
    void loadData();
    const timer = window.setInterval(() => {
      void loadData({ silent: true });
    }, 5000);

    return () => window.clearInterval(timer);
  }, []);

  const alerts = useMemo(() => buildAlertsFromEndpoints(endpoints), [endpoints]);
  const healthyServices = serviceHealth.filter((service) => service.status === "healthy").length;
  const healthyEndpoints = endpoints.filter((endpoint) => endpoint.status === "healthy").length;
  const recentEndpoints = endpoints.slice(0, 6);

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="Platform Overview"
        title="Security operations dashboard"
        description="This dashboard shows live platform information from the running backend services and refreshes automatically every 5 seconds."
        actions={
          <Button variant="secondary" onClick={() => void loadData()} disabled={loading}>
            <RefreshCcw className="mr-2 h-4 w-4" />
            {loading ? "Refreshing..." : "Refresh"}
          </Button>
        }
      />

      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-5">
        <MetricCard label="Total endpoints" value={String(endpoints.length)} change="Live inventory" icon={ShieldCheck} />
        <MetricCard label="Compliant endpoints" value={String(healthyEndpoints)} change="Latest evaluations" icon={ShieldCheck} />
        <MetricCard label="Active policies" value={String(policiesCount)} change="Policy service" icon={Workflow} />
        <MetricCard label="Healthy services" value={`${healthyServices}/${serviceHealth.length || 4}`} change="Platform health" icon={ListChecks} />
        <MetricCard label="Open findings" value={String(alerts.length)} change="Derived from compliance decisions" icon={AlertTriangle} />
      </div>

      <div className="grid gap-6 xl:grid-cols-[1.3fr_1fr]">
        <Card>
          <CardHeader>
            <div>
              <CardTitle>System health</CardTitle>
              <p className="mt-1 text-sm text-slate-400">Live status from the four backend services.</p>
            </div>
          </CardHeader>
          <CardBody className="grid gap-4 md:grid-cols-2">
            {serviceHealth.map((service) => (
              <div key={service.name} className="rounded-2xl border border-border bg-slate-950/35 p-4">
                <div className="flex items-center justify-between gap-3">
                  <div>
                    <p className="font-medium text-white">{service.name}</p>
                    <p className="text-xs text-slate-500">{service.url}</p>
                  </div>
                  <StatusBadge value={service.status} />
                </div>
                <p className="mt-2 text-sm text-slate-400">{service.detail}</p>
              </div>
            ))}
          </CardBody>
        </Card>

        <Card>
          <CardHeader>
            <div>
              <CardTitle>Quick actions</CardTitle>
              <p className="mt-1 text-sm text-slate-400">Shortcuts into the live operational areas.</p>
            </div>
          </CardHeader>
          <CardBody className="space-y-3">
            {[
              { label: "Open endpoints", href: "/endpoints" },
              { label: "Open policies", href: "/policies" },
              { label: "Review alerts", href: "/alerts" },
              { label: "Inspect audit events", href: "/events" }
            ].map((action) => (
              <button
                key={action.href}
                onClick={() => router.push(action.href)}
                className="flex w-full items-center justify-between rounded-2xl border border-border bg-slate-950/40 px-4 py-3 text-left text-sm text-slate-200 transition hover:bg-slate-900"
              >
                {action.label}
                <span className="text-xs uppercase tracking-[0.16em] text-slate-500">Open</span>
              </button>
            ))}
          </CardBody>
        </Card>
      </div>

      <div className="grid gap-6 xl:grid-cols-[1fr_1fr]">
        <Card>
          <CardHeader>
            <div>
              <CardTitle>Recent endpoints</CardTitle>
              <p className="mt-1 text-sm text-slate-400">Newest endpoints seen by telemetry.</p>
            </div>
          </CardHeader>
          <CardBody>
            {recentEndpoints.length === 0 ? (
              <EmptyState
                icon={ShieldCheck}
                title="No endpoints yet"
                description="When collectors submit telemetry, endpoints will appear here automatically."
              />
            ) : (
              <DataTable
                data={recentEndpoints}
                getRowKey={(endpoint) => endpoint.endpointId}
                onRowClick={(endpoint) => router.push(`/endpoints/${endpoint.endpointId}`)}
                columns={[
                  { id: "name", header: "Endpoint", cell: (endpoint) => endpoint.hostname, sortAccessor: (endpoint) => endpoint.hostname },
                  { id: "status", header: "Status", cell: (endpoint) => <StatusBadge value={endpoint.status} />, sortAccessor: (endpoint) => endpoint.status },
                  { id: "ip", header: "IP", cell: (endpoint) => endpoint.ipAddress ?? "Unavailable", sortAccessor: (endpoint) => endpoint.ipAddress ?? "" },
                  { id: "lastSeen", header: "Last seen", cell: (endpoint) => relativeTime(endpoint.lastSeen), sortAccessor: (endpoint) => endpoint.lastSeen }
                ]}
              />
            )}
          </CardBody>
        </Card>

        <Card>
          <CardHeader>
            <div>
              <CardTitle>Recent audit events</CardTitle>
              <p className="mt-1 text-sm text-slate-400">Live events from enforcement audit logging.</p>
            </div>
          </CardHeader>
          <CardBody>
            {auditEvents.length === 0 ? (
              <EmptyState
                icon={Activity}
                title="No audit events yet"
                description="Enforcement and compliance events will appear after decisions are processed."
              />
            ) : (
              <DataTable
                data={auditEvents.slice(0, 10)}
                getRowKey={(event) => `${event.created_at}-${event.event_type}-${event.endpoint_id ?? "platform"}`}
                columns={[
                  { id: "time", header: "Time", cell: (event) => formatDateTime(event.created_at), sortAccessor: (event) => event.created_at },
                  { id: "type", header: "Event type", cell: (event) => event.event_type, sortAccessor: (event) => event.event_type },
                  { id: "endpoint", header: "Endpoint", cell: (event) => event.endpoint_id ?? "Platform", sortAccessor: (event) => event.endpoint_id ?? "" }
                ]}
              />
            )}
          </CardBody>
        </Card>
      </div>
    </div>
  );
}
