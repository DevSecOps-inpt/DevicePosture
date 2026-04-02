"use client";

import { useEffect, useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import { ArrowLeft, RefreshCcw, ShieldOff, ShieldPlus } from "lucide-react";
import { api } from "@/lib/api";
import { buildEndpointView } from "@/lib/platform-data";
import type { AuditEvent, ComplianceDecision, EndpointView, Policy, TelemetryRecordResponse } from "@/types/platform";
import { Button } from "@/components/ui/button";
import { Card, CardBody, CardHeader, CardTitle } from "@/components/ui/card";
import { DataTable } from "@/components/ui/data-table";
import { EmptyState } from "@/components/ui/empty-state";
import { Modal } from "@/components/ui/modal";
import { PageHeader } from "@/components/ui/page-header";
import { StatusBadge } from "@/components/ui/status-badge";
import { useToast } from "@/components/ui/toast-provider";
import { formatDateTime, relativeTime, relativeTimeFromSeconds } from "@/lib/utils";

export function EndpointDetailPage({ endpointId }: { endpointId: string }) {
  const router = useRouter();
  const { pushToast } = useToast();
  const [loading, setLoading] = useState(true);
  const [endpoint, setEndpoint] = useState<EndpointView | null>(null);
  const [telemetryHistory, setTelemetryHistory] = useState<TelemetryRecordResponse[]>([]);
  const [decisionHistory, setDecisionHistory] = useState<ComplianceDecision[]>([]);
  const [policy, setPolicy] = useState<Policy | null>(null);
  const [policies, setPolicies] = useState<Policy[]>([]);
  const [auditEvents, setAuditEvents] = useState<AuditEvent[]>([]);
  const [assignmentModalOpen, setAssignmentModalOpen] = useState(false);
  const [assignmentPolicyId, setAssignmentPolicyId] = useState<number | null>(null);

  const loadData = async ({ silent = false }: { silent?: boolean } = {}) => {
    if (!silent) {
      setLoading(true);
    }
    try {
      const endpoints = await api.listEndpoints();
      const endpointSummary = endpoints.find((item) => item.endpoint_id === endpointId);
      if (!endpointSummary) {
        setEndpoint(null);
        return;
      }

      const [latestTelemetry, latestDecision, resolvedPolicy, latestEnforcement, telemetry, decisions, events, policyItems] =
        await Promise.all([
          api.getLatestTelemetry(endpointId).catch(() => null),
          api.getLatestDecision(endpointId).catch(() => null),
          api.resolvePolicy(endpointId).catch(() => null),
          api.getLatestEnforcement(endpointId).catch(() => null),
          api.getTelemetryHistory(endpointId).catch(() => []),
          api.getDecisionHistory(endpointId).catch(() => []),
          api.listAuditEvents().catch(() => []),
          api.listPolicies().catch(() => [])
        ]);

      setEndpoint(
        buildEndpointView({
          endpoint: endpointSummary,
          telemetry: latestTelemetry,
          policy: resolvedPolicy,
          decision: latestDecision,
          enforcement: latestEnforcement
        })
      );
      setTelemetryHistory(telemetry);
      setDecisionHistory(decisions);
      setPolicy(resolvedPolicy);
      setPolicies(policyItems);
      if (policyItems.length > 0 && assignmentPolicyId === null) {
        setAssignmentPolicyId(policyItems[0].id);
      }
      setAuditEvents(events.filter((event) => event.endpoint_id === endpointId));
    } catch (error) {
      if (!silent) {
        pushToast({
          tone: "error",
          title: "Failed to load endpoint",
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
  }, [endpointId]);

  const antivirusProducts = useMemo(
    () => endpoint?.latestTelemetry?.raw_payload.antivirus_products ?? [],
    [endpoint]
  );
  const latestPayload = endpoint?.latestTelemetry?.raw_payload ?? null;
  const hotfixRows = useMemo(
    () =>
      (latestPayload?.hotfixes ?? []).map((item, index) => ({
        ...item,
        rowId: `${item.id}-${index}`
      })),
    [latestPayload]
  );
  const serviceRows = useMemo(
    () =>
      (latestPayload?.services ?? []).map((item, index) => ({
        ...item,
        rowId: `${item.name}-${index}`
      })),
    [latestPayload]
  );
  const processRows = useMemo(
    () =>
      (latestPayload?.processes ?? []).map((item, index) => ({
        ...item,
        rowId: `${item.name}-${item.pid ?? "na"}-${index}`
      })),
    [latestPayload]
  );
  const additionalPayload = useMemo(() => {
    if (!latestPayload) {
      return {};
    }
    const {
      agent: _agent,
      hotfixes: _hotfixes,
      services: _services,
      processes: _processes,
      antivirus_products: _antivirusProducts,
      extras,
      ...rest
    } = latestPayload as Record<string, unknown>;
    return {
      ...(typeof extras === "object" && extras !== null ? (extras as Record<string, unknown>) : {}),
      ...rest
    };
  }, [latestPayload]);

  if (!loading && !endpoint) {
    return (
      <EmptyState
        icon={ShieldPlus}
        title="Endpoint not found"
        description="This endpoint does not exist in telemetry-api yet, or no real telemetry has been stored for it."
        action={
          <Button onClick={() => router.push("/endpoints")}>Return to endpoints</Button>
        }
      />
    );
  }

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="Endpoint Detail"
        title={endpoint?.hostname ?? endpointId}
        description="Live endpoint metadata, heartbeat cadence, policy assignment, evaluation history, and enforcement status. This page refreshes every 5 seconds."
        actions={
          <>
            <Button variant="ghost" onClick={() => router.push("/endpoints")}>
              <ArrowLeft className="mr-2 h-4 w-4" />
              Back to list
            </Button>
            <Button
              variant="secondary"
              onClick={() => setAssignmentModalOpen(true)}
              disabled={loading || policies.length === 0}
            >
              Assign policy
            </Button>
            <Button
              variant="secondary"
              onClick={async () => {
                try {
                  await api.evaluateEndpoint(endpointId);
                  pushToast({ tone: "success", title: "Evaluation completed" });
                  await loadData();
                } catch (error) {
                  pushToast({
                    tone: "error",
                    title: "Evaluation failed",
                    description: error instanceof Error ? error.message : "Unknown error"
                  });
                }
              }}
              disabled={loading}
            >
              <RefreshCcw className="mr-2 h-4 w-4" />
              Evaluate now
            </Button>
            <Button
              onClick={async () => {
                if (!endpoint?.ipAddress) {
                  pushToast({ tone: "info", title: "No IP address available for this endpoint" });
                  return;
                }
                try {
                  await api.quarantineEndpoint(endpoint.endpointId, endpoint.ipAddress, endpoint.latestDecision);
                  pushToast({ tone: "success", title: "Quarantine action submitted" });
                  await loadData();
                } catch (error) {
                  pushToast({
                    tone: "error",
                    title: "Quarantine failed",
                    description: error instanceof Error ? error.message : "Unknown error"
                  });
                }
              }}
              disabled={loading}
            >
              <ShieldOff className="mr-2 h-4 w-4" />
              Isolate
            </Button>
          </>
        }
      />

      <div className="grid gap-6 xl:grid-cols-[1.3fr_1fr]">
        <Card>
          <CardHeader>
            <div>
              <CardTitle>Live metadata</CardTitle>
              <p className="mt-1 text-sm text-slate-400">Real identity and posture metadata returned by the backend.</p>
            </div>
              {endpoint ? <StatusBadge value={endpoint.status} /> : null}
          </CardHeader>
          <CardBody className="grid gap-4 md:grid-cols-2">
              {[
                ["Endpoint ID", endpoint?.endpointId ?? endpointId],
                ["Hostname", endpoint?.hostname ?? "Unavailable"],
                ["IP address", endpoint?.ipAddress ?? "Unavailable"],
                ["OS", endpoint?.osType ?? "Unavailable"],
                ["OS build", endpoint?.osBuild ?? "Unavailable"],
                [
                  "Last seen",
                  endpoint
                    ? endpoint.secondsSinceSeen !== null && endpoint.secondsSinceSeen !== undefined
                      ? relativeTimeFromSeconds(endpoint.secondsSinceSeen)
                      : relativeTime(endpoint.lastSeen)
                    : "Unavailable"
                ],
                ["Last collected", endpoint?.lastCollectedAt ? formatDateTime(endpoint.lastCollectedAt) : "Unavailable"],
                [
                  "Expected cadence",
                  endpoint && endpoint.expectedIntervalSeconds !== null ? `${endpoint.expectedIntervalSeconds}s` : "Unavailable"
                ],
                [
                  "Heartbeat timeout",
                  endpoint && endpoint.activityTimeoutSeconds !== null ? `${endpoint.activityTimeoutSeconds}s` : "Unavailable"
                ]
              ].map(([label, value]) => (
                <div key={label} className="rounded-2xl border border-border bg-slate-950/35 p-4">
                  <p className="text-xs uppercase tracking-[0.16em] text-slate-500">{label}</p>
                <p className="mt-2 text-sm font-medium text-slate-100">{value}</p>
              </div>
            ))}
          </CardBody>
        </Card>

        <Card>
          <CardHeader>
            <div>
              <CardTitle>Current posture</CardTitle>
              <p className="mt-1 text-sm text-slate-400">Latest evaluation and enforcement result.</p>
            </div>
          </CardHeader>
          <CardBody className="space-y-4">
            <div className="rounded-2xl border border-border bg-slate-950/35 p-4">
              <p className="text-xs uppercase tracking-[0.16em] text-slate-500">Heartbeat state</p>
              <div className="mt-2 flex items-center justify-between gap-3">
                <StatusBadge value={endpoint?.activityStatus ?? "unknown"} />
                <span className="text-sm text-slate-400">
                  {endpoint?.secondsSinceSeen !== null && endpoint?.secondsSinceSeen !== undefined
                    ? `${Math.round(endpoint.secondsSinceSeen)}s since last check-in`
                    : "No cadence reported"}
                </span>
              </div>
            </div>
            <div className="rounded-2xl border border-border bg-slate-950/35 p-4">
              <p className="text-xs uppercase tracking-[0.16em] text-slate-500">Assigned policy</p>
              <p className="mt-2 text-sm font-medium text-slate-100">{policy?.name ?? "No resolved policy"}</p>
            </div>
            <div className="rounded-2xl border border-border bg-slate-950/35 p-4">
              <p className="text-xs uppercase tracking-[0.16em] text-slate-500">Latest decision</p>
              {endpoint?.latestDecision ? (
                <>
                  <div className="mt-2 flex items-center gap-3">
                    <StatusBadge value={endpoint.status} />
                    <span className="text-sm text-slate-400">{formatDateTime(endpoint.latestDecision.evaluated_at)}</span>
                  </div>
                  <ul className="mt-3 list-disc space-y-1 pl-5 text-sm text-slate-300">
                    {endpoint.latestDecision.reasons.length > 0 ? (
                      endpoint.latestDecision.reasons.map((reason) => <li key={`${reason.check_type}-${reason.message}`}>{reason.message}</li>)
                    ) : (
                      <li>No failure reasons. Endpoint is compliant.</li>
                    )}
                  </ul>
                </>
              ) : (
                <p className="mt-2 text-sm text-slate-400">No evaluation result yet.</p>
              )}
            </div>
            <div className="rounded-2xl border border-border bg-slate-950/35 p-4">
              <p className="text-xs uppercase tracking-[0.16em] text-slate-500">Latest enforcement</p>
              {endpoint?.latestEnforcement ? (
                <div className="mt-2 flex items-center justify-between gap-3">
                  <StatusBadge value={endpoint.latestEnforcement.status} />
                  <span className="text-sm text-slate-400">{endpoint.latestEnforcement.action}</span>
                </div>
              ) : (
                <p className="mt-2 text-sm text-slate-400">No enforcement record yet.</p>
              )}
            </div>
          </CardBody>
        </Card>
      </div>

      <div className="grid gap-6 xl:grid-cols-[1fr_1fr]">
        <Card>
          <CardHeader>
            <div>
              <CardTitle>Telemetry history</CardTitle>
              <p className="mt-1 text-sm text-slate-400">Recent telemetry submissions for this endpoint.</p>
            </div>
          </CardHeader>
          <CardBody>
            <DataTable
              data={telemetryHistory}
              getRowKey={(record) => String(record.id)}
              columns={[
                { id: "time", header: "Collected", cell: (record) => formatDateTime(record.collected_at), sortAccessor: (record) => record.collected_at },
                { id: "collector", header: "Collector", cell: (record) => record.collector_type, sortAccessor: (record) => record.collector_type },
                { id: "os", header: "OS", cell: (record) => record.core_os_name ?? "Unavailable", sortAccessor: (record) => record.core_os_name ?? "" },
                { id: "ip", header: "IP", cell: (record) => record.core_ipv4 ?? "Unavailable", sortAccessor: (record) => record.core_ipv4 ?? "" }
              ]}
            />
          </CardBody>
        </Card>

        <Card>
          <CardHeader>
            <div>
              <CardTitle>Evaluation history</CardTitle>
              <p className="mt-1 text-sm text-slate-400">Recent compliance decisions stored by the evaluation engine.</p>
            </div>
          </CardHeader>
          <CardBody>
            <DataTable
              data={decisionHistory}
              getRowKey={(decision) => decision.evaluated_at}
              columns={[
                { id: "time", header: "Evaluated", cell: (decision) => formatDateTime(decision.evaluated_at), sortAccessor: (decision) => decision.evaluated_at },
                { id: "status", header: "Status", cell: (decision) => <StatusBadge value={decision.compliant ? "healthy" : decision.recommended_action === "quarantine" ? "critical" : "warning"} />, sortAccessor: (decision) => String(decision.compliant) },
                { id: "action", header: "Action", cell: (decision) => decision.recommended_action, sortAccessor: (decision) => decision.recommended_action },
                { id: "policy", header: "Policy", cell: (decision) => decision.policy_name ?? "Unassigned", sortAccessor: (decision) => decision.policy_name ?? "" }
              ]}
            />
          </CardBody>
        </Card>
      </div>

      <div className="grid gap-6 xl:grid-cols-[1fr_1fr]">
        <Card>
          <CardHeader>
            <div>
              <CardTitle>Collector runtime configuration</CardTitle>
              <p className="mt-1 text-sm text-slate-400">Agent config sent by the collector with latest payload.</p>
            </div>
          </CardHeader>
          <CardBody className="grid gap-3 md:grid-cols-2">
            {[
              ["Agent name", latestPayload?.agent?.name ?? "Unknown"],
              [
                "Interval (s)",
                latestPayload?.agent?.interval_seconds !== undefined && latestPayload?.agent?.interval_seconds !== null
                  ? String(latestPayload.agent.interval_seconds)
                  : "Unknown"
              ],
              [
                "Grace multiplier",
                latestPayload?.agent?.active_grace_multiplier !== undefined &&
                latestPayload?.agent?.active_grace_multiplier !== null
                  ? String(latestPayload.agent.active_grace_multiplier)
                  : "Unknown"
              ],
              [
                "Transport enabled",
                latestPayload?.agent?.transport_enabled !== undefined && latestPayload?.agent?.transport_enabled !== null
                  ? latestPayload.agent.transport_enabled
                    ? "Yes"
                    : "No"
                  : "Unknown"
              ],
              [
                "Enabled collectors",
                (latestPayload?.agent?.enabled_collectors ?? []).length > 0
                  ? latestPayload?.agent?.enabled_collectors?.join(", ")
                  : "Default"
              ]
            ].map(([label, value]) => (
              <div key={String(label)} className="rounded-2xl border border-border bg-slate-950/35 p-4">
                <p className="text-xs uppercase tracking-[0.16em] text-slate-500">{label}</p>
                <p className="mt-2 text-sm text-slate-100">{value}</p>
              </div>
            ))}
          </CardBody>
        </Card>

        <Card>
          <CardHeader>
            <div>
              <CardTitle>Additional endpoint info</CardTitle>
              <p className="mt-1 text-sm text-slate-400">
                Extra non-core telemetry fields included in the latest payload.
              </p>
            </div>
          </CardHeader>
          <CardBody>
            {Object.keys(additionalPayload).length === 0 ? (
              <p className="text-sm text-slate-400">No extra fields reported.</p>
            ) : (
              <pre className="max-h-[320px] overflow-auto rounded-xl border border-border bg-slate-950/40 p-3 text-xs text-slate-200">
                {JSON.stringify(additionalPayload, null, 2)}
              </pre>
            )}
          </CardBody>
        </Card>
      </div>

      <div className="grid gap-6 xl:grid-cols-[1fr_1fr]">
        <Card>
          <CardHeader>
            <div>
              <CardTitle>Installed KB hotfixes (all)</CardTitle>
              <p className="mt-1 text-sm text-slate-400">Complete hotfix list from the latest telemetry payload.</p>
            </div>
          </CardHeader>
          <CardBody>
            <DataTable
              data={hotfixRows}
              getRowKey={(item) => item.rowId}
              columns={[
                { id: "id", header: "KB", cell: (item) => item.id, sortAccessor: (item) => item.id },
                {
                  id: "description",
                  header: "Description",
                  cell: (item) => item.description ?? "N/A",
                  sortAccessor: (item) => item.description ?? ""
                },
                {
                  id: "installed",
                  header: "Installed on",
                  cell: (item) => item.installed_on ?? "N/A",
                  sortAccessor: (item) => item.installed_on ?? ""
                }
              ]}
            />
          </CardBody>
        </Card>

        <Card>
          <CardHeader>
            <div>
              <CardTitle>Installed services (all)</CardTitle>
              <p className="mt-1 text-sm text-slate-400">Complete services list from the latest telemetry payload.</p>
            </div>
          </CardHeader>
          <CardBody>
            <DataTable
              data={serviceRows}
              getRowKey={(item) => item.rowId}
              columns={[
                { id: "name", header: "Service", cell: (item) => item.name, sortAccessor: (item) => item.name },
                {
                  id: "display_name",
                  header: "Display name",
                  cell: (item) => item.display_name ?? "N/A",
                  sortAccessor: (item) => item.display_name ?? ""
                },
                {
                  id: "status",
                  header: "Status",
                  cell: (item) => item.status ?? "Unknown",
                  sortAccessor: (item) => item.status ?? ""
                },
                {
                  id: "start_type",
                  header: "Start type",
                  cell: (item) => item.start_type ?? "Unknown",
                  sortAccessor: (item) => item.start_type ?? ""
                }
              ]}
            />
          </CardBody>
        </Card>
      </div>

      <div className="grid gap-6 xl:grid-cols-[1fr_1fr]">
        <Card>
          <CardHeader>
            <div>
              <CardTitle>Running processes (all)</CardTitle>
              <p className="mt-1 text-sm text-slate-400">Complete process list from the latest telemetry payload.</p>
            </div>
          </CardHeader>
          <CardBody>
            <DataTable
              data={processRows}
              getRowKey={(item) => item.rowId}
              columns={[
                {
                  id: "pid",
                  header: "PID",
                  cell: (item) => (item.pid !== undefined && item.pid !== null ? String(item.pid) : "N/A"),
                  sortAccessor: (item) => item.pid ?? -1
                },
                { id: "name", header: "Process", cell: (item) => item.name, sortAccessor: (item) => item.name }
              ]}
            />
          </CardBody>
        </Card>

        <Card>
          <CardHeader>
            <div>
              <CardTitle>Detected antivirus</CardTitle>
              <p className="mt-1 text-sm text-slate-400">Reported by the latest real telemetry payload.</p>
            </div>
          </CardHeader>
          <CardBody>
            {antivirusProducts.length === 0 ? (
              <EmptyState
                icon={ShieldPlus}
                title="No antivirus products reported"
                description="This endpoint has not reported antivirus products in the latest telemetry payload."
              />
            ) : (
              <div className="space-y-3">
                {antivirusProducts.map((product) => (
                  <div key={`${product.name}-${product.identifier ?? ""}`} className="rounded-2xl border border-border bg-slate-950/35 p-4">
                    <p className="font-medium text-white">{product.name}</p>
                    <p className="mt-1 text-sm text-slate-400">{product.identifier ?? "No identifier reported"}</p>
                  </div>
                ))}
              </div>
            )}
          </CardBody>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <div>
            <CardTitle>Raw telemetry payload (latest)</CardTitle>
            <p className="mt-1 text-sm text-slate-400">Full JSON received from the collector for this endpoint.</p>
          </div>
        </CardHeader>
        <CardBody>
          <pre className="max-h-[500px] overflow-auto rounded-xl border border-border bg-slate-950/40 p-3 text-xs text-slate-200">
            {JSON.stringify(endpoint?.latestTelemetry?.raw_payload ?? {}, null, 2)}
          </pre>
        </CardBody>
      </Card>

      <div className="grid gap-6 xl:grid-cols-[1fr_1fr]">
        <Card>
          <CardHeader>
            <div>
              <CardTitle>Audit events</CardTitle>
              <p className="mt-1 text-sm text-slate-400">Real enforcement audit records for this endpoint.</p>
            </div>
          </CardHeader>
          <CardBody>
            <DataTable
              data={auditEvents}
              getRowKey={(event) => `${event.created_at}-${event.event_type}`}
              columns={[
                { id: "time", header: "Time", cell: (event) => formatDateTime(event.created_at), sortAccessor: (event) => event.created_at },
                { id: "type", header: "Event type", cell: (event) => event.event_type, sortAccessor: (event) => event.event_type }
              ]}
            />
          </CardBody>
        </Card>
      </div>

      <Modal
        open={assignmentModalOpen}
        title="Assign policy to endpoint"
        description="Select one of the existing policies. The newest endpoint assignment becomes effective."
        onClose={() => setAssignmentModalOpen(false)}
        footer={
          <>
            <Button variant="ghost" onClick={() => setAssignmentModalOpen(false)}>
              Cancel
            </Button>
            <Button
              disabled={assignmentPolicyId === null}
              onClick={async () => {
                if (assignmentPolicyId === null) {
                  return;
                }
                try {
                  await api.createAssignment(assignmentPolicyId, {
                    assignment_type: "endpoint",
                    assignment_value: endpointId
                  });
                  pushToast({ tone: "success", title: "Policy assigned to endpoint" });
                  setAssignmentModalOpen(false);
                  await loadData();
                } catch (error) {
                  pushToast({
                    tone: "error",
                    title: "Failed to assign policy",
                    description: error instanceof Error ? error.message : "Unknown error"
                  });
                }
              }}
            >
              Assign policy
            </Button>
          </>
        }
      >
        <div className="grid gap-4">
          <label className="space-y-2">
            <span className="text-sm text-slate-300">Available policies</span>
            <select
              value={assignmentPolicyId === null ? "" : String(assignmentPolicyId)}
              onChange={(event) =>
                setAssignmentPolicyId(event.target.value ? Number(event.target.value) : null)
              }
              className="w-full rounded-xl border border-border bg-slate-900 px-3 py-2.5 text-sm text-white outline-none focus:border-teal-500"
            >
              {policies.length === 0 ? <option value="">No policies available</option> : null}
              {policies.map((item) => (
                <option key={item.id} value={String(item.id)}>
                  {item.name} ({item.policy_scope === "lifecycle" ? "lifecycle" : "posture"})
                </option>
              ))}
            </select>
          </label>
        </div>
      </Modal>
    </div>
  );
}
