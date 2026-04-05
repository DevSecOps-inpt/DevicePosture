import type {
  AlertView,
  EndpointActivityStatus,
  ComplianceDecision,
  EndpointStatus,
  EndpointSummary,
  EndpointView,
  Policy,
  TelemetryRecordResponse
} from "@/types/platform";

export function decisionToStatus(decision: ComplianceDecision | null): EndpointStatus {
  if (!decision) {
    return "unknown";
  }
  if (decision.compliant) {
    return "healthy";
  }
  if (decision.recommended_action === "quarantine" || decision.recommended_action === "block") {
    return "critical";
  }
  return "warning";
}

export function activityToStatus(activityStatus: EndpointActivityStatus, decision: ComplianceDecision | null): EndpointStatus {
  if (activityStatus === "inactive") {
    return "inactive";
  }
  return decisionToStatus(decision);
}

export function scoreFromDecision(decision: ComplianceDecision | null): number | null {
  if (!decision) {
    return null;
  }
  if (decision.compliant) {
    return 100;
  }
  return Math.max(20, 100 - decision.reasons.length * 25);
}

export function buildEndpointView(args: {
  endpoint: EndpointSummary;
  telemetry: TelemetryRecordResponse | null;
  policy: Policy | null;
  decision: ComplianceDecision | null;
  enforcement: EndpointView["latestEnforcement"];
  assignedPolicies?: Array<{ id: number; name: string }>;
}): EndpointView {
  const { endpoint, telemetry, policy, decision, enforcement, assignedPolicies } = args;
  return {
    endpointId: endpoint.endpoint_id,
    hostname: endpoint.hostname,
    status: activityToStatus(endpoint.activity_status, decision),
    activityStatus: endpoint.activity_status,
    ipAddress: telemetry?.source_ip ?? telemetry?.core_ipv4 ?? null,
    osType: telemetry?.core_os_name ?? null,
    osBuild: telemetry?.core_os_build ?? null,
    lastSeen: endpoint.last_seen,
    lastCollectedAt: endpoint.last_collected_at,
    expectedIntervalSeconds: endpoint.expected_interval_seconds,
    activityTimeoutSeconds: endpoint.activity_timeout_seconds,
    secondsSinceSeen: endpoint.seconds_since_seen,
    policyName: policy?.name ?? decision?.policy_name ?? null,
    policyId: policy?.id ?? decision?.policy_id ?? null,
    assignedPolicies: assignedPolicies ?? [],
    healthScore: endpoint.activity_status === "inactive" ? 0 : scoreFromDecision(decision),
    latestTelemetry: telemetry,
    latestDecision: decision,
    latestEnforcement: enforcement
  };
}

export function buildAlertsFromEndpoints(endpoints: EndpointView[]): AlertView[] {
  const alerts: AlertView[] = [];

  for (const endpoint of endpoints) {
    if (endpoint.activityStatus === "inactive") {
      alerts.push({
        id: `alert-heartbeat-${endpoint.endpointId}`,
        title: `Endpoint ${endpoint.hostname} missed its telemetry window`,
        severity: "high",
        source: "telemetry-api",
        relatedResource: endpoint.endpointId,
        status: "open",
        createdAt: endpoint.lastSeen,
        assignedTo: "Unassigned"
      });
    }

    if (endpoint.latestDecision && !endpoint.latestDecision.compliant) {
      alerts.push({
        id: `alert-compliance-${endpoint.endpointId}`,
        title:
          endpoint.latestDecision.reasons[0]?.message ??
          `Endpoint ${endpoint.hostname} is non-compliant`,
        severity:
          endpoint.status === "critical"
            ? "critical"
            : endpoint.latestDecision.reasons.length > 1
              ? "high"
              : "medium",
        source: "evaluation-engine",
        relatedResource: endpoint.endpointId,
        status: endpoint.latestEnforcement?.status === "success" ? "investigating" : "open",
        createdAt: endpoint.latestDecision.evaluated_at ?? endpoint.lastSeen,
        assignedTo: "Unassigned"
      });
    }
  }

  return alerts;
}
