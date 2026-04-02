"use client";

import { useEffect, useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import { RefreshCcw, ShieldCheck } from "lucide-react";
import { api } from "@/lib/api";
import { useSmartPolling } from "@/hooks/use-smart-polling";
import type { EndpointActivityStatus, TelemetryRecordResponse } from "@/types/platform";
import { Button } from "@/components/ui/button";
import { Card, CardBody } from "@/components/ui/card";
import { DataTable } from "@/components/ui/data-table";
import { EmptyState } from "@/components/ui/empty-state";
import { FilterBar } from "@/components/ui/filter-bar";
import { PageHeader } from "@/components/ui/page-header";
import { StatusBadge } from "@/components/ui/status-badge";
import { useToast } from "@/components/ui/toast-provider";
import { formatDateTime, relativeTimeFromSeconds } from "@/lib/utils";

type HygieneRow = {
  endpointId: string;
  hostname: string;
  activityStatus: EndpointActivityStatus;
  secondsSinceSeen: number | null;
  ipAddress: string | null;
  osName: string | null;
  osBuild: string | null;
  hotfixCount: number;
  serviceCount: number;
  processCount: number;
  antivirusFamilies: string[];
  enabledCollectors: string[];
  transportEnabled: boolean | null;
  collectedAt: string | null;
};

function normalizeAntivirusFamilies(telemetry: TelemetryRecordResponse | null): string[] {
  const fromProducts =
    telemetry?.raw_payload.antivirus_products?.map((item) =>
      String(item.identifier ?? item.name ?? "").trim().toLowerCase().replace(/\s+/g, "_")
    ) ?? [];
  return Array.from(new Set(fromProducts.filter(Boolean)));
}

function readPayloadCount(payload: TelemetryRecordResponse["raw_payload"] | undefined, key: string, fallbackArrayKey: "hotfixes" | "services" | "processes" | "antivirus_products") {
  const value = payload?.[key];
  if (typeof value === "number" && Number.isFinite(value)) {
    return value;
  }
  return payload?.[fallbackArrayKey]?.length ?? 0;
}

export function ItHygienePage() {
  const router = useRouter();
  const { pushToast } = useToast();
  const [rows, setRows] = useState<HygieneRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState("all");

  const loadData = async ({ silent = false }: { silent?: boolean } = {}) => {
    if (!silent) {
      setLoading(true);
    }
    try {
      const endpoints = await api.listEndpoints();
      const endpointIds = endpoints.map((item) => item.endpoint_id);
      const telemetryBatch = await api.getLatestTelemetryBatch(endpointIds, { includeRaw: false }).catch(() => []);
      const telemetryByEndpoint = Object.fromEntries(telemetryBatch.map((item) => [item.endpoint_id, item]));
      const nextRows: HygieneRow[] = endpoints.map((endpoint) => {
        const telemetry = telemetryByEndpoint[endpoint.endpoint_id] ?? null;
        return {
          endpointId: endpoint.endpoint_id,
          hostname: endpoint.hostname,
          activityStatus: endpoint.activity_status,
          secondsSinceSeen: endpoint.seconds_since_seen,
          ipAddress: telemetry?.core_ipv4 ?? null,
          osName: telemetry?.core_os_name ?? null,
          osBuild: telemetry?.core_os_build ?? null,
          hotfixCount: readPayloadCount(telemetry?.raw_payload, "hotfixes_count", "hotfixes"),
          serviceCount: readPayloadCount(telemetry?.raw_payload, "services_count", "services"),
          processCount: readPayloadCount(telemetry?.raw_payload, "processes_count", "processes"),
          antivirusFamilies: normalizeAntivirusFamilies(telemetry),
          enabledCollectors: telemetry?.raw_payload.agent?.enabled_collectors ?? [],
          transportEnabled: telemetry?.raw_payload.agent?.transport_enabled ?? null,
          collectedAt: telemetry?.collected_at ?? null
        };
      });
      setRows(nextRows);
    } catch (error) {
      if (!silent) {
        pushToast({
          tone: "error",
          title: "Failed to load IT hygiene data",
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
  }, []);
  useSmartPolling(() => loadData({ silent: true }), { visibleIntervalMs: 12000, hiddenIntervalMs: 60000, runImmediately: false });

  const filteredRows = useMemo(() => {
    return rows.filter((row) => {
      const matchesSearch =
        row.hostname.toLowerCase().includes(search.toLowerCase()) ||
        row.endpointId.toLowerCase().includes(search.toLowerCase()) ||
        (row.ipAddress ?? "").includes(search);
      const matchesStatus = statusFilter === "all" || row.activityStatus === statusFilter;
      return matchesSearch && matchesStatus;
    });
  }, [rows, search, statusFilter]);

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="Endpoint Inventory"
        title="IT Hygiene"
        description="Operational endpoint telemetry view: OS/build, KB inventory, services, processes, antivirus families, and collector health."
        actions={
          <Button variant="secondary" onClick={() => void loadData()} disabled={loading}>
            <RefreshCcw className="mr-2 h-4 w-4" />
            {loading ? "Refreshing..." : "Refresh"}
          </Button>
        }
      />

      <FilterBar
        searchValue={search}
        onSearchChange={setSearch}
        searchPlaceholder="Search by endpoint, identifier, or IP"
        filters={[
          {
            id: "status",
            label: "Heartbeat",
            value: statusFilter,
            onChange: setStatusFilter,
            options: [
              { label: "All", value: "all" },
              { label: "Active", value: "active" },
              { label: "Inactive", value: "inactive" },
              { label: "Unknown", value: "unknown" }
            ]
          }
        ]}
      />

      <Card>
        <CardBody className="p-0">
          {filteredRows.length === 0 && !loading ? (
            <EmptyState
              icon={ShieldCheck}
              title="No endpoint telemetry available"
              description="Endpoints will appear here after collectors submit telemetry."
            />
          ) : (
            <DataTable
              data={filteredRows}
              getRowKey={(item) => item.endpointId}
              onRowClick={(item) => router.push(`/endpoints/${item.endpointId}`)}
              columns={[
                {
                  id: "endpoint",
                  header: "Endpoint",
                  cell: (item) => (
                    <div>
                      <div className="font-medium text-white">{item.hostname}</div>
                      <div className="text-xs uppercase tracking-[0.16em] text-slate-500">{item.endpointId}</div>
                    </div>
                  ),
                  sortAccessor: (item) => item.hostname
                },
                {
                  id: "heartbeat",
                  header: "Heartbeat",
                  cell: (item) => <StatusBadge value={item.activityStatus} />,
                  sortAccessor: (item) => item.activityStatus
                },
                {
                  id: "last_seen",
                  header: "Last seen",
                  cell: (item) => relativeTimeFromSeconds(item.secondsSinceSeen),
                  sortAccessor: (item) => item.secondsSinceSeen ?? Number.MAX_SAFE_INTEGER
                },
                {
                  id: "os",
                  header: "OS / Build",
                  cell: (item) => `${item.osName ?? "Unknown"}${item.osBuild ? ` / ${item.osBuild}` : ""}`,
                  sortAccessor: (item) => `${item.osName ?? ""}-${item.osBuild ?? ""}`
                },
                {
                  id: "kbs",
                  header: "KBs",
                  cell: (item) => item.hotfixCount,
                  sortAccessor: (item) => item.hotfixCount
                },
                {
                  id: "services",
                  header: "Services",
                  cell: (item) => item.serviceCount,
                  sortAccessor: (item) => item.serviceCount
                },
                {
                  id: "processes",
                  header: "Processes",
                  cell: (item) => item.processCount,
                  sortAccessor: (item) => item.processCount
                },
                {
                  id: "av",
                  header: "Antivirus families",
                  cell: (item) =>
                    item.antivirusFamilies.length > 0 ? item.antivirusFamilies.join(", ") : "None",
                  sortAccessor: (item) => item.antivirusFamilies.join(",")
                },
                {
                  id: "collectors",
                  header: "Collectors",
                  cell: (item) =>
                    item.enabledCollectors.length > 0 ? item.enabledCollectors.join(", ") : "Default",
                  sortAccessor: (item) => item.enabledCollectors.join(",")
                },
                {
                  id: "transport",
                  header: "Transport",
                  cell: (item) =>
                    item.transportEnabled === null
                      ? "Unknown"
                      : item.transportEnabled
                        ? "Enabled"
                        : "Disabled",
                  sortAccessor: (item) => String(item.transportEnabled)
                },
                {
                  id: "collected_at",
                  header: "Latest payload",
                  cell: (item) => (item.collectedAt ? formatDateTime(item.collectedAt) : "No payload"),
                  sortAccessor: (item) => item.collectedAt ?? ""
                }
              ]}
            />
          )}
        </CardBody>
      </Card>
    </div>
  );
}
