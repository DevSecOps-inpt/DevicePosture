"use client";

import { useEffect, useMemo, useState } from "react";
import { Activity } from "lucide-react";
import { api } from "@/lib/api";
import type { AuditEvent } from "@/types/platform";
import { Card, CardBody, CardHeader, CardTitle } from "@/components/ui/card";
import { DataTable } from "@/components/ui/data-table";
import { EmptyState } from "@/components/ui/empty-state";
import { FilterBar } from "@/components/ui/filter-bar";
import { PageHeader } from "@/components/ui/page-header";
import { useToast } from "@/components/ui/toast-provider";
import { formatDateTime } from "@/lib/utils";

export function EventsPage() {
  const { pushToast } = useToast();
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [search, setSearch] = useState("");
  const [typeFilter, setTypeFilter] = useState("all");
  const [selectedEvent, setSelectedEvent] = useState<AuditEvent | null>(null);

  const loadEvents = async () => {
    try {
      const loaded = await api.listAuditEvents();
      setEvents(loaded);
      setSelectedEvent(loaded[0] ?? null);
    } catch (error) {
      pushToast({
        tone: "error",
        title: "Failed to load events",
        description: error instanceof Error ? error.message : "Unknown error"
      });
    }
  };

  useEffect(() => {
    loadEvents();
  }, []);

  const eventTypes = Array.from(new Set(events.map((event) => event.event_type)));
  const filtered = useMemo(() => {
    return events.filter((event) => {
      const payloadString = JSON.stringify(event.payload);
      const matchesSearch =
        event.event_type.toLowerCase().includes(search.toLowerCase()) ||
        (event.endpoint_id ?? "").toLowerCase().includes(search.toLowerCase()) ||
        payloadString.toLowerCase().includes(search.toLowerCase());
      return matchesSearch && (typeFilter === "all" || event.event_type === typeFilter);
    });
  }, [events, search, typeFilter]);

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="Operational Telemetry"
        title="Events / Logs"
        description="Browse the audit stream emitted by the enforcement service."
      />

      <FilterBar
        searchValue={search}
        onSearchChange={setSearch}
        searchPlaceholder="Search by event type, endpoint, or payload text"
        filters={[
          {
            id: "type",
            label: "Event type",
            value: typeFilter,
            onChange: setTypeFilter,
            options: [{ label: "All event types", value: "all" }, ...eventTypes.map((type) => ({ label: type, value: type }))]
          }
        ]}
      />

      {filtered.length === 0 ? (
        <EmptyState
          icon={Activity}
          title="No audit events found"
          description="Events will appear here after evaluations and enforcement actions create audit records."
        />
      ) : (
        <div className="grid gap-6 xl:grid-cols-[1.35fr_0.95fr]">
          <Card>
            <CardBody className="p-0">
              <DataTable
                data={filtered}
                getRowKey={(event) => `${event.created_at}-${event.event_type}-${event.endpoint_id ?? "platform"}`}
                onRowClick={setSelectedEvent}
                columns={[
                  { id: "time", header: "Timestamp", cell: (event) => formatDateTime(event.created_at), sortAccessor: (event) => event.created_at },
                  { id: "type", header: "Event type", cell: (event) => event.event_type, sortAccessor: (event) => event.event_type },
                  { id: "endpoint", header: "Endpoint", cell: (event) => event.endpoint_id ?? "Platform", sortAccessor: (event) => event.endpoint_id ?? "" }
                ]}
              />
            </CardBody>
          </Card>

          <Card>
            <CardHeader>
              <div>
                <CardTitle>Event detail</CardTitle>
                <p className="mt-1 text-sm text-slate-400">Payload from the selected audit event.</p>
              </div>
            </CardHeader>
            <CardBody className="space-y-4">
              {selectedEvent ? (
                <>
                  <div>
                    <p className="text-xs uppercase tracking-[0.16em] text-slate-500">Type</p>
                    <p className="mt-1 text-sm text-white">{selectedEvent.event_type}</p>
                  </div>
                  <div>
                    <p className="text-xs uppercase tracking-[0.16em] text-slate-500">Created</p>
                    <p className="mt-1 text-sm text-white">{formatDateTime(selectedEvent.created_at)}</p>
                  </div>
                  <div>
                    <p className="text-xs uppercase tracking-[0.16em] text-slate-500">Endpoint</p>
                    <p className="mt-1 text-sm text-white">{selectedEvent.endpoint_id ?? "Platform-wide event"}</p>
                  </div>
                  <div>
                    <p className="text-xs uppercase tracking-[0.16em] text-slate-500">Payload</p>
                    <pre className="mt-2 overflow-auto rounded-2xl border border-border bg-slate-950/40 p-4 text-xs text-slate-300">
                      {JSON.stringify(selectedEvent.payload, null, 2)}
                    </pre>
                  </div>
                </>
              ) : (
                <p className="text-sm text-slate-400">Select an event to inspect its payload.</p>
              )}
            </CardBody>
          </Card>
        </div>
      )}
    </div>
  );
}
