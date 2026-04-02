"use client";

import { ListTodo } from "lucide-react";
import { EmptyState } from "@/components/ui/empty-state";
import { PageHeader } from "@/components/ui/page-header";

export function TasksPage() {
  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="Background Operations"
        title="Tasks / Jobs"
        description="Track scheduled work, imports, and operational jobs here when a scheduler or jobs API is connected."
      />

      <EmptyState
        icon={ListTodo}
        title="No tasks available"
        description="Queued jobs, retries, and historical task records will appear here once the scheduler service is available."
      />
    </div>
  );
}
