"use client";

import { Puzzle } from "lucide-react";
import { EmptyState } from "@/components/ui/empty-state";
import { PageHeader } from "@/components/ui/page-header";

export function ExtensionsPage() {
  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="Add-ons"
        title="Extensions / Integrations"
        description="Extension inventory and lifecycle controls can appear here once an extension registry is connected."
      />

      <EmptyState
        icon={Puzzle}
        title="No extensions available"
        description="Installed and available extensions will appear here once an extension registry is connected."
      />
    </div>
  );
}
