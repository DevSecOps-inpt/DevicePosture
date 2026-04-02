"use client";

import { useRouter } from "next/navigation";
import { Cable } from "lucide-react";
import { Button } from "@/components/ui/button";
import { EmptyState } from "@/components/ui/empty-state";
import { PageHeader } from "@/components/ui/page-header";

export function AdapterDetailPage({ adapterId }: { adapterId: string }) {
  const router = useRouter();

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="Adapter Detail"
        title={adapterId}
        description="This route is reserved for adapter resources once adapter inventory and configuration APIs are available."
        actions={
          <Button variant="ghost" onClick={() => router.push("/adapters")}>
            Back to adapters
          </Button>
        }
      />

      <EmptyState
        icon={Cable}
        title="Adapter detail unavailable"
        description="Adapter inventory and configuration details will appear here when an adapter management API is connected."
      />
    </div>
  );
}
