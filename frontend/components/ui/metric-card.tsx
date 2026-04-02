import type { LucideIcon } from "lucide-react";
import { ArrowUpRight } from "lucide-react";
import { Card, CardBody } from "@/components/ui/card";

export function MetricCard({
  label,
  value,
  change,
  icon: Icon
}: {
  label: string;
  value: string;
  change: string;
  icon: LucideIcon;
}) {
  return (
    <Card className="overflow-hidden">
      <CardBody className="space-y-4">
        <div className="flex items-center justify-between">
          <span className="text-sm font-medium text-slate-400">{label}</span>
          <span className="rounded-xl bg-slate-800/80 p-2 text-teal-300">
            <Icon className="h-4 w-4" />
          </span>
        </div>
        <div>
          <div className="text-3xl font-semibold tracking-tight text-white">{value}</div>
          <div className="mt-1 inline-flex items-center gap-1 text-sm text-emerald-300">
            <ArrowUpRight className="h-4 w-4" />
            {change}
          </div>
        </div>
      </CardBody>
    </Card>
  );
}
