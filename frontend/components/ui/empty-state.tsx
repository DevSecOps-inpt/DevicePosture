import type { LucideIcon } from "lucide-react";
import { Card, CardBody } from "@/components/ui/card";

export function EmptyState({
  icon: Icon,
  title,
  description,
  action
}: {
  icon: LucideIcon;
  title: string;
  description: string;
  action?: React.ReactNode;
}) {
  return (
    <Card>
      <CardBody className="flex flex-col items-start gap-4 py-12">
        <div className="rounded-2xl bg-slate-900/80 p-4 text-teal-300">
          <Icon className="h-6 w-6" />
        </div>
        <div className="space-y-2">
          <h3 className="text-xl font-semibold text-white">{title}</h3>
          <p className="max-w-2xl text-sm leading-6 text-slate-400">{description}</p>
        </div>
        {action}
      </CardBody>
    </Card>
  );
}
