import { cn } from "@/lib/utils";

const toneMap: Record<string, string> = {
  healthy: "bg-emerald-500/15 text-emerald-300 ring-emerald-500/20",
  active: "bg-emerald-500/15 text-emerald-300 ring-emerald-500/20",
  connected: "bg-emerald-500/15 text-emerald-300 ring-emerald-500/20",
  installed: "bg-emerald-500/15 text-emerald-300 ring-emerald-500/20",
  completed: "bg-emerald-500/15 text-emerald-300 ring-emerald-500/20",
  warning: "bg-amber-500/15 text-amber-300 ring-amber-500/20",
  degraded: "bg-amber-500/15 text-amber-300 ring-amber-500/20",
  queued: "bg-sky-500/15 text-sky-300 ring-sky-500/20",
  investigating: "bg-sky-500/15 text-sky-300 ring-sky-500/20",
  critical: "bg-rose-500/15 text-rose-300 ring-rose-500/20",
  high: "bg-rose-500/15 text-rose-300 ring-rose-500/20",
  error: "bg-rose-500/15 text-rose-300 ring-rose-500/20",
  open: "bg-rose-500/15 text-rose-300 ring-rose-500/20",
  failed: "bg-rose-500/15 text-rose-300 ring-rose-500/20",
  quarantine: "bg-orange-500/15 text-orange-300 ring-orange-500/20",
  block: "bg-rose-500/15 text-rose-300 ring-rose-500/20",
  allow: "bg-emerald-500/15 text-emerald-300 ring-emerald-500/20",
  isolated: "bg-orange-500/15 text-orange-300 ring-orange-500/20",
  medium: "bg-amber-500/15 text-amber-300 ring-amber-500/20",
  info: "bg-sky-500/15 text-sky-300 ring-sky-500/20",
  low: "bg-slate-500/15 text-slate-300 ring-slate-500/30",
  disabled: "bg-slate-500/15 text-slate-300 ring-slate-500/30",
  inactive: "bg-slate-500/15 text-slate-300 ring-slate-500/30",
  offline: "bg-slate-500/15 text-slate-300 ring-slate-500/30",
  unknown: "bg-slate-500/15 text-slate-300 ring-slate-500/30",
  available: "bg-slate-500/15 text-slate-300 ring-slate-500/30",
  resolved: "bg-emerald-500/15 text-emerald-300 ring-emerald-500/20",
  acknowledged: "bg-indigo-500/15 text-indigo-300 ring-indigo-500/20",
  "upgrade-available": "bg-violet-500/15 text-violet-300 ring-violet-500/20",
  running: "bg-sky-500/15 text-sky-300 ring-sky-500/20",
  cancelled: "bg-slate-500/15 text-slate-300 ring-slate-500/30",
  mitigated: "bg-emerald-500/15 text-emerald-300 ring-emerald-500/20",
  closed: "bg-slate-500/15 text-slate-300 ring-slate-500/30"
};

export function StatusBadge({ value, className }: { value?: string | null; className?: string }) {
  const normalizedValue = value ?? "unknown";

  return (
    <span
      className={cn(
        "inline-flex items-center rounded-full px-2.5 py-1 text-xs font-medium capitalize ring-1",
        toneMap[normalizedValue] ?? "bg-slate-500/15 text-slate-300 ring-slate-500/30",
        className
      )}
    >
      {normalizedValue.replaceAll("-", " ")}
    </span>
  );
}
