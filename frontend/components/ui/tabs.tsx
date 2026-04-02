"use client";

import { cn } from "@/lib/utils";

export function Tabs({
  tabs,
  value,
  onChange
}: {
  tabs: Array<{ label: string; value: string }>;
  value: string;
  onChange: (value: string) => void;
}) {
  return (
    <div className="inline-flex flex-wrap gap-2 rounded-2xl border border-border bg-slate-950/40 p-1">
      {tabs.map((tab) => (
        <button
          key={tab.value}
          type="button"
          onClick={() => onChange(tab.value)}
          className={cn(
            "rounded-xl px-3 py-2 text-sm font-medium transition",
            value === tab.value ? "bg-accent text-white" : "text-slate-400 hover:bg-slate-800 hover:text-slate-100"
          )}
        >
          {tab.label}
        </button>
      ))}
    </div>
  );
}
