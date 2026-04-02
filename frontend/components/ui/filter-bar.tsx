"use client";

import type { ReactNode } from "react";
import { Search } from "lucide-react";

export interface FilterDefinition {
  id: string;
  label: string;
  value: string;
  options: Array<{ label: string; value: string }>;
  onChange: (value: string) => void;
}

export function FilterBar({
  searchValue,
  onSearchChange,
  searchPlaceholder,
  filters,
  actions
}: {
  searchValue: string;
  onSearchChange: (value: string) => void;
  searchPlaceholder: string;
  filters?: FilterDefinition[];
  actions?: ReactNode;
}) {
  return (
    <div className="flex flex-col gap-3 rounded-2xl border border-border bg-slate-950/40 p-4 lg:flex-row lg:items-center lg:justify-between">
      <div className="flex flex-1 flex-col gap-3 lg:flex-row lg:items-center">
        <label className="relative min-w-[240px] flex-1">
          <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-500" />
          <input
            value={searchValue}
            onChange={(event) => onSearchChange(event.target.value)}
            placeholder={searchPlaceholder}
            className="w-full rounded-xl border border-border bg-slate-900 px-10 py-2.5 text-sm text-slate-100 outline-none placeholder:text-slate-500 focus:border-teal-500"
          />
        </label>
        {filters?.map((filter) => (
          <label key={filter.id} className="min-w-[180px]">
            <span className="mb-1 block text-xs uppercase tracking-[0.16em] text-slate-500">{filter.label}</span>
            <select
              value={filter.value}
              onChange={(event) => filter.onChange(event.target.value)}
              className="w-full rounded-xl border border-border bg-slate-900 px-3 py-2.5 text-sm text-slate-100 outline-none focus:border-teal-500"
            >
              {filter.options.map((option) => (
                <option key={option.value} value={option.value}>
                  {option.label}
                </option>
              ))}
            </select>
          </label>
        ))}
      </div>
      {actions ? <div className="flex flex-wrap gap-3">{actions}</div> : null}
    </div>
  );
}
