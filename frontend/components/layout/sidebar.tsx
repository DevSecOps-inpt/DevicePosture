"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { ShieldCheck } from "lucide-react";
import { navigationGroups } from "@/lib/navigation";
import { cn } from "@/lib/utils";

export function Sidebar() {
  const pathname = usePathname();

  return (
    <aside className="hidden w-72 shrink-0 border-r border-border bg-slate-950/85 lg:flex lg:flex-col">
      <div className="border-b border-border px-6 py-6">
        <div className="flex items-center gap-3">
          <div className="rounded-2xl bg-accentSoft p-3 text-teal-300">
            <ShieldCheck className="h-6 w-6" />
          </div>
          <div>
            <p className="text-xs font-semibold uppercase tracking-[0.18em] text-teal-300">Device Posture</p>
            <h1 className="text-lg font-semibold text-white">Control Console</h1>
          </div>
        </div>
      </div>

      <div className="flex-1 space-y-8 overflow-y-auto px-4 py-6">
        {navigationGroups.map((group) => (
          <div key={group.title}>
            <p className="px-3 text-xs font-semibold uppercase tracking-[0.16em] text-slate-500">{group.title}</p>
            <nav className="mt-3 space-y-1">
              {group.items.map((item) => {
                const active = pathname === item.href || pathname.startsWith(`${item.href}/`);
                const Icon = item.icon;
                return (
                  <Link
                    key={item.href}
                    href={item.href}
                    className={cn(
                      "flex items-center gap-3 rounded-xl px-3 py-2.5 text-sm font-medium transition",
                      active ? "bg-accentSoft text-white ring-1 ring-teal-500/30" : "text-slate-400 hover:bg-slate-900 hover:text-slate-100"
                    )}
                  >
                    <Icon className="h-4 w-4" />
                    {item.label}
                  </Link>
                );
              })}
            </nav>
          </div>
        ))}
      </div>

      <div className="border-t border-border px-6 py-5 text-sm text-slate-400">
        <div className="rounded-2xl bg-slate-900/70 p-4">
          <p className="text-xs font-semibold uppercase tracking-[0.16em] text-slate-500">Workspace</p>
          <p className="mt-2 font-medium text-slate-100">Operations / Production</p>
          <p className="mt-1 text-xs text-slate-500">Live data shown per connected service modules</p>
        </div>
      </div>
    </aside>
  );
}
