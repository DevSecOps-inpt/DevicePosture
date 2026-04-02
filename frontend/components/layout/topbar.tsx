"use client";

import { Bell, Command, Search } from "lucide-react";
import { usePathname } from "next/navigation";
import { quickSearchSuggestions } from "@/lib/navigation";
import { useAuth } from "@/components/auth/auth-provider";
import { useToast } from "@/components/ui/toast-provider";

const pageNames: Record<string, string> = {
  "/dashboard": "Dashboard",
  "/endpoints": "Endpoints",
  "/policies": "Policies",
  "/objects": "Objects",
  "/adapters": "Adapters",
  "/extensions": "Extensions",
  "/events": "Events / Logs",
  "/tasks": "Tasks / Jobs",
  "/alerts": "Alerts / Findings",
  "/users": "User Administration",
  "/settings": "Settings"
};

export function Topbar() {
  const pathname = usePathname();
  const { user, logout } = useAuth();
  const { pushToast } = useToast();
  const sectionKey = Object.keys(pageNames).find((key) => pathname === key || pathname.startsWith(`${key}/`)) ?? "/dashboard";
  const title = pageNames[sectionKey];
  const suggestionIndex = Math.abs(pathname.length) % quickSearchSuggestions.length;

  return (
    <header className="sticky top-0 z-30 border-b border-border bg-shell/85 px-6 py-4 backdrop-blur">
      <div className="flex flex-col gap-4 xl:flex-row xl:items-center xl:justify-between">
        <div>
          <p className="text-xs font-semibold uppercase tracking-[0.18em] text-slate-500">Operations Console</p>
          <h2 className="mt-1 text-xl font-semibold text-white">{title}</h2>
        </div>

        <div className="flex flex-1 flex-col gap-3 xl:max-w-3xl xl:flex-row xl:items-center xl:justify-end">
          <label className="relative w-full xl:max-w-xl">
            <Search className="pointer-events-none absolute left-4 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-500" />
            <input
              placeholder={quickSearchSuggestions[suggestionIndex]}
              className="w-full rounded-2xl border border-border bg-slate-900/80 px-11 py-3 text-sm text-slate-100 placeholder:text-slate-500 focus:border-teal-500 focus:outline-none"
            />
            <span className="absolute right-3 top-1/2 -translate-y-1/2 rounded-lg border border-border bg-slate-950 px-2 py-1 text-[11px] font-semibold uppercase tracking-[0.16em] text-slate-500">
              <Command className="mr-1 inline h-3 w-3" />
              K
            </span>
          </label>

          <div className="flex items-center gap-3">
            <button
              className="rounded-2xl border border-border bg-slate-900/70 p-3 text-slate-300 transition hover:bg-slate-800"
              onClick={() =>
                pushToast({
                  tone: "info",
                  title: "Notifications center is not implemented yet",
                  description: "This shell action now responds, but a real notifications backend is still pending."
                })
              }
            >
              <Bell className="h-4 w-4" />
            </button>
            <div className="flex items-center gap-3 rounded-2xl border border-border bg-slate-900/70 px-3 py-2.5">
              <div className="flex h-10 w-10 items-center justify-center rounded-full bg-teal-500/15 text-sm font-semibold text-teal-200">
                {user?.username?.slice(0, 2).toUpperCase() ?? "NA"}
              </div>
              <div className="hidden sm:block">
                <p className="text-sm font-medium text-slate-100">{user?.full_name ?? user?.username ?? "Unknown user"}</p>
                <p className="text-xs text-slate-500">
                  {(user?.roles ?? []).join(", ") || "operator"} | {user?.auth_source ?? "local"}
                </p>
              </div>
              <button
                className="rounded-lg border border-border bg-slate-950 px-2 py-1 text-xs text-slate-300 hover:bg-slate-900"
                onClick={async () => {
                  await logout();
                  pushToast({ tone: "info", title: "Signed out" });
                }}
              >
                Sign out
              </button>
            </div>
          </div>
        </div>
      </div>
    </header>
  );
}
