import type { PropsWithChildren } from "react";
import { Sidebar } from "@/components/layout/sidebar";
import { Topbar } from "@/components/layout/topbar";

export function AppShell({ children }: PropsWithChildren) {
  return (
    <div className="flex min-h-screen bg-shell text-slate-100">
      <Sidebar />
      <div className="flex min-h-screen flex-1 flex-col bg-grid">
        <Topbar />
        <main className="flex-1 px-4 py-6 sm:px-6 lg:px-8">
          <div className="mx-auto max-w-[1680px]">{children}</div>
        </main>
      </div>
    </div>
  );
}
