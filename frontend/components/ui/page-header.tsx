import type { ReactNode } from "react";

export function PageHeader({
  eyebrow,
  title,
  description,
  actions
}: {
  eyebrow: string;
  title: string;
  description: string;
  actions?: ReactNode;
}) {
  return (
    <div className="flex flex-col gap-4 border-b border-border pb-5 lg:flex-row lg:items-end lg:justify-between">
      <div className="space-y-2">
        <p className="text-xs font-semibold uppercase tracking-[0.18em] text-teal-300">{eyebrow}</p>
        <div>
          <h1 className="text-3xl font-semibold tracking-tight text-white">{title}</h1>
          <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-400">{description}</p>
        </div>
      </div>
      {actions ? <div className="flex flex-wrap items-center gap-3">{actions}</div> : null}
    </div>
  );
}
