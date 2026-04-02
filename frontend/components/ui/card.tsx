import type { PropsWithChildren } from "react";
import { cn } from "@/lib/utils";

interface CardProps {
  className?: string;
}

export function Card({ className, children }: PropsWithChildren<CardProps>) {
  return (
    <section className={cn("rounded-2xl border border-border bg-panel/90 shadow-panel", className)}>
      {children}
    </section>
  );
}

export function CardHeader({ className, children }: PropsWithChildren<CardProps>) {
  return <div className={cn("flex items-center justify-between gap-3 border-b border-border px-5 py-4", className)}>{children}</div>;
}

export function CardTitle({ className, children }: PropsWithChildren<CardProps>) {
  return <h3 className={cn("text-sm font-semibold uppercase tracking-[0.14em] text-slate-400", className)}>{children}</h3>;
}

export function CardBody({ className, children }: PropsWithChildren<CardProps>) {
  return <div className={cn("px-5 py-4", className)}>{children}</div>;
}
