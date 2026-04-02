"use client";

import type { ReactNode } from "react";
import { X } from "lucide-react";
import { Button } from "@/components/ui/button";

export function Modal({
  open,
  title,
  description,
  children,
  footer,
  onClose
}: {
  open: boolean;
  title: string;
  description?: string;
  children: ReactNode;
  footer?: ReactNode;
  onClose: () => void;
}) {
  if (!open) {
    return null;
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/70 p-4 backdrop-blur-sm">
      <div className="w-full max-w-2xl rounded-3xl border border-border bg-panel shadow-panel">
        <div className="flex items-start justify-between gap-4 border-b border-border px-6 py-5">
          <div>
            <h3 className="text-xl font-semibold text-white">{title}</h3>
            {description ? <p className="mt-1 text-sm text-slate-400">{description}</p> : null}
          </div>
          <Button variant="ghost" className="px-2 py-2" onClick={onClose}>
            <X className="h-4 w-4" />
          </Button>
        </div>
        <div className="px-6 py-5">{children}</div>
        {footer ? <div className="flex justify-end gap-3 border-t border-border px-6 py-5">{footer}</div> : null}
      </div>
    </div>
  );
}
