"use client";

import { createContext, useCallback, useContext, useMemo, useState } from "react";
import { CheckCircle2, CircleAlert, Info, X } from "lucide-react";
import { cn } from "@/lib/utils";

type ToastTone = "success" | "error" | "info";

interface ToastItem {
  id: number;
  title: string;
  description?: string;
  tone: ToastTone;
}

interface ToastContextValue {
  pushToast: (toast: Omit<ToastItem, "id">) => void;
}

const ToastContext = createContext<ToastContextValue | null>(null);

const toneClasses: Record<ToastTone, string> = {
  success: "border-emerald-500/30 bg-emerald-500/10 text-emerald-100",
  error: "border-rose-500/30 bg-rose-500/10 text-rose-100",
  info: "border-sky-500/30 bg-sky-500/10 text-sky-100"
};

const toneIcons = {
  success: CheckCircle2,
  error: CircleAlert,
  info: Info
};

export function ToastProvider({ children }: { children: React.ReactNode }) {
  const [toasts, setToasts] = useState<ToastItem[]>([]);

  const pushToast = useCallback((toast: Omit<ToastItem, "id">) => {
    const item = { ...toast, id: Date.now() + Math.floor(Math.random() * 1000) };
    setToasts((current) => [...current, item]);
    window.setTimeout(() => {
      setToasts((current) => current.filter((entry) => entry.id !== item.id));
    }, 4000);
  }, []);

  const value = useMemo(() => ({ pushToast }), [pushToast]);

  return (
    <ToastContext.Provider value={value}>
      {children}
      <div className="pointer-events-none fixed right-4 top-4 z-[100] flex w-full max-w-sm flex-col gap-3">
        {toasts.map((toast) => {
          const Icon = toneIcons[toast.tone];
          return (
            <div
              key={toast.id}
              className={cn(
                "pointer-events-auto rounded-2xl border p-4 shadow-panel backdrop-blur",
                toneClasses[toast.tone]
              )}
            >
              <div className="flex items-start gap-3">
                <Icon className="mt-0.5 h-5 w-5 shrink-0" />
                <div className="min-w-0 flex-1">
                  <p className="font-medium">{toast.title}</p>
                  {toast.description ? <p className="mt-1 text-sm opacity-80">{toast.description}</p> : null}
                </div>
                <button
                  type="button"
                  onClick={() => setToasts((current) => current.filter((entry) => entry.id !== toast.id))}
                  className="rounded-lg p-1 opacity-70 transition hover:bg-white/10 hover:opacity-100"
                >
                  <X className="h-4 w-4" />
                </button>
              </div>
            </div>
          );
        })}
      </div>
    </ToastContext.Provider>
  );
}

export function useToast() {
  const context = useContext(ToastContext);
  if (!context) {
    throw new Error("useToast must be used inside ToastProvider");
  }
  return context;
}
