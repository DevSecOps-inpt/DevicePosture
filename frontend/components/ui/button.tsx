import type { ButtonHTMLAttributes, PropsWithChildren } from "react";
import { cn } from "@/lib/utils";

type Variant = "primary" | "secondary" | "ghost" | "danger";

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant;
}

const variantClasses: Record<Variant, string> = {
  primary: "bg-accent text-white hover:bg-teal-600",
  secondary: "bg-slate-800 text-slate-100 ring-1 ring-border hover:bg-slate-700",
  ghost: "bg-transparent text-slate-300 hover:bg-slate-800",
  danger: "bg-danger/90 text-white hover:bg-danger"
};

export function Button({
  className,
  variant = "primary",
  children,
  ...props
}: PropsWithChildren<ButtonProps>) {
  return (
    <button
      className={cn(
        "inline-flex items-center justify-center rounded-lg px-4 py-2 text-sm font-medium transition disabled:cursor-not-allowed disabled:opacity-50",
        variantClasses[variant],
        className
      )}
      {...props}
    >
      {children}
    </button>
  );
}
