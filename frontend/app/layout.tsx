import type { Metadata } from "next";
import type { ReactNode } from "react";
import { AppShell } from "@/components/layout/app-shell";
import { ToastProvider } from "@/components/ui/toast-provider";
import "./globals.css";

export const metadata: Metadata = {
  title: "Device Posture Control Console",
  description: "Administrative console for endpoint posture, policy, adapters, and platform operations."
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body className="antialiased">
        <ToastProvider>
          <AppShell>{children}</AppShell>
        </ToastProvider>
      </body>
    </html>
  );
}
