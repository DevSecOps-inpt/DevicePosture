"use client";

import { useState } from "react";
import { ShieldCheck } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardBody, CardHeader, CardTitle } from "@/components/ui/card";
import { useToast } from "@/components/ui/toast-provider";
import { useAuth } from "@/components/auth/auth-provider";

export function LoginScreen() {
  const { login } = useAuth();
  const { pushToast } = useToast();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [submitting, setSubmitting] = useState(false);

  return (
    <div className="flex min-h-screen items-center justify-center bg-shell px-6">
      <Card className="w-full max-w-md">
        <CardHeader>
          <div className="flex items-center gap-3">
            <div className="rounded-xl bg-accentSoft p-3 text-teal-300">
              <ShieldCheck className="h-6 w-6" />
            </div>
            <div>
              <CardTitle>Sign in to Device Posture</CardTitle>
              <p className="mt-1 text-sm text-slate-400">Authentication checks local accounts first, then enabled external providers by priority.</p>
            </div>
          </div>
        </CardHeader>
        <CardBody className="space-y-4">
          <label className="space-y-2">
            <span className="text-sm text-slate-300">Username</span>
            <input
              value={username}
              onChange={(event) => setUsername(event.target.value)}
              className="w-full rounded-xl border border-border bg-slate-900 px-3 py-2.5 text-sm text-white outline-none focus:border-teal-500"
            />
          </label>
          <label className="space-y-2">
            <span className="text-sm text-slate-300">Password</span>
            <input
              type="password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              className="w-full rounded-xl border border-border bg-slate-900 px-3 py-2.5 text-sm text-white outline-none focus:border-teal-500"
            />
          </label>
          <p className="rounded-xl border border-border bg-slate-900/60 px-3 py-2 text-xs text-slate-400">
            Authentication flow is secure-by-default: local account is checked first, then enabled external providers by configured priority.
          </p>
          <Button
            className="w-full"
            disabled={!username.trim() || !password || submitting}
            onClick={async () => {
              setSubmitting(true);
              try {
                await login({ username: username.trim(), password });
                pushToast({ tone: "success", title: "Login successful" });
              } catch (error) {
                pushToast({
                  tone: "error",
                  title: "Login failed",
                  description: error instanceof Error ? error.message : "Unknown error"
                });
              } finally {
                setSubmitting(false);
              }
            }}
          >
            {submitting ? "Signing in..." : "Sign in"}
          </Button>
        </CardBody>
      </Card>
    </div>
  );
}
