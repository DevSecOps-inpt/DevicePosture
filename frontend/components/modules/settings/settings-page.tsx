"use client";

import { useEffect, useState } from "react";
import { Bell, Save, SunMoon } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardBody, CardHeader, CardTitle } from "@/components/ui/card";
import { PageHeader } from "@/components/ui/page-header";
import { useToast } from "@/components/ui/toast-provider";

export function SettingsPage() {
  const { pushToast } = useToast();
  const [notificationsEnabled, setNotificationsEnabled] = useState(true);
  const [compactView, setCompactView] = useState(false);

  useEffect(() => {
    const storedNotifications = window.localStorage.getItem("device-posture.notifications");
    const storedCompactView = window.localStorage.getItem("device-posture.compact-view");
    if (storedNotifications !== null) {
      setNotificationsEnabled(storedNotifications === "true");
    }
    if (storedCompactView !== null) {
      setCompactView(storedCompactView === "true");
    }
  }, []);

  const savePreferences = () => {
    window.localStorage.setItem("device-posture.notifications", String(notificationsEnabled));
    window.localStorage.setItem("device-posture.compact-view", String(compactView));
    pushToast({ tone: "success", title: "Preferences saved locally" });
  };

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="Platform Settings"
        title="Settings"
        description="Manage local workspace preferences for this admin console."
        actions={
          <Button onClick={savePreferences}>
            <Save className="mr-2 h-4 w-4" />
            Save preferences
          </Button>
        }
      />

      <div className="grid gap-6 xl:grid-cols-2">
        <Card>
          <CardHeader>
            <div className="flex items-center gap-3">
              <Bell className="h-5 w-5 text-teal-300" />
              <CardTitle>User preferences</CardTitle>
            </div>
          </CardHeader>
          <CardBody className="space-y-4">
            <label className="flex items-center justify-between rounded-2xl border border-border bg-slate-950/35 px-4 py-3">
              <span className="text-sm text-slate-300">Enable in-app notifications</span>
              <input type="checkbox" checked={notificationsEnabled} onChange={(event) => setNotificationsEnabled(event.target.checked)} />
            </label>
            <label className="flex items-center justify-between rounded-2xl border border-border bg-slate-950/35 px-4 py-3">
              <span className="text-sm text-slate-300">Compact table density</span>
              <input type="checkbox" checked={compactView} onChange={(event) => setCompactView(event.target.checked)} />
            </label>
          </CardBody>
        </Card>

        <Card>
          <CardHeader>
            <div className="flex items-center gap-3">
              <SunMoon className="h-5 w-5 text-teal-300" />
              <CardTitle>Workspace notes</CardTitle>
            </div>
          </CardHeader>
          <CardBody>
            <p className="text-sm text-slate-400">
              Additional platform settings such as access control, token management, and adapter defaults can be connected here as those services come online.
            </p>
          </CardBody>
        </Card>
      </div>
    </div>
  );
}
