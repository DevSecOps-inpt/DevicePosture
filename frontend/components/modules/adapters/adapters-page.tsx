"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import { Cable, Plus, RefreshCcw } from "lucide-react";
import { api } from "@/lib/api";
import type { AdapterConfig, AdapterProfileHealth, ServiceStatus } from "@/types/platform";
import { Button } from "@/components/ui/button";
import { Card, CardBody, CardHeader, CardTitle } from "@/components/ui/card";
import { EmptyState } from "@/components/ui/empty-state";
import { PageHeader } from "@/components/ui/page-header";
import { StatusBadge } from "@/components/ui/status-badge";
import { useToast } from "@/components/ui/toast-provider";

type ProfileDraft = {
  profileName: string;
  isActive: boolean;
  baseUrl: string;
  token: string;
  vdom: string;
  quarantineGroup: string;
  timeoutSeconds: string;
  retries: string;
};

function buildDefaultDraft(profileName = "fortigate-default"): ProfileDraft {
  return {
    profileName,
    isActive: true,
    baseUrl: "",
    token: "",
    vdom: "root",
    quarantineGroup: "NON_COMPLIANT_ENDPOINTS",
    timeoutSeconds: "10",
    retries: "3"
  };
}

function buildDraftFromProfile(profile: AdapterConfig): ProfileDraft {
  return {
    profileName: profile.name,
    isActive: profile.is_active,
    baseUrl: String((profile.settings.base_url as string) ?? ""),
    token: String((profile.settings.token as string) ?? ""),
    vdom: String((profile.settings.vdom as string) ?? "root"),
    quarantineGroup: String((profile.settings.quarantine_group as string) ?? "NON_COMPLIANT_ENDPOINTS"),
    timeoutSeconds: String((profile.settings.timeout_seconds as number | string) ?? "10"),
    retries: String((profile.settings.retries as number | string) ?? "3")
  };
}

export function AdaptersPage() {
  const { pushToast } = useToast();
  const [serviceHealth, setServiceHealth] = useState<ServiceStatus[]>([]);
  const [profiles, setProfiles] = useState<AdapterConfig[]>([]);
  const [profileHealth, setProfileHealth] = useState<Record<string, AdapterProfileHealth>>({});
  const [selectedProfileName, setSelectedProfileName] = useState<string | null>(null);
  const [draft, setDraft] = useState<ProfileDraft>(buildDefaultDraft());
  const [loading, setLoading] = useState(true);
  const [refreshingHealth, setRefreshingHealth] = useState(false);
  const refreshInFlight = useRef(false);

  const selectedProfile = useMemo(
    () => profiles.find((item) => item.name === selectedProfileName) ?? null,
    [profiles, selectedProfileName]
  );
  const selectedHealth = selectedProfileName ? profileHealth[selectedProfileName] : undefined;

  const withTimeout = async <T,>(promise: Promise<T>, timeoutMs: number): Promise<T> => {
    return await new Promise<T>((resolve, reject) => {
      const timer = window.setTimeout(() => reject(new Error("Request timed out")), timeoutMs);
      promise
        .then((value) => {
          window.clearTimeout(timer);
          resolve(value);
        })
        .catch((error: unknown) => {
          window.clearTimeout(timer);
          reject(error);
        });
    });
  };

  const refreshRuntimeHealth = async ({
    quiet = true,
    profilesSnapshot
  }: {
    quiet?: boolean;
    profilesSnapshot?: AdapterConfig[];
  } = {}) => {
    if (refreshInFlight.current) {
      return;
    }
    refreshInFlight.current = true;
    setRefreshingHealth(true);
    try {
      const health = await withTimeout(api.getServiceHealth(), 5000);
      setServiceHealth(health);
      try {
        const adapterHealth = await withTimeout(api.listAdapterHealth(), 8000);
        const mapped = Object.fromEntries(adapterHealth.map((item) => [item.name, item]));
        setProfileHealth(mapped);
      } catch {
        const snapshot = profilesSnapshot ?? profiles;
        const fallback = Object.fromEntries(
          snapshot.map((profile) => [
            profile.name,
            {
              name: profile.name,
              adapter: profile.adapter,
              is_active: profile.is_active,
              status: profile.is_active ? "error" : "disabled",
              detail: profile.is_active
                ? "Adapter health probe timed out or adapter service is unreachable."
                : "Profile is disabled",
              checked_at: new Date().toISOString()
            } satisfies AdapterProfileHealth
          ])
        );
        setProfileHealth(fallback);
      }
    } catch (error) {
      const snapshot = profilesSnapshot ?? profiles;
      const fallback = Object.fromEntries(
        snapshot.map((profile) => [
          profile.name,
          {
            name: profile.name,
            adapter: profile.adapter,
            is_active: profile.is_active,
            status: profile.is_active ? "error" : "disabled",
            detail: "Refresh failed because backend services are not reachable.",
            checked_at: new Date().toISOString()
          } satisfies AdapterProfileHealth
        ])
      );
      setProfileHealth(fallback);
      if (!quiet) {
        pushToast({
          tone: "error",
          title: "Failed to refresh adapter health",
          description: error instanceof Error ? error.message : "Unknown error"
        });
      }
    } finally {
      setRefreshingHealth(false);
      refreshInFlight.current = false;
    }
  };

  const loadData = async (preferredProfileName?: string | null) => {
    setLoading(true);
    try {
      const [health, adapters] = await Promise.all([
        api.getServiceHealth(),
        api.listAdapterConfigs()
      ]);
      setServiceHealth(health);

      const fortigateProfiles = adapters
        .filter((item) => item.adapter === "fortigate")
        .sort((a, b) => a.name.localeCompare(b.name));
      setProfiles(fortigateProfiles);
      const seedHealth = Object.fromEntries(
        fortigateProfiles.map((profile) => [
          profile.name,
          {
            name: profile.name,
            adapter: profile.adapter,
            is_active: profile.is_active,
            status: profile.is_active ? "unknown" : "disabled",
            detail: profile.is_active ? "Refreshing adapter health..." : "Profile is disabled",
            checked_at: new Date().toISOString()
          } satisfies AdapterProfileHealth
        ])
      );
      setProfileHealth(seedHealth);

      const targetName =
        preferredProfileName && fortigateProfiles.some((item) => item.name === preferredProfileName)
          ? preferredProfileName
          : selectedProfileName && fortigateProfiles.some((item) => item.name === selectedProfileName)
            ? selectedProfileName
            : fortigateProfiles[0]?.name ?? null;

      setSelectedProfileName(targetName);

      if (targetName) {
        const target = fortigateProfiles.find((item) => item.name === targetName) ?? null;
        setDraft(target ? buildDraftFromProfile(target) : buildDefaultDraft());
      } else {
        setDraft(buildDefaultDraft());
      }
      void refreshRuntimeHealth({ quiet: true, profilesSnapshot: fortigateProfiles });
    } catch (error) {
      pushToast({
        tone: "error",
        title: "Failed to load adapter data",
        description: error instanceof Error ? error.message : "Unknown error"
      });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void loadData();
  }, []);

  useEffect(() => {
    const timer = window.setInterval(() => {
      void refreshRuntimeHealth({ quiet: true });
    }, 10000);
    return () => window.clearInterval(timer);
  }, []);

  const nextProfileName = () => {
    let index = profiles.length + 1;
    let candidate = `fortigate-profile-${index}`;
    const existing = new Set(profiles.map((item) => item.name));
    while (existing.has(candidate)) {
      index += 1;
      candidate = `fortigate-profile-${index}`;
    }
    return candidate;
  };

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="Connectivity"
        title="Adapters"
        description="Create and manage multiple FortiGate profiles. Health is probed live from the backend against each firewall API."
        actions={
          <>
            <Button
              variant="secondary"
              onClick={() => {
                setSelectedProfileName(null);
                setDraft(buildDefaultDraft(nextProfileName()));
              }}
            >
              <Plus className="mr-2 h-4 w-4" />
              New profile
            </Button>
            <Button
              variant="secondary"
              onClick={() => {
                void refreshRuntimeHealth({ quiet: false });
              }}
              disabled={refreshingHealth}
            >
              <RefreshCcw className="mr-2 h-4 w-4" />
              {refreshingHealth ? "Refreshing..." : "Refresh"}
            </Button>
          </>
        }
      />

      <Card>
        <CardHeader>
          <div>
            <CardTitle>FortiGate Profiles</CardTitle>
            <p className="mt-1 text-sm text-slate-400">
              Select an existing profile to edit it, or create a new one. Policies can reference any saved profile name.
            </p>
          </div>
          <StatusBadge value={selectedHealth?.status ?? (draft.isActive ? "unknown" : "disabled")} />
        </CardHeader>
        <CardBody className="space-y-4">
          {profiles.length > 0 ? (
            <div className="grid gap-3 md:grid-cols-2">
              {profiles.map((profile) => {
                const health = profileHealth[profile.name];
                const selected = profile.name === selectedProfileName;
                return (
                  <button
                    key={profile.id}
                    type="button"
                    onClick={() => {
                      setSelectedProfileName(profile.name);
                      setDraft(buildDraftFromProfile(profile));
                    }}
                    className={`rounded-xl border px-4 py-3 text-left transition ${
                      selected ? "border-teal-500 bg-slate-900/90" : "border-border bg-slate-900/50 hover:bg-slate-900/80"
                    }`}
                  >
                    <div className="flex items-center justify-between gap-3">
                      <div>
                        <p className="text-sm font-medium text-white">{profile.name}</p>
                        <p className="text-xs text-slate-400">{String((profile.settings.base_url as string) ?? "No base URL")}</p>
                      </div>
                      <StatusBadge value={health?.status ?? (profile.is_active ? "unknown" : "disabled")} />
                    </div>
                  </button>
                );
              })}
            </div>
          ) : (
            <div className="rounded-xl border border-border bg-slate-900/50 px-4 py-3 text-sm text-slate-400">
              No FortiGate profiles yet. Create one with the <span className="text-white">New profile</span> button.
            </div>
          )}

          <div className="rounded-xl border border-border bg-slate-900/40 px-4 py-3">
            <p className="text-xs uppercase tracking-[0.16em] text-slate-500">Connection state</p>
            <div className="mt-2 flex items-center gap-3">
              <StatusBadge value={selectedHealth?.status ?? (draft.isActive ? "unknown" : "disabled")} />
              <span className="text-sm text-slate-300">
                {selectedHealth?.detail ??
                  (draft.isActive
                    ? "Connection not checked yet. Save or refresh to probe this profile."
                    : "Profile is disabled.")}
              </span>
            </div>
          </div>

          <div className="grid gap-4 md:grid-cols-2">
            <label className="space-y-2">
              <span className="text-sm text-slate-300">Profile name</span>
              <input
                value={draft.profileName}
                onChange={(event) => setDraft((current) => ({ ...current, profileName: event.target.value }))}
                className="w-full rounded-xl border border-border bg-slate-900 px-3 py-2.5 text-sm text-white outline-none focus:border-teal-500"
              />
            </label>
            <label className="flex items-center gap-3 rounded-xl border border-border bg-slate-900 px-3 py-2.5">
              <input
                type="checkbox"
                checked={draft.isActive}
                onChange={(event) => setDraft((current) => ({ ...current, isActive: event.target.checked }))}
              />
              <span className="text-sm text-slate-300">Profile active</span>
            </label>
          </div>
          <div className="grid gap-4 md:grid-cols-2">
            <label className="space-y-2">
              <span className="text-sm text-slate-300">Base URL</span>
              <input
                value={draft.baseUrl}
                onChange={(event) => setDraft((current) => ({ ...current, baseUrl: event.target.value }))}
                placeholder="https://192.168.2.2"
                className="w-full rounded-xl border border-border bg-slate-900 px-3 py-2.5 text-sm text-white outline-none focus:border-teal-500"
              />
            </label>
            <label className="space-y-2">
              <span className="text-sm text-slate-300">API token</span>
              <input
                type="password"
                value={draft.token}
                onChange={(event) => setDraft((current) => ({ ...current, token: event.target.value }))}
                className="w-full rounded-xl border border-border bg-slate-900 px-3 py-2.5 text-sm text-white outline-none focus:border-teal-500"
              />
            </label>
          </div>
          <div className="grid gap-4 md:grid-cols-4">
            <label className="space-y-2">
              <span className="text-sm text-slate-300">VDOM</span>
              <input
                value={draft.vdom}
                onChange={(event) => setDraft((current) => ({ ...current, vdom: event.target.value }))}
                className="w-full rounded-xl border border-border bg-slate-900 px-3 py-2.5 text-sm text-white outline-none focus:border-teal-500"
              />
            </label>
            <label className="space-y-2 md:col-span-2">
              <span className="text-sm text-slate-300">Quarantine group</span>
              <input
                value={draft.quarantineGroup}
                onChange={(event) => setDraft((current) => ({ ...current, quarantineGroup: event.target.value }))}
                className="w-full rounded-xl border border-border bg-slate-900 px-3 py-2.5 text-sm text-white outline-none focus:border-teal-500"
              />
            </label>
            <label className="space-y-2">
              <span className="text-sm text-slate-300">Timeout (s)</span>
              <input
                value={draft.timeoutSeconds}
                onChange={(event) => setDraft((current) => ({ ...current, timeoutSeconds: event.target.value }))}
                className="w-full rounded-xl border border-border bg-slate-900 px-3 py-2.5 text-sm text-white outline-none focus:border-teal-500"
              />
            </label>
          </div>
          <div className="grid gap-4 md:grid-cols-4">
            <label className="space-y-2">
              <span className="text-sm text-slate-300">Retries</span>
              <input
                value={draft.retries}
                onChange={(event) => setDraft((current) => ({ ...current, retries: event.target.value }))}
                className="w-full rounded-xl border border-border bg-slate-900 px-3 py-2.5 text-sm text-white outline-none focus:border-teal-500"
              />
            </label>
          </div>
          <div className="flex justify-end">
            <div className="flex gap-3">
              {selectedProfile ? (
                <Button
                  variant="danger"
                  onClick={async () => {
                    try {
                      await api.deleteAdapterConfig(selectedProfile.name);
                      pushToast({ tone: "success", title: `Profile '${selectedProfile.name}' deleted` });
                      setSelectedProfileName(null);
                      setDraft(buildDefaultDraft(nextProfileName()));
                      await loadData();
                    } catch (error) {
                      pushToast({
                        tone: "error",
                        title: "Failed to delete profile",
                        description: error instanceof Error ? error.message : "Unknown error"
                      });
                    }
                  }}
                >
                  Delete profile
                </Button>
              ) : null}
              <Button
                onClick={async () => {
                  const profileName = draft.profileName.trim();
                  try {
                    await api.upsertAdapterConfig(profileName, {
                      adapter: "fortigate",
                      is_active: draft.isActive,
                      settings: {
                        base_url: draft.baseUrl.trim(),
                        token: draft.token,
                        vdom: draft.vdom.trim(),
                        quarantine_group: draft.quarantineGroup.trim(),
                        timeout_seconds: Number(draft.timeoutSeconds) || 10,
                        retries: Number(draft.retries) || 3
                      }
                    });
                    pushToast({ tone: "success", title: `Profile '${profileName}' saved` });
                    await loadData(profileName);
                  } catch (error) {
                    pushToast({
                      tone: "error",
                      title: "Failed to save profile",
                      description: error instanceof Error ? error.message : "Unknown error"
                    });
                  }
                }}
                disabled={!draft.profileName.trim() || !draft.baseUrl.trim()}
              >
                Save profile
              </Button>
            </div>
          </div>
        </CardBody>
      </Card>

      {serviceHealth.length > 0 ? (
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
          {serviceHealth.map((service) => (
            <Card key={service.name}>
              <CardHeader>
                <div>
                  <CardTitle>{service.name}</CardTitle>
                  <p className="mt-1 text-sm text-slate-400">{service.url}</p>
                </div>
                <StatusBadge value={service.status} />
              </CardHeader>
              <CardBody>
                <p className="text-sm text-slate-400">{service.detail}</p>
              </CardBody>
            </Card>
          ))}
        </div>
      ) : (
        <EmptyState
          icon={Cable}
          title="No service health available"
          description="Service cards will appear once health endpoints are reachable."
        />
      )}
    </div>
  );
}
