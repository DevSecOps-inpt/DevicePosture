"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import { Cable, Edit, Plus, RefreshCcw, Trash2 } from "lucide-react";
import { api } from "@/lib/api";
import type { AdapterConfig, AdapterProfileHealth, ServiceStatus } from "@/types/platform";
import { Button } from "@/components/ui/button";
import { Card, CardBody, CardHeader, CardTitle } from "@/components/ui/card";
import { EmptyState } from "@/components/ui/empty-state";
import { Modal } from "@/components/ui/modal";
import { PageHeader } from "@/components/ui/page-header";
import { StatusBadge } from "@/components/ui/status-badge";
import { useToast } from "@/components/ui/toast-provider";

type AdapterType = "fortigate" | "cisco" | "paloalto" | "checkpoint" | "custom";

type ProfileDraft = {
  profileName: string;
  adapter: AdapterType;
  isActive: boolean;
  baseUrl: string;
  token: string;
  timeoutSeconds: string;
  retries: string;
  targetGroup: string;
  scope: string;
};

const ADAPTER_OPTIONS: Array<{ value: AdapterType; label: string }> = [
  { value: "fortigate", label: "FortiGate" },
  { value: "cisco", label: "Cisco" },
  { value: "paloalto", label: "Palo Alto" },
  { value: "checkpoint", label: "Check Point" },
  { value: "custom", label: "Custom API" }
];

function defaultScopeForAdapter(adapter: AdapterType): string {
  if (adapter === "fortigate") return "root";
  return "";
}

function buildDefaultDraft(profileName = "adapter-profile-1"): ProfileDraft {
  return {
    profileName,
    adapter: "fortigate",
    isActive: true,
    baseUrl: "",
    token: "",
    timeoutSeconds: "10",
    retries: "3",
    targetGroup: "NON_COMPLIANT_ENDPOINTS",
    scope: defaultScopeForAdapter("fortigate")
  };
}

function buildDraftFromProfile(profile: AdapterConfig): ProfileDraft {
  const adapter = (profile.adapter as AdapterType) || "custom";
  const settings = profile.settings ?? {};
  return {
    profileName: profile.name,
    adapter,
    isActive: profile.is_active,
    baseUrl: String((settings.base_url as string) ?? ""),
    token: String((settings.token as string) ?? ""),
    timeoutSeconds: String((settings.timeout_seconds as number | string) ?? "10"),
    retries: String((settings.retries as number | string) ?? "3"),
    targetGroup: String(
      (settings.target_group as string) ?? (settings.quarantine_group as string) ?? "NON_COMPLIANT_ENDPOINTS"
    ),
    scope: String((settings.scope as string) ?? (settings.vdom as string) ?? defaultScopeForAdapter(adapter))
  };
}

function draftToSettings(draft: ProfileDraft): Record<string, unknown> {
  const settings: Record<string, unknown> = {
    base_url: draft.baseUrl.trim(),
    token: draft.token,
    timeout_seconds: Number(draft.timeoutSeconds) || 10,
    retries: Number(draft.retries) || 3,
    target_group: draft.targetGroup.trim(),
    scope: draft.scope.trim()
  };

  if (draft.adapter === "fortigate") {
    settings.vdom = draft.scope.trim() || "root";
    settings.quarantine_group = draft.targetGroup.trim();
  }
  return settings;
}

function scopeLabel(adapter: AdapterType): string {
  if (adapter === "fortigate") return "Scope (VDOM)";
  if (adapter === "paloalto") return "Scope (Device group)";
  if (adapter === "checkpoint") return "Scope (Domain)";
  return "Scope";
}

export function AdaptersPage() {
  const { pushToast } = useToast();
  const [serviceHealth, setServiceHealth] = useState<ServiceStatus[]>([]);
  const [profiles, setProfiles] = useState<AdapterConfig[]>([]);
  const [profileHealth, setProfileHealth] = useState<Record<string, AdapterProfileHealth>>({});
  const [loading, setLoading] = useState(true);
  const [refreshingHealth, setRefreshingHealth] = useState(false);
  const [editorOpen, setEditorOpen] = useState(false);
  const [draft, setDraft] = useState<ProfileDraft>(buildDefaultDraft());
  const [editingName, setEditingName] = useState<string | null>(null);
  const refreshInFlight = useRef(false);

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
        setProfileHealth(Object.fromEntries(adapterHealth.map((item) => [item.name, item])));
      } catch {
        const snapshot = profilesSnapshot ?? profiles;
        setProfileHealth(
          Object.fromEntries(
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
          )
        );
      }
    } catch (error) {
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

  const loadData = async () => {
    setLoading(true);
    try {
      const [health, adapters] = await Promise.all([api.getServiceHealth(), api.listAdapterConfigs()]);
      const allProfiles = adapters.sort((a, b) => a.name.localeCompare(b.name));
      setServiceHealth(health);
      setProfiles(allProfiles);
      void refreshRuntimeHealth({ quiet: true, profilesSnapshot: allProfiles });
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
  }, [profiles]);

  const nextProfileName = useMemo(() => {
    let index = profiles.length + 1;
    let candidate = `adapter-profile-${index}`;
    const existing = new Set(profiles.map((item) => item.name));
    while (existing.has(candidate)) {
      index += 1;
      candidate = `adapter-profile-${index}`;
    }
    return candidate;
  }, [profiles]);

  const inputClassName =
    "w-full rounded-xl border border-border bg-slate-900 px-3 py-2.5 text-sm text-white outline-none focus:border-teal-500";

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="Connectivity"
        title="Adapters"
        description="Manage adapter profiles for FortiGate, Cisco, Palo Alto, Check Point, and custom APIs."
        actions={
          <>
            <Button
              variant="secondary"
              onClick={() => {
                setEditingName(null);
                setDraft(buildDefaultDraft(nextProfileName));
                setEditorOpen(true);
              }}
            >
              <Plus className="mr-2 h-4 w-4" />
              Create adapter profile
            </Button>
            <Button variant="secondary" onClick={() => void refreshRuntimeHealth({ quiet: false })} disabled={refreshingHealth}>
              <RefreshCcw className="mr-2 h-4 w-4" />
              {refreshingHealth ? "Refreshing..." : "Refresh"}
            </Button>
          </>
        }
      />

      <Card>
        <CardHeader>
          <div>
            <CardTitle>Adapter profiles</CardTitle>
            <p className="mt-1 text-sm text-slate-400">
              Profiles are created and edited from popup forms. No permanent inline profile fields.
            </p>
          </div>
        </CardHeader>
        <CardBody className="space-y-3">
          {profiles.length === 0 && !loading ? (
            <EmptyState
              icon={Cable}
              title="No adapter profiles"
              description="Create your first adapter profile with the Create adapter profile button."
            />
          ) : (
            profiles.map((profile) => {
              const health = profileHealth[profile.name];
              return (
                <div
                  key={profile.id}
                  className="rounded-2xl border border-border bg-slate-900/40 px-4 py-3"
                >
                  <div className="flex flex-wrap items-center justify-between gap-3">
                    <div>
                      <p className="text-sm font-medium text-white">{profile.name}</p>
                      <p className="text-xs text-slate-400">
                        {profile.adapter} | {String((profile.settings.base_url as string) ?? "No base URL")}
                      </p>
                    </div>
                    <div className="flex items-center gap-2">
                      <StatusBadge
                        value={health?.status ?? (profile.is_active ? "unknown" : "disabled")}
                      />
                      <Button
                        variant="secondary"
                        onClick={() => {
                          setEditingName(profile.name);
                          setDraft(buildDraftFromProfile(profile));
                          setEditorOpen(true);
                        }}
                      >
                        <Edit className="mr-2 h-4 w-4" />
                        Edit
                      </Button>
                      <Button
                        variant="danger"
                        onClick={async () => {
                          try {
                            await api.deleteAdapterConfig(profile.name);
                            pushToast({ tone: "success", title: `Profile '${profile.name}' deleted` });
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
                        <Trash2 className="mr-2 h-4 w-4" />
                        Delete
                      </Button>
                    </div>
                  </div>
                  {health ? (
                    <p className="mt-2 text-sm text-slate-400">{health.detail}</p>
                  ) : null}
                </div>
              );
            })
          )}
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
      ) : null}

      <Modal
        open={editorOpen}
        title={editingName ? `Edit ${editingName}` : "Create adapter profile"}
        description="Configure adapter connectivity in a popup form."
        onClose={() => setEditorOpen(false)}
        footer={
          <>
            <Button variant="ghost" onClick={() => setEditorOpen(false)}>
              Cancel
            </Button>
            <Button
              disabled={!draft.profileName.trim() || !draft.baseUrl.trim()}
              onClick={async () => {
                const profileName = draft.profileName.trim();
                try {
                  await api.upsertAdapterConfig(profileName, {
                    adapter: draft.adapter,
                    is_active: draft.isActive,
                    settings: draftToSettings(draft)
                  });
                  pushToast({
                    tone: "success",
                    title: editingName ? "Adapter profile updated" : "Adapter profile created"
                  });
                  setEditorOpen(false);
                  await loadData();
                } catch (error) {
                  pushToast({
                    tone: "error",
                    title: "Failed to save adapter profile",
                    description: error instanceof Error ? error.message : "Unknown error"
                  });
                }
              }}
            >
              Save profile
            </Button>
          </>
        }
      >
        <div className="grid gap-4">
          <div className="grid gap-4 md:grid-cols-2">
            <label className="space-y-2">
              <span className="text-sm text-slate-300">Profile name</span>
              <input
                value={draft.profileName}
                onChange={(event) => setDraft((current) => ({ ...current, profileName: event.target.value }))}
                className={inputClassName}
              />
            </label>
            <label className="space-y-2">
              <span className="text-sm text-slate-300">Adapter type</span>
              <select
                value={draft.adapter}
                onChange={(event) =>
                  setDraft((current) => ({
                    ...current,
                    adapter: event.target.value as AdapterType,
                    scope:
                      current.scope || defaultScopeForAdapter(event.target.value as AdapterType)
                  }))
                }
                className={inputClassName}
              >
                {ADAPTER_OPTIONS.map((item) => (
                  <option key={item.value} value={item.value}>
                    {item.label}
                  </option>
                ))}
              </select>
            </label>
          </div>

          <label className="flex items-center gap-3 rounded-xl border border-border bg-slate-900 px-3 py-2.5">
            <input
              type="checkbox"
              checked={draft.isActive}
              onChange={(event) => setDraft((current) => ({ ...current, isActive: event.target.checked }))}
            />
            <span className="text-sm text-slate-300">Profile active</span>
          </label>

          <div className="grid gap-4 md:grid-cols-2">
            <label className="space-y-2">
              <span className="text-sm text-slate-300">Base URL</span>
              <input
                value={draft.baseUrl}
                onChange={(event) => setDraft((current) => ({ ...current, baseUrl: event.target.value }))}
                placeholder="https://192.168.2.2"
                className={inputClassName}
              />
            </label>
            <label className="space-y-2">
              <span className="text-sm text-slate-300">API token</span>
              <input
                type="password"
                value={draft.token}
                onChange={(event) => setDraft((current) => ({ ...current, token: event.target.value }))}
                className={inputClassName}
              />
            </label>
          </div>

          <div className="grid gap-4 md:grid-cols-4">
            <label className="space-y-2 md:col-span-2">
              <span className="text-sm text-slate-300">Target object group</span>
              <input
                value={draft.targetGroup}
                onChange={(event) => setDraft((current) => ({ ...current, targetGroup: event.target.value }))}
                className={inputClassName}
              />
            </label>
            <label className="space-y-2">
              <span className="text-sm text-slate-300">Timeout (s)</span>
              <input
                value={draft.timeoutSeconds}
                onChange={(event) => setDraft((current) => ({ ...current, timeoutSeconds: event.target.value }))}
                className={inputClassName}
              />
            </label>
            <label className="space-y-2">
              <span className="text-sm text-slate-300">Retries</span>
              <input
                value={draft.retries}
                onChange={(event) => setDraft((current) => ({ ...current, retries: event.target.value }))}
                className={inputClassName}
              />
            </label>
          </div>

          <label className="space-y-2">
            <span className="text-sm text-slate-300">{scopeLabel(draft.adapter)}</span>
            <input
              value={draft.scope}
              onChange={(event) => setDraft((current) => ({ ...current, scope: event.target.value }))}
              className={inputClassName}
            />
          </label>
        </div>
      </Modal>
    </div>
  );
}
