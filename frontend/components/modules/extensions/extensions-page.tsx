"use client";

import { useEffect, useMemo, useState } from "react";
import { KeyRound, Link2, Plus, RefreshCcw, Search, ShieldCheck } from "lucide-react";
import { api } from "@/lib/api";
import type { AuthProvider, DirectoryGroup, DirectoryGroupSearchResponse, ProviderTestResult } from "@/types/platform";
import { Button } from "@/components/ui/button";
import { Card, CardBody, CardHeader, CardTitle } from "@/components/ui/card";
import { EmptyState } from "@/components/ui/empty-state";
import { Modal } from "@/components/ui/modal";
import { PageHeader } from "@/components/ui/page-header";
import { StatusBadge } from "@/components/ui/status-badge";
import { Tabs } from "@/components/ui/tabs";
import { useToast } from "@/components/ui/toast-provider";

type ProviderProtocol = AuthProvider["protocol"];

type ProviderDraft = {
  name: string;
  protocol: ProviderProtocol;
  is_enabled: boolean;
  priority: number;
  settings: Record<string, unknown>;
};

const PROTOCOLS: Array<{ value: ProviderProtocol; label: string }> = [
  { value: "ldap", label: "LDAP" },
  { value: "radius", label: "RADIUS" },
  { value: "oidc", label: "OIDC" },
  { value: "oauth2", label: "OAuth2" },
  { value: "saml", label: "SAML" }
];

function defaultSettings(protocol: ProviderProtocol): Record<string, unknown> {
  if (protocol === "ldap") {
    return {
      server_uri: "ldap://127.0.0.1:389",
      base_dn: "",
      user_search_base: "",
      group_base_dn: "",
      group_search_filter: "(objectClass=group)",
      group_name_attribute: "cn",
      bind_dn: "",
      bind_password: "",
      timeout_seconds: 5,
      accept_all_credentials_for_testing: false
    };
  }
  if (protocol === "radius") {
    return {
      host: "127.0.0.1",
      auth_port: 1812,
      shared_secret: "",
      timeout_seconds: 5,
      accept_all_credentials_for_testing: false
    };
  }
  if (protocol === "oidc") {
    return {
      issuer_url: "https://idp.example.local",
      discovery_url: "",
      client_id: "",
      client_secret: "",
      scopes: "openid profile email",
      timeout_seconds: 5
    };
  }
  if (protocol === "oauth2") {
    return {
      token_endpoint: "https://idp.example.local/oauth/token",
      client_id: "",
      client_secret: "",
      scopes: "profile email",
      timeout_seconds: 5
    };
  }
  return {
    metadata_url: "https://idp.example.local/metadata.xml",
    sso_url: "https://idp.example.local/sso",
    entity_id: "",
    timeout_seconds: 5
  };
}

function buildDefaultDraft(protocol: ProviderProtocol = "ldap"): ProviderDraft {
  return {
    name: `${protocol}-provider`,
    protocol,
    is_enabled: false,
    priority: 100,
    settings: defaultSettings(protocol)
  };
}

function draftFromProvider(provider: AuthProvider): ProviderDraft {
  return {
    name: provider.name,
    protocol: provider.protocol,
    is_enabled: provider.is_enabled,
    priority: provider.priority,
    settings: { ...defaultSettings(provider.protocol), ...(provider.settings ?? {}) }
  };
}

function providerStatus(value: ProviderTestResult | null, isEnabled: boolean): string {
  if (!isEnabled) {
    return "disabled";
  }
  if (!value) {
    return "unknown";
  }
  return value.ok ? "healthy" : "error";
}

export function ExtensionsPage() {
  const { pushToast } = useToast();
  const [tab, setTab] = useState("identity");
  const [providers, setProviders] = useState<AuthProvider[]>([]);
  const [loading, setLoading] = useState(true);
  const [editorOpen, setEditorOpen] = useState(false);
  const [editing, setEditing] = useState<AuthProvider | null>(null);
  const [draft, setDraft] = useState<ProviderDraft>(buildDefaultDraft());
  const [testUser, setTestUser] = useState("");
  const [testPassword, setTestPassword] = useState("");
  const [connectivityByProvider, setConnectivityByProvider] = useState<Record<number, ProviderTestResult>>({});
  const [directoryGroupsByProvider, setDirectoryGroupsByProvider] = useState<Record<number, DirectoryGroup[]>>({});
  const [syncingProviderIds, setSyncingProviderIds] = useState<number[]>([]);
  const [groupBrowserOpen, setGroupBrowserOpen] = useState(false);
  const [groupBrowserProvider, setGroupBrowserProvider] = useState<AuthProvider | null>(null);
  const [groupBrowserFilter, setGroupBrowserFilter] = useState("(objectClass=group)");
  const [groupBrowserSearch, setGroupBrowserSearch] = useState("");
  const [groupBrowserBase, setGroupBrowserBase] = useState("");
  const [groupBrowserLimit, setGroupBrowserLimit] = useState("200");
  const [groupBrowserComputerOnly, setGroupBrowserComputerOnly] = useState(false);
  const [groupBrowserLoading, setGroupBrowserLoading] = useState(false);
  const [groupBrowserResult, setGroupBrowserResult] = useState<DirectoryGroupSearchResponse | null>(null);

  const loadProviders = async () => {
    setLoading(true);
    try {
      const items = await api.listAuthProviders();
      setProviders(items);
      const ldapProviderIds = items.filter((item) => item.protocol === "ldap").map((item) => item.id);
      if (ldapProviderIds.length > 0) {
        const groups = await api.listLdapDirectoryGroups({ providerIds: ldapProviderIds }).catch(() => []);
        const grouped: Record<number, DirectoryGroup[]> = {};
        for (const group of groups) {
          if (!grouped[group.provider_id]) {
            grouped[group.provider_id] = [];
          }
          grouped[group.provider_id].push(group);
        }
        setDirectoryGroupsByProvider(grouped);
      } else {
        setDirectoryGroupsByProvider({});
      }
    } catch (error) {
      pushToast({
        tone: "error",
        title: "Failed to load auth providers",
        description: error instanceof Error ? error.message : "Unknown error"
      });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void loadProviders();
  }, []);

  const openGroupBrowser = (provider: AuthProvider) => {
    setGroupBrowserProvider(provider);
    setGroupBrowserFilter(String(provider.settings.group_search_filter ?? "(objectClass=group)"));
    setGroupBrowserSearch("");
    setGroupBrowserBase(String(provider.settings.group_base_dn ?? provider.settings.base_dn ?? ""));
    setGroupBrowserLimit("200");
    setGroupBrowserComputerOnly(false);
    setGroupBrowserResult(null);
    setGroupBrowserOpen(true);
  };

  const runGroupBrowserSearch = async (persist: boolean) => {
    if (!groupBrowserProvider) {
      return;
    }
    setGroupBrowserLoading(true);
    try {
      const payload = {
        ldap_filter: groupBrowserFilter.trim() || "(objectClass=group)",
        search: groupBrowserSearch.trim() || null,
        search_base: groupBrowserBase.trim() || null,
        limit: Math.max(1, Math.min(2000, Number(groupBrowserLimit) || 200)),
        computer_only: groupBrowserComputerOnly,
        persist
      };
      const result = await api.searchAuthProviderDirectoryGroups(groupBrowserProvider.id, payload);
      setGroupBrowserResult(result);
      if (persist) {
        const groups = await api.listAuthProviderDirectoryGroups(groupBrowserProvider.id);
        setDirectoryGroupsByProvider((current) => ({ ...current, [groupBrowserProvider.id]: groups }));
      }
      pushToast({
        tone: "success",
        title: persist ? "Group results imported" : "LDAP search completed",
        description: `${result.matched_count} matched, ${result.imported_count} imported`
      });
    } catch (error) {
      pushToast({
        tone: "error",
        title: "LDAP group search failed",
        description: error instanceof Error ? error.message : "Unknown error"
      });
    } finally {
      setGroupBrowserLoading(false);
    }
  };

  const installed = useMemo(() => providers.filter((item) => item.is_enabled), [providers]);
  const inputClassName =
    "w-full rounded-xl border border-border bg-slate-900 px-3 py-2.5 text-sm text-white outline-none focus:border-teal-500";

  const renderProtocolFields = () => {
    if (draft.protocol === "ldap") {
      return (
        <div className="grid gap-4">
          <label className="space-y-2">
            <span className="text-sm text-slate-300">Server URI</span>
            <input
              value={String(draft.settings.server_uri ?? "")}
              onChange={(event) => setDraft((current) => ({ ...current, settings: { ...current.settings, server_uri: event.target.value } }))}
              className={inputClassName}
            />
          </label>
          <div className="grid gap-4 md:grid-cols-2">
            <label className="space-y-2">
              <span className="text-sm text-slate-300">Base DN</span>
              <input
                value={String(draft.settings.base_dn ?? "")}
                onChange={(event) => setDraft((current) => ({ ...current, settings: { ...current.settings, base_dn: event.target.value } }))}
                className={inputClassName}
              />
            </label>
            <label className="space-y-2">
              <span className="text-sm text-slate-300">User search base (optional)</span>
              <input
                value={String(draft.settings.user_search_base ?? "")}
                onChange={(event) =>
                  setDraft((current) => ({ ...current, settings: { ...current.settings, user_search_base: event.target.value } }))
                }
                className={inputClassName}
              />
            </label>
          </div>
          <div className="grid gap-4 md:grid-cols-2">
            <label className="space-y-2">
              <span className="text-sm text-slate-300">Group search base (optional)</span>
              <input
                value={String(draft.settings.group_base_dn ?? "")}
                onChange={(event) =>
                  setDraft((current) => ({ ...current, settings: { ...current.settings, group_base_dn: event.target.value } }))
                }
                className={inputClassName}
              />
            </label>
            <label className="space-y-2">
              <span className="text-sm text-slate-300">Group search filter</span>
              <input
                value={String(draft.settings.group_search_filter ?? "")}
                onChange={(event) =>
                  setDraft((current) => ({ ...current, settings: { ...current.settings, group_search_filter: event.target.value } }))
                }
                className={inputClassName}
              />
            </label>
          </div>
          <div className="grid gap-4 md:grid-cols-2">
            <label className="space-y-2">
              <span className="text-sm text-slate-300">Group name attribute</span>
              <input
                value={String(draft.settings.group_name_attribute ?? "")}
                onChange={(event) =>
                  setDraft((current) => ({ ...current, settings: { ...current.settings, group_name_attribute: event.target.value } }))
                }
                className={inputClassName}
              />
            </label>
            <label className="space-y-2">
              <span className="text-sm text-slate-300">Service account DN</span>
              <input
                value={String(draft.settings.bind_dn ?? "")}
                onChange={(event) =>
                  setDraft((current) => ({ ...current, settings: { ...current.settings, bind_dn: event.target.value } }))
                }
                className={inputClassName}
              />
            </label>
          </div>
          <label className="space-y-2">
            <span className="text-sm text-slate-300">Service account password</span>
            <input
              type="password"
              value={String(draft.settings.bind_password ?? "")}
              onChange={(event) =>
                setDraft((current) => ({ ...current, settings: { ...current.settings, bind_password: event.target.value } }))
              }
              className={inputClassName}
            />
          </label>
        </div>
      );
    }
    if (draft.protocol === "radius") {
      return (
        <div className="grid gap-4">
          <div className="grid gap-4 md:grid-cols-2">
            <label className="space-y-2">
              <span className="text-sm text-slate-300">Host</span>
              <input
                value={String(draft.settings.host ?? "")}
                onChange={(event) => setDraft((current) => ({ ...current, settings: { ...current.settings, host: event.target.value } }))}
                className={inputClassName}
              />
            </label>
            <label className="space-y-2">
              <span className="text-sm text-slate-300">Auth port</span>
              <input
                value={String(draft.settings.auth_port ?? "1812")}
                onChange={(event) =>
                  setDraft((current) => ({
                    ...current,
                    settings: { ...current.settings, auth_port: Number(event.target.value) || 1812 }
                  }))
                }
                className={inputClassName}
              />
            </label>
          </div>
          <label className="space-y-2">
            <span className="text-sm text-slate-300">Shared secret</span>
            <input
              type="password"
              value={String(draft.settings.shared_secret ?? "")}
              onChange={(event) =>
                setDraft((current) => ({ ...current, settings: { ...current.settings, shared_secret: event.target.value } }))
              }
              className={inputClassName}
            />
          </label>
        </div>
      );
    }
    if (draft.protocol === "oidc") {
      return (
        <div className="grid gap-4">
          <label className="space-y-2">
            <span className="text-sm text-slate-300">Issuer URL</span>
            <input
              value={String(draft.settings.issuer_url ?? "")}
              onChange={(event) => setDraft((current) => ({ ...current, settings: { ...current.settings, issuer_url: event.target.value } }))}
              className={inputClassName}
            />
          </label>
          <label className="space-y-2">
            <span className="text-sm text-slate-300">Discovery URL (optional)</span>
            <input
              value={String(draft.settings.discovery_url ?? "")}
              onChange={(event) => setDraft((current) => ({ ...current, settings: { ...current.settings, discovery_url: event.target.value } }))}
              className={inputClassName}
            />
          </label>
          <div className="grid gap-4 md:grid-cols-2">
            <label className="space-y-2">
              <span className="text-sm text-slate-300">Client ID</span>
              <input
                value={String(draft.settings.client_id ?? "")}
                onChange={(event) => setDraft((current) => ({ ...current, settings: { ...current.settings, client_id: event.target.value } }))}
                className={inputClassName}
              />
            </label>
            <label className="space-y-2">
              <span className="text-sm text-slate-300">Client secret</span>
              <input
                type="password"
                value={String(draft.settings.client_secret ?? "")}
                onChange={(event) =>
                  setDraft((current) => ({ ...current, settings: { ...current.settings, client_secret: event.target.value } }))
                }
                className={inputClassName}
              />
            </label>
          </div>
        </div>
      );
    }
    if (draft.protocol === "oauth2") {
      return (
        <div className="grid gap-4">
          <label className="space-y-2">
            <span className="text-sm text-slate-300">Token endpoint</span>
            <input
              value={String(draft.settings.token_endpoint ?? "")}
              onChange={(event) =>
                setDraft((current) => ({ ...current, settings: { ...current.settings, token_endpoint: event.target.value } }))
              }
              className={inputClassName}
            />
          </label>
          <div className="grid gap-4 md:grid-cols-2">
            <label className="space-y-2">
              <span className="text-sm text-slate-300">Client ID</span>
              <input
                value={String(draft.settings.client_id ?? "")}
                onChange={(event) => setDraft((current) => ({ ...current, settings: { ...current.settings, client_id: event.target.value } }))}
                className={inputClassName}
              />
            </label>
            <label className="space-y-2">
              <span className="text-sm text-slate-300">Client secret</span>
              <input
                type="password"
                value={String(draft.settings.client_secret ?? "")}
                onChange={(event) =>
                  setDraft((current) => ({ ...current, settings: { ...current.settings, client_secret: event.target.value } }))
                }
                className={inputClassName}
              />
            </label>
          </div>
        </div>
      );
    }
    return (
      <div className="grid gap-4">
        <label className="space-y-2">
          <span className="text-sm text-slate-300">Metadata URL</span>
          <input
            value={String(draft.settings.metadata_url ?? "")}
            onChange={(event) => setDraft((current) => ({ ...current, settings: { ...current.settings, metadata_url: event.target.value } }))}
            className={inputClassName}
          />
        </label>
        <label className="space-y-2">
          <span className="text-sm text-slate-300">SSO URL</span>
          <input
            value={String(draft.settings.sso_url ?? "")}
            onChange={(event) => setDraft((current) => ({ ...current, settings: { ...current.settings, sso_url: event.target.value } }))}
            className={inputClassName}
          />
        </label>
        <label className="space-y-2">
          <span className="text-sm text-slate-300">Entity ID</span>
          <input
            value={String(draft.settings.entity_id ?? "")}
            onChange={(event) => setDraft((current) => ({ ...current, settings: { ...current.settings, entity_id: event.target.value } }))}
            className={inputClassName}
          />
        </label>
      </div>
    );
  };

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="Identity Extensions"
        title="Extensions / Integrations"
        description="Configure LDAP, RADIUS, OIDC, OAuth2, and SAML providers with backend-managed settings and live tests."
        actions={
          <>
            <Button variant="secondary" onClick={() => void loadProviders()} disabled={loading}>
              <RefreshCcw className="mr-2 h-4 w-4" />
              {loading ? "Refreshing..." : "Refresh"}
            </Button>
            <Button
              onClick={() => {
                setEditing(null);
                setDraft(buildDefaultDraft());
                setEditorOpen(true);
              }}
            >
              <Plus className="mr-2 h-4 w-4" />
              Create provider
            </Button>
          </>
        }
      />

      <Tabs
        tabs={[
          { label: "Identity Providers", value: "identity" },
          { label: "Enabled", value: "enabled" }
        ]}
        value={tab}
        onChange={setTab}
      />

      {tab === "identity" ? (
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
          {providers.map((provider) => {
            const connectivity = connectivityByProvider[provider.id] ?? null;
            return (
              <Card key={provider.id}>
                <CardHeader>
                  <div>
                    <CardTitle>{provider.name}</CardTitle>
                    <p className="mt-1 text-sm text-slate-400">{provider.protocol.toUpperCase()}</p>
                  </div>
                  <StatusBadge value={providerStatus(connectivity, provider.is_enabled)} />
                </CardHeader>
                <CardBody className="space-y-3">
                  <p className="text-sm text-slate-400">
                    Priority: {provider.priority} | {provider.is_enabled ? "Enabled" : "Disabled"}
                  </p>
                  {provider.protocol === "ldap" ? (
                    <p className="text-xs text-slate-500">
                      Cached LDAP groups: {directoryGroupsByProvider[provider.id]?.length ?? 0}
                    </p>
                  ) : null}
                  <div className="flex flex-wrap gap-2">
                    <Button
                      variant="secondary"
                      onClick={() => {
                        setEditing(provider);
                        setDraft(draftFromProvider(provider));
                        setEditorOpen(true);
                      }}
                    >
                      <Link2 className="mr-2 h-4 w-4" />
                      Configure
                    </Button>
                    <Button
                      variant="secondary"
                      onClick={async () => {
                        try {
                          const result = await api.testAuthProviderConnectivity(provider.id);
                          setConnectivityByProvider((current) => ({ ...current, [provider.id]: result }));
                          pushToast({
                            tone: result.ok ? "success" : "error",
                            title: result.ok ? `${provider.name} reachable` : `${provider.name} unreachable`,
                            description: result.message
                          });
                        } catch (error) {
                          pushToast({
                            tone: "error",
                            title: "Connectivity test failed",
                            description: error instanceof Error ? error.message : "Unknown error"
                          });
                        }
                      }}
                    >
                      <ShieldCheck className="mr-2 h-4 w-4" />
                      Test connectivity
                    </Button>
                    {provider.protocol === "ldap" ? (
                      <Button
                        variant="secondary"
                        onClick={() => openGroupBrowser(provider)}
                      >
                        <Search className="mr-2 h-4 w-4" />
                        Browse groups
                      </Button>
                    ) : null}
                    {provider.protocol === "ldap" ? (
                      <Button
                        variant="secondary"
                        onClick={async () => {
                          setSyncingProviderIds((current) => [...current, provider.id]);
                          try {
                            const groups = await api.syncAuthProviderDirectoryGroups(provider.id);
                            setDirectoryGroupsByProvider((current) => ({ ...current, [provider.id]: groups }));
                            pushToast({
                              tone: "success",
                              title: "LDAP groups synchronized",
                              description: `${groups.length} groups loaded`
                            });
                          } catch (error) {
                            pushToast({
                              tone: "error",
                              title: "LDAP sync failed",
                              description: error instanceof Error ? error.message : "Unknown error"
                            });
                          } finally {
                            setSyncingProviderIds((current) => current.filter((item) => item !== provider.id));
                          }
                        }}
                        disabled={syncingProviderIds.includes(provider.id)}
                      >
                        <RefreshCcw className="mr-2 h-4 w-4" />
                        {syncingProviderIds.includes(provider.id) ? "Syncing..." : "Sync groups"}
                      </Button>
                    ) : null}
                  </div>
                  {connectivity ? <p className="text-xs text-slate-400">{connectivity.message}</p> : null}
                </CardBody>
              </Card>
            );
          })}
          {providers.length === 0 && !loading ? (
            <EmptyState
              icon={KeyRound}
              title="No providers configured"
              description="Create your first protocol provider profile."
            />
          ) : null}
        </div>
      ) : installed.length === 0 ? (
        <EmptyState
          icon={KeyRound}
          title="No enabled providers"
          description="Enable at least one provider profile for external authentication."
        />
      ) : (
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
          {installed.map((provider) => (
            <Card key={provider.id}>
              <CardHeader>
                <div>
                  <CardTitle>{provider.name}</CardTitle>
                  <p className="mt-1 text-sm text-slate-400">{provider.protocol.toUpperCase()}</p>
                </div>
                <StatusBadge value="healthy" />
              </CardHeader>
              <CardBody className="space-y-2">
                <p className="text-sm text-slate-300">Priority: {provider.priority}</p>
                <p className="text-sm text-slate-300">Enabled and available for login mapping.</p>
              </CardBody>
            </Card>
          ))}
        </div>
      )}

      <Modal
        open={groupBrowserOpen}
        title={groupBrowserProvider ? `Browse LDAP groups: ${groupBrowserProvider.name}` : "Browse LDAP groups"}
        description="Search AD groups using a custom LDAP filter, similar to FortiGate group browsing."
        onClose={() => setGroupBrowserOpen(false)}
        footer={
          <>
            <Button variant="ghost" onClick={() => setGroupBrowserOpen(false)}>
              Close
            </Button>
            <Button
              variant="secondary"
              onClick={() => void runGroupBrowserSearch(false)}
              disabled={!groupBrowserProvider || groupBrowserLoading}
            >
              <Search className="mr-2 h-4 w-4" />
              {groupBrowserLoading ? "Searching..." : "Search"}
            </Button>
            <Button
              onClick={() => void runGroupBrowserSearch(true)}
              disabled={!groupBrowserProvider || groupBrowserLoading}
            >
              <Plus className="mr-2 h-4 w-4" />
              Import results
            </Button>
          </>
        }
      >
        <div className="grid gap-4">
          <div className="grid gap-4 md:grid-cols-2">
            <label className="space-y-2">
              <span className="text-sm text-slate-300">Custom LDAP filter</span>
              <input
                value={groupBrowserFilter}
                onChange={(event) => setGroupBrowserFilter(event.target.value)}
                className={inputClassName}
                placeholder="(objectClass=group)"
              />
            </label>
            <label className="space-y-2">
              <span className="text-sm text-slate-300">Search text</span>
              <input
                value={groupBrowserSearch}
                onChange={(event) => setGroupBrowserSearch(event.target.value)}
                className={inputClassName}
                placeholder="domain admins"
              />
            </label>
          </div>
          <div className="grid gap-4 md:grid-cols-2">
            <label className="space-y-2">
              <span className="text-sm text-slate-300">Search base (optional override)</span>
              <input
                value={groupBrowserBase}
                onChange={(event) => setGroupBrowserBase(event.target.value)}
                className={inputClassName}
                placeholder="DC=example,DC=local"
              />
            </label>
            <label className="space-y-2">
              <span className="text-sm text-slate-300">Result limit</span>
              <input
                value={groupBrowserLimit}
                onChange={(event) => setGroupBrowserLimit(event.target.value)}
                className={inputClassName}
              />
            </label>
          </div>
          <label className="flex items-center gap-3 rounded-xl border border-border bg-slate-900 px-3 py-2.5">
            <input
              type="checkbox"
              checked={groupBrowserComputerOnly}
              onChange={(event) => setGroupBrowserComputerOnly(event.target.checked)}
            />
            <span className="text-sm text-slate-300">Computer-related groups only</span>
          </label>

          {groupBrowserResult ? (
            <div className="grid gap-3 rounded-xl border border-border bg-slate-900/30 p-3">
              <p className="text-xs text-slate-400">
                {groupBrowserResult.message} | matched: {groupBrowserResult.matched_count} | imported: {groupBrowserResult.imported_count}
              </p>
              <p className="text-xs text-slate-500">
                Effective filter: {groupBrowserResult.search_filter}
              </p>
              <div className="max-h-72 overflow-auto rounded-lg border border-border">
                <table className="w-full text-left text-sm">
                  <thead className="bg-slate-900/80 text-xs uppercase tracking-[0.12em] text-slate-400">
                    <tr>
                      <th className="px-3 py-2">Group</th>
                      <th className="px-3 py-2">DN</th>
                      <th className="px-3 py-2">Cached</th>
                    </tr>
                  </thead>
                  <tbody>
                    {groupBrowserResult.items.map((item) => (
                      <tr key={item.group_key} className="border-t border-border/60">
                        <td className="px-3 py-2 text-slate-100">{item.group_name}</td>
                        <td className="px-3 py-2 text-xs text-slate-400">{item.group_dn ?? "-"}</td>
                        <td className="px-3 py-2 text-xs text-slate-300">{item.already_cached ? "yes" : "no"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          ) : (
            <p className="text-xs text-slate-500">
              Run search to preview LDAP groups, then import results into the local cache.
            </p>
          )}
        </div>
      </Modal>

      <Modal
        open={editorOpen}
        title={editing ? `Configure ${editing.name}` : "Create identity provider"}
        description="Protocol profile fields are backend-managed and reusable by User Administration."
        onClose={() => setEditorOpen(false)}
        footer={
          <>
            <Button variant="ghost" onClick={() => setEditorOpen(false)}>
              Cancel
            </Button>
            <Button
              onClick={async () => {
                try {
                  if (editing) {
                    await api.updateAuthProvider(editing.id, draft);
                    pushToast({ tone: "success", title: "Provider updated" });
                  } else {
                    await api.createAuthProvider(draft);
                    pushToast({ tone: "success", title: "Provider created" });
                  }
                  setEditorOpen(false);
                  await loadProviders();
                } catch (error) {
                  pushToast({
                    tone: "error",
                    title: "Failed to save provider",
                    description: error instanceof Error ? error.message : "Unknown error"
                  });
                }
              }}
              disabled={!draft.name.trim()}
            >
              Save provider
            </Button>
            {editing ? (
              <Button
                variant="danger"
                onClick={async () => {
                  try {
                    await api.deleteAuthProvider(editing.id);
                    pushToast({ tone: "success", title: "Provider deleted" });
                    setEditorOpen(false);
                    await loadProviders();
                  } catch (error) {
                    pushToast({
                      tone: "error",
                      title: "Failed to delete provider",
                      description: error instanceof Error ? error.message : "Unknown error"
                    });
                  }
                }}
              >
                Delete provider
              </Button>
            ) : null}
          </>
        }
      >
        <div className="grid gap-4">
          <div className="grid gap-4 md:grid-cols-2">
            <label className="space-y-2">
              <span className="text-sm text-slate-300">Provider name</span>
              <input
                value={draft.name}
                onChange={(event) => setDraft((current) => ({ ...current, name: event.target.value }))}
                className={inputClassName}
              />
            </label>
            <label className="space-y-2">
              <span className="text-sm text-slate-300">Protocol</span>
              <select
                disabled={Boolean(editing)}
                value={draft.protocol}
                onChange={(event) =>
                  setDraft((current) => ({
                    ...current,
                    protocol: event.target.value as ProviderProtocol,
                    settings: defaultSettings(event.target.value as ProviderProtocol)
                  }))
                }
                className={inputClassName}
              >
                {PROTOCOLS.map((option) => (
                  <option key={option.value} value={option.value}>
                    {option.label}
                  </option>
                ))}
              </select>
            </label>
          </div>
          <div className="grid gap-4 md:grid-cols-2">
            <label className="space-y-2">
              <span className="text-sm text-slate-300">Priority</span>
              <input
                value={String(draft.priority)}
                onChange={(event) => setDraft((current) => ({ ...current, priority: Number(event.target.value) || 100 }))}
                className={inputClassName}
              />
            </label>
            <label className="flex items-center gap-3 rounded-xl border border-border bg-slate-900 px-3 py-2.5">
              <input
                type="checkbox"
                checked={draft.is_enabled}
                onChange={(event) => setDraft((current) => ({ ...current, is_enabled: event.target.checked }))}
              />
              <span className="text-sm text-slate-300">Provider enabled</span>
            </label>
          </div>

          {renderProtocolFields()}

          {editing ? (
            <div className="grid gap-3 rounded-xl border border-border bg-slate-900/40 p-3">
              <p className="text-sm text-slate-300">Test credentials</p>
              <div className="grid gap-3 md:grid-cols-2">
                <input
                  value={testUser}
                  onChange={(event) => setTestUser(event.target.value)}
                  placeholder="Username"
                  className={inputClassName}
                />
                <input
                  type="password"
                  value={testPassword}
                  onChange={(event) => setTestPassword(event.target.value)}
                  placeholder="Password"
                  className={inputClassName}
                />
              </div>
              <div className="flex gap-2">
                <Button
                  variant="secondary"
                  onClick={async () => {
                    try {
                      const result = await api.testAuthProviderCredentials(editing.id, {
                        username: testUser.trim(),
                        password: testPassword
                      });
                      pushToast({
                        tone: result.ok ? "success" : "error",
                        title: result.ok ? "Credentials accepted" : "Credentials rejected",
                        description: result.message
                      });
                    } catch (error) {
                      pushToast({
                        tone: "error",
                        title: "Credentials test failed",
                        description: error instanceof Error ? error.message : "Unknown error"
                      });
                    }
                  }}
                  disabled={!testUser.trim() || !testPassword}
                >
                  Test credentials
                </Button>
              </div>
            </div>
          ) : null}
        </div>
      </Modal>
    </div>
  );
}
