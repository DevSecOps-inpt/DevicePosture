"use client";

import { useEffect, useMemo, useState } from "react";
import { KeyRound, Link2, Plus, RefreshCcw, ShieldCheck } from "lucide-react";
import { api } from "@/lib/api";
import type { AuthProvider, ProviderTestResult } from "@/types/platform";
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
      bind_dn_template: "uid={username},ou=people,dc=example,dc=local",
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

  const loadProviders = async () => {
    setLoading(true);
    try {
      const items = await api.listAuthProviders();
      setProviders(items);
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
              <span className="text-sm text-slate-300">Bind DN template</span>
              <input
                value={String(draft.settings.bind_dn_template ?? "")}
                onChange={(event) =>
                  setDraft((current) => ({ ...current, settings: { ...current.settings, bind_dn_template: event.target.value } }))
                }
                className={inputClassName}
              />
            </label>
          </div>
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

