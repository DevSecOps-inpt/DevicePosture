"use client";

import { useEffect, useMemo, useState } from "react";
import { KeyRound, Link2, Puzzle } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardBody, CardHeader, CardTitle } from "@/components/ui/card";
import { EmptyState } from "@/components/ui/empty-state";
import { Modal } from "@/components/ui/modal";
import { PageHeader } from "@/components/ui/page-header";
import { StatusBadge } from "@/components/ui/status-badge";
import { Tabs } from "@/components/ui/tabs";
import { useToast } from "@/components/ui/toast-provider";

type AuthProviderType = "ldap" | "radius" | "oidc" | "oauth2" | "saml";

type AuthExtension = {
  id: AuthProviderType;
  name: string;
  protocol: AuthProviderType;
  enabled: boolean;
  status: "healthy" | "warning" | "disabled" | "unknown";
  endpoint: string;
  clientId: string;
  description: string;
};

const AUTH_EXTENSIONS_STORAGE_KEY = "device-posture.auth-extensions.v1";

function defaultExtensions(): AuthExtension[] {
  return [
    {
      id: "ldap",
      name: "LDAP Directory",
      protocol: "ldap",
      enabled: false,
      status: "disabled",
      endpoint: "",
      clientId: "",
      description: "Enterprise directory authentication"
    },
    {
      id: "radius",
      name: "RADIUS",
      protocol: "radius",
      enabled: false,
      status: "disabled",
      endpoint: "",
      clientId: "",
      description: "Network access authentication server"
    },
    {
      id: "oidc",
      name: "OIDC Provider",
      protocol: "oidc",
      enabled: false,
      status: "disabled",
      endpoint: "",
      clientId: "",
      description: "OpenID Connect identity provider"
    },
    {
      id: "oauth2",
      name: "OAuth2 Provider",
      protocol: "oauth2",
      enabled: false,
      status: "disabled",
      endpoint: "",
      clientId: "",
      description: "OAuth2 authorization provider"
    },
    {
      id: "saml",
      name: "SAML Identity Provider",
      protocol: "saml",
      enabled: false,
      status: "disabled",
      endpoint: "",
      clientId: "",
      description: "SAML single sign-on integration"
    }
  ];
}

export function ExtensionsPage() {
  const { pushToast } = useToast();
  const [tab, setTab] = useState("identity");
  const [extensions, setExtensions] = useState<AuthExtension[]>(defaultExtensions());
  const [editorOpen, setEditorOpen] = useState(false);
  const [draft, setDraft] = useState<AuthExtension | null>(null);

  useEffect(() => {
    try {
      const raw = window.localStorage.getItem(AUTH_EXTENSIONS_STORAGE_KEY);
      if (!raw) return;
      const parsed = JSON.parse(raw) as AuthExtension[];
      if (Array.isArray(parsed) && parsed.length > 0) {
        setExtensions(parsed);
      }
    } catch {
    }
  }, []);

  useEffect(() => {
    try {
      window.localStorage.setItem(AUTH_EXTENSIONS_STORAGE_KEY, JSON.stringify(extensions));
    } catch {
    }
  }, [extensions]);

  const installed = useMemo(
    () => extensions.filter((item) => item.enabled),
    [extensions]
  );

  const inputClassName =
    "w-full rounded-xl border border-border bg-slate-900 px-3 py-2.5 text-sm text-white outline-none focus:border-teal-500";

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="Add-ons"
        title="Extensions / Integrations"
        description="Enable and configure identity integrations: LDAP, RADIUS, OIDC, OAuth2, and SAML."
      />

      <Tabs
        tabs={[
          { label: "Identity Providers", value: "identity" },
          { label: "Installed", value: "installed" }
        ]}
        value={tab}
        onChange={setTab}
      />

      {tab === "identity" ? (
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
          {extensions.map((item) => (
            <Card key={item.id}>
              <CardHeader>
                <div>
                  <CardTitle>{item.name}</CardTitle>
                  <p className="mt-1 text-sm text-slate-400">{item.description}</p>
                </div>
                <StatusBadge value={item.enabled ? item.status : "disabled"} />
              </CardHeader>
              <CardBody className="space-y-3">
                <div className="rounded-xl border border-border bg-slate-900/40 px-3 py-2">
                  <p className="text-xs uppercase tracking-[0.16em] text-slate-500">Protocol</p>
                  <p className="mt-1 text-sm text-slate-100">{item.protocol.toUpperCase()}</p>
                </div>
                <div className="flex flex-wrap gap-2">
                  <Button
                    variant="secondary"
                    onClick={() => {
                      setDraft(item);
                      setEditorOpen(true);
                    }}
                  >
                    <Link2 className="mr-2 h-4 w-4" />
                    Configure
                  </Button>
                  <Button
                    onClick={() => {
                      setExtensions((current) =>
                        current.map((candidate) =>
                          candidate.id === item.id
                            ? {
                                ...candidate,
                                enabled: !candidate.enabled,
                                status: !candidate.enabled
                                  ? candidate.endpoint
                                    ? "healthy"
                                    : "warning"
                                  : "disabled"
                              }
                            : candidate
                        )
                      );
                      pushToast({
                        tone: "success",
                        title: item.enabled ? `${item.name} disabled` : `${item.name} enabled`
                      });
                    }}
                  >
                    {item.enabled ? "Disable" : "Enable"}
                  </Button>
                </div>
              </CardBody>
            </Card>
          ))}
        </div>
      ) : installed.length === 0 ? (
        <EmptyState
          icon={Puzzle}
          title="No installed extensions"
          description="Enable one of the identity providers to activate it in the platform."
        />
      ) : (
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
          {installed.map((item) => (
            <Card key={item.id}>
              <CardHeader>
                <div>
                  <CardTitle>{item.name}</CardTitle>
                  <p className="mt-1 text-sm text-slate-400">{item.endpoint || "Endpoint not configured"}</p>
                </div>
                <StatusBadge value={item.status} />
              </CardHeader>
              <CardBody className="space-y-2">
                <p className="text-sm text-slate-300">Protocol: {item.protocol.toUpperCase()}</p>
                <p className="text-sm text-slate-300">Client/Realm: {item.clientId || "Not set"}</p>
              </CardBody>
            </Card>
          ))}
        </div>
      )}

      <Modal
        open={editorOpen}
        title={draft ? `Configure ${draft.name}` : "Configure extension"}
        description="Store extension connection details for future backend integration."
        onClose={() => setEditorOpen(false)}
        footer={
          <>
            <Button variant="ghost" onClick={() => setEditorOpen(false)}>
              Cancel
            </Button>
            <Button
              onClick={() => {
                if (!draft) return;
                setExtensions((current) =>
                  current.map((item) =>
                    item.id === draft.id
                      ? {
                          ...draft,
                          status: draft.enabled ? (draft.endpoint ? "healthy" : "warning") : "disabled"
                        }
                      : item
                  )
                );
                setEditorOpen(false);
                pushToast({ tone: "success", title: `${draft.name} configuration saved` });
              }}
              disabled={!draft}
            >
              Save
            </Button>
          </>
        }
      >
        {draft ? (
          <div className="grid gap-4">
            <label className="space-y-2">
              <span className="text-sm text-slate-300">Display name</span>
              <input
                value={draft.name}
                onChange={(event) =>
                  setDraft((current) => (current ? { ...current, name: event.target.value } : current))
                }
                className={inputClassName}
              />
            </label>
            <label className="space-y-2">
              <span className="text-sm text-slate-300">Endpoint / Issuer URL</span>
              <input
                value={draft.endpoint}
                onChange={(event) =>
                  setDraft((current) => (current ? { ...current, endpoint: event.target.value } : current))
                }
                className={inputClassName}
                placeholder={
                  draft.protocol === "ldap"
                    ? "ldap://directory.example.local"
                    : "https://idp.example.local"
                }
              />
            </label>
            <label className="space-y-2">
              <span className="text-sm text-slate-300">Client ID / Realm</span>
              <input
                value={draft.clientId}
                onChange={(event) =>
                  setDraft((current) => (current ? { ...current, clientId: event.target.value } : current))
                }
                className={inputClassName}
              />
            </label>
            <label className="flex items-center gap-3 rounded-xl border border-border bg-slate-900 px-3 py-2.5">
              <input
                type="checkbox"
                checked={draft.enabled}
                onChange={(event) =>
                  setDraft((current) => (current ? { ...current, enabled: event.target.checked } : current))
                }
              />
              <span className="text-sm text-slate-300">Extension enabled</span>
            </label>
            <div className="rounded-xl border border-border bg-slate-900/40 px-3 py-2">
              <p className="text-xs uppercase tracking-[0.16em] text-slate-500">Protocol</p>
              <p className="mt-1 flex items-center text-sm text-slate-100">
                <KeyRound className="mr-2 h-4 w-4" />
                {draft.protocol.toUpperCase()}
              </p>
            </div>
          </div>
        ) : null}
      </Modal>
    </div>
  );
}
