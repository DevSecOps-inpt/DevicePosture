"use client";

import { useEffect, useState } from "react";
import { Plus, RefreshCcw, Trash2, UserCog } from "lucide-react";
import { api } from "@/lib/api";
import type { AuthProtocol, UserAccount } from "@/types/platform";
import { Button } from "@/components/ui/button";
import { Card, CardBody, CardHeader, CardTitle } from "@/components/ui/card";
import { DataTable } from "@/components/ui/data-table";
import { Modal } from "@/components/ui/modal";
import { PageHeader } from "@/components/ui/page-header";
import { StatusBadge } from "@/components/ui/status-badge";
import { useToast } from "@/components/ui/toast-provider";

type Draft = {
  username: string;
  fullName: string;
  email: string;
  authSource: AuthProtocol;
  password: string;
  externalSubject: string;
  externalGroups: string;
  roles: string;
  isActive: boolean;
};

function buildDefaultDraft(): Draft {
  return {
    username: "",
    fullName: "",
    email: "",
    authSource: "local",
    password: "",
    externalSubject: "",
    externalGroups: "",
    roles: "admin",
    isActive: true
  };
}

export function UsersPage() {
  const { pushToast } = useToast();
  const [users, setUsers] = useState<UserAccount[]>([]);
  const [loading, setLoading] = useState(true);
  const [modalOpen, setModalOpen] = useState(false);
  const [editing, setEditing] = useState<UserAccount | null>(null);
  const [draft, setDraft] = useState<Draft>(buildDefaultDraft());

  const loadUsers = async () => {
    setLoading(true);
    try {
      const items = await api.listUsers();
      setUsers(items);
    } catch (error) {
      pushToast({
        tone: "error",
        title: "Failed to load users",
        description: error instanceof Error ? error.message : "Unknown error"
      });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void loadUsers();
  }, []);

  const inputClassName =
    "w-full rounded-xl border border-border bg-slate-900 px-3 py-2.5 text-sm text-white outline-none focus:border-teal-500";

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="Identity Access"
        title="User Administration"
        description="Manage local and external users. External users can be mapped to LDAP/RADIUS/OIDC/OAuth2/SAML identities and groups."
        actions={
          <>
            <Button variant="secondary" onClick={() => void loadUsers()} disabled={loading}>
              <RefreshCcw className="mr-2 h-4 w-4" />
              {loading ? "Refreshing..." : "Refresh"}
            </Button>
            <Button
              onClick={() => {
                setEditing(null);
                setDraft(buildDefaultDraft());
                setModalOpen(true);
              }}
            >
              <Plus className="mr-2 h-4 w-4" />
              Create user
            </Button>
          </>
        }
      />

      <Card>
        <CardHeader>
          <div>
            <CardTitle>Accounts</CardTitle>
            <p className="mt-1 text-sm text-slate-400">Only active accounts can authenticate to the frontend.</p>
          </div>
        </CardHeader>
        <CardBody className="p-0">
          <DataTable
            data={users}
            getRowKey={(item) => String(item.id)}
            columns={[
              {
                id: "user",
                header: "User",
                cell: (item) => (
                  <div>
                    <div className="font-medium text-white">{item.username}</div>
                    <div className="text-xs text-slate-500">{item.full_name ?? "No full name"}</div>
                  </div>
                ),
                sortAccessor: (item) => item.username
              },
              {
                id: "source",
                header: "Auth source",
                cell: (item) => item.auth_source,
                sortAccessor: (item) => item.auth_source
              },
              {
                id: "subject",
                header: "External subject",
                cell: (item) => item.external_subject ?? "N/A",
                sortAccessor: (item) => item.external_subject ?? ""
              },
              {
                id: "groups",
                header: "External groups",
                cell: (item) => (item.external_groups.length ? item.external_groups.join(", ") : "None"),
                sortAccessor: (item) => item.external_groups.join(",")
              },
              {
                id: "roles",
                header: "Roles",
                cell: (item) => item.roles.join(", "),
                sortAccessor: (item) => item.roles.join(",")
              },
              {
                id: "status",
                header: "Status",
                cell: (item) => <StatusBadge value={item.is_active ? "healthy" : "disabled"} />,
                sortAccessor: (item) => String(item.is_active)
              },
              {
                id: "actions",
                header: "Actions",
                cell: (item) => (
                  <div className="flex gap-2">
                    <Button
                      variant="secondary"
                      onClick={(event) => {
                        event.stopPropagation();
                        setEditing(item);
                        setDraft({
                          username: item.username,
                          fullName: item.full_name ?? "",
                          email: item.email ?? "",
                          authSource: item.auth_source,
                          password: "",
                          externalSubject: item.external_subject ?? "",
                          externalGroups: item.external_groups.join(","),
                          roles: item.roles.join(","),
                          isActive: item.is_active
                        });
                        setModalOpen(true);
                      }}
                    >
                      <UserCog className="mr-2 h-4 w-4" />
                      Edit
                    </Button>
                    <Button
                      variant="danger"
                      onClick={async (event) => {
                        event.stopPropagation();
                        try {
                          await api.deleteUser(item.id);
                          pushToast({ tone: "success", title: `Deleted user ${item.username}` });
                          await loadUsers();
                        } catch (error) {
                          pushToast({
                            tone: "error",
                            title: "Delete failed",
                            description: error instanceof Error ? error.message : "Unknown error"
                          });
                        }
                      }}
                    >
                      <Trash2 className="mr-2 h-4 w-4" />
                      Delete
                    </Button>
                  </div>
                )
              }
            ]}
          />
        </CardBody>
      </Card>

      <Modal
        open={modalOpen}
        title={editing ? `Edit ${editing.username}` : "Create user"}
        description="Configure local or external authentication mapping."
        onClose={() => setModalOpen(false)}
        footer={
          <>
            <Button variant="ghost" onClick={() => setModalOpen(false)}>
              Cancel
            </Button>
            <Button
              disabled={!draft.username.trim() || (draft.authSource === "local" && !editing && draft.password.length < 8)}
              onClick={async () => {
                const payload = {
                  username: draft.username.trim(),
                  full_name: draft.fullName.trim() || null,
                  email: draft.email.trim() || null,
                  is_active: draft.isActive,
                  auth_source: draft.authSource,
                  password: draft.password || undefined,
                  external_subject: draft.externalSubject.trim() || null,
                  external_groups: draft.externalGroups
                    .split(",")
                    .map((item) => item.trim())
                    .filter(Boolean),
                  roles: draft.roles
                    .split(",")
                    .map((item) => item.trim())
                    .filter(Boolean)
                };
                try {
                  if (editing) {
                    await api.updateUser(editing.id, payload);
                    pushToast({ tone: "success", title: "User updated" });
                  } else {
                    await api.createUser(payload);
                    pushToast({ tone: "success", title: "User created" });
                  }
                  setModalOpen(false);
                  await loadUsers();
                } catch (error) {
                  pushToast({
                    tone: "error",
                    title: "Failed to save user",
                    description: error instanceof Error ? error.message : "Unknown error"
                  });
                }
              }}
            >
              Save
            </Button>
          </>
        }
      >
        <div className="grid gap-4">
          <div className="grid gap-4 md:grid-cols-2">
            <label className="space-y-2">
              <span className="text-sm text-slate-300">Username</span>
              <input
                disabled={Boolean(editing)}
                value={draft.username}
                onChange={(event) => setDraft((current) => ({ ...current, username: event.target.value }))}
                className={inputClassName}
              />
            </label>
            <label className="space-y-2">
              <span className="text-sm text-slate-300">Auth source</span>
              <select
                disabled={Boolean(editing)}
                value={draft.authSource}
                onChange={(event) => setDraft((current) => ({ ...current, authSource: event.target.value as AuthProtocol }))}
                className={inputClassName}
              >
                <option value="local">local</option>
                <option value="ldap">ldap</option>
                <option value="radius">radius</option>
                <option value="oidc">oidc</option>
                <option value="oauth2">oauth2</option>
                <option value="saml">saml</option>
              </select>
            </label>
          </div>
          <div className="grid gap-4 md:grid-cols-2">
            <label className="space-y-2">
              <span className="text-sm text-slate-300">Full name</span>
              <input
                value={draft.fullName}
                onChange={(event) => setDraft((current) => ({ ...current, fullName: event.target.value }))}
                className={inputClassName}
              />
            </label>
            <label className="space-y-2">
              <span className="text-sm text-slate-300">Email</span>
              <input
                value={draft.email}
                onChange={(event) => setDraft((current) => ({ ...current, email: event.target.value }))}
                className={inputClassName}
              />
            </label>
          </div>
          {draft.authSource === "local" ? (
            <label className="space-y-2">
              <span className="text-sm text-slate-300">{editing ? "New password (optional)" : "Password"}</span>
              <input
                type="password"
                value={draft.password}
                onChange={(event) => setDraft((current) => ({ ...current, password: event.target.value }))}
                className={inputClassName}
              />
            </label>
          ) : (
            <>
              <label className="space-y-2">
                <span className="text-sm text-slate-300">External subject (provider username)</span>
                <input
                  value={draft.externalSubject}
                  onChange={(event) => setDraft((current) => ({ ...current, externalSubject: event.target.value }))}
                  className={inputClassName}
                />
              </label>
              <label className="space-y-2">
                <span className="text-sm text-slate-300">Allowed external groups (comma-separated)</span>
                <input
                  value={draft.externalGroups}
                  onChange={(event) => setDraft((current) => ({ ...current, externalGroups: event.target.value }))}
                  className={inputClassName}
                />
              </label>
            </>
          )}
          <label className="space-y-2">
            <span className="text-sm text-slate-300">Roles (comma-separated)</span>
            <input
              value={draft.roles}
              onChange={(event) => setDraft((current) => ({ ...current, roles: event.target.value }))}
              className={inputClassName}
            />
          </label>
          <label className="flex items-center gap-3 rounded-xl border border-border bg-slate-900 px-3 py-2.5">
            <input
              type="checkbox"
              checked={draft.isActive}
              onChange={(event) => setDraft((current) => ({ ...current, isActive: event.target.checked }))}
            />
            <span className="text-sm text-slate-300">User is active</span>
          </label>
        </div>
      </Modal>
    </div>
  );
}

