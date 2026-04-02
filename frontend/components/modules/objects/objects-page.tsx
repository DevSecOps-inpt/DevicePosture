"use client";

import { useEffect, useMemo, useState } from "react";
import { Boxes, Edit3, Plus, RefreshCcw, Trash2 } from "lucide-react";
import { api } from "@/lib/api";
import { Button } from "@/components/ui/button";
import { Card, CardBody } from "@/components/ui/card";
import { DataTable } from "@/components/ui/data-table";
import { EmptyState } from "@/components/ui/empty-state";
import { FilterBar } from "@/components/ui/filter-bar";
import { Modal } from "@/components/ui/modal";
import { PageHeader } from "@/components/ui/page-header";
import { Tabs } from "@/components/ui/tabs";
import { useToast } from "@/components/ui/toast-provider";
import { formatDateTime } from "@/lib/utils";
import type { ConditionGroup, IpObjectType } from "@/types/platform";

type ApiIpObject = {
  object_id: string;
  name: string;
  object_type: string;
  value: string;
  description: string | null;
  managed_by: string;
  created_at: string;
  updated_at: string;
  group_count: number;
};

type ApiIpGroup = {
  group_id: string;
  name: string;
  description: string | null;
  created_at: string;
  updated_at: string;
  member_count: number;
  member_object_ids: string[];
};

type IpObjectDraft = {
  name: string;
  description: string;
  type: IpObjectType;
  value: string;
};

type IpGroupDraft = {
  name: string;
  description: string;
  memberObjectIds: string[];
};

export function ObjectsPage() {
  const { pushToast } = useToast();
  const [activeTab, setActiveTab] = useState<"ip-objects" | "ip-groups" | "condition-groups">("ip-objects");
  const [search, setSearch] = useState("");
  const [typeFilter, setTypeFilter] = useState<"all" | IpObjectType>("all");
  const [loading, setLoading] = useState(true);
  const [ipObjects, setIpObjects] = useState<ApiIpObject[]>([]);
  const [ipGroups, setIpGroups] = useState<ApiIpGroup[]>([]);
  const [conditionGroups, setConditionGroups] = useState<ConditionGroup[]>([]);

  const [ipModalOpen, setIpModalOpen] = useState(false);
  const [groupModalOpen, setGroupModalOpen] = useState(false);
  const [conditionGroupModalOpen, setConditionGroupModalOpen] = useState(false);
  const [editingIpObjectId, setEditingIpObjectId] = useState<string | null>(null);
  const [editingIpGroupId, setEditingIpGroupId] = useState<string | null>(null);
  const [editingConditionGroupId, setEditingConditionGroupId] = useState<number | null>(null);
  const [editingGroupOriginalMembers, setEditingGroupOriginalMembers] = useState<string[]>([]);

  const [ipDraft, setIpDraft] = useState<IpObjectDraft>({
    name: "",
    description: "",
    type: "host",
    value: "",
  });
  const [groupDraft, setGroupDraft] = useState<IpGroupDraft>({
    name: "",
    description: "",
    memberObjectIds: [],
  });
  const [conditionGroupDraft, setConditionGroupDraft] = useState<{
    name: string;
    group_type: ConditionGroup["group_type"];
    description: string;
    valuesText: string;
  }>({
    name: "",
    group_type: "allowed_os",
    description: "",
    valuesText: "",
  });

  async function loadData() {
    setLoading(true);
    try {
      const [objects, groups, conditionGroupsResponse] = await Promise.all([
        api.listIpObjects(),
        api.listIpGroups(),
        api.listConditionGroups().catch(() => []),
      ]);
      setIpObjects(objects);
      setIpGroups(groups);
      setConditionGroups(conditionGroupsResponse);
    } catch (error) {
      pushToast({
        tone: "error",
        title: "Failed to load objects",
        description: error instanceof Error ? error.message : "Unknown error",
      });
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    void loadData();
  }, []);

  const objectNameById = useMemo(() => {
    const map = new Map<string, string>();
    for (const item of ipObjects) {
      map.set(item.object_id, item.name);
    }
    return map;
  }, [ipObjects]);

  const filteredIpObjects = useMemo(() => {
    const term = search.trim().toLowerCase();
    return ipObjects.filter((object) => {
      const matchesSearch =
        term.length === 0 ||
        object.name.toLowerCase().includes(term) ||
        object.value.toLowerCase().includes(term) ||
        (object.description ?? "").toLowerCase().includes(term);
      const matchesType = typeFilter === "all" || object.object_type === typeFilter;
      return matchesSearch && matchesType;
    });
  }, [ipObjects, search, typeFilter]);

  const filteredIpGroups = useMemo(() => {
    const term = search.trim().toLowerCase();
    return ipGroups.filter((group) => {
      if (term.length === 0) {
        return true;
      }
      const memberNames = group.member_object_ids
        .map((id) => objectNameById.get(id) ?? id)
        .join(" ")
        .toLowerCase();
      return (
        group.name.toLowerCase().includes(term) ||
        (group.description ?? "").toLowerCase().includes(term) ||
        memberNames.includes(term)
      );
    });
  }, [ipGroups, objectNameById, search]);

  const filteredConditionGroups = useMemo(() => {
    const term = search.trim().toLowerCase();
    return conditionGroups.filter((group) => {
      if (term.length === 0) {
        return true;
      }
      return (
        group.name.toLowerCase().includes(term) ||
        group.group_type.toLowerCase().includes(term) ||
        (group.description ?? "").toLowerCase().includes(term) ||
        group.values.join(" ").toLowerCase().includes(term)
      );
    });
  }, [conditionGroups, search]);

  function resetIpDraft() {
    setIpDraft({ name: "", description: "", type: "host", value: "" });
    setEditingIpObjectId(null);
  }

  function resetGroupDraft() {
    setGroupDraft({ name: "", description: "", memberObjectIds: [] });
    setEditingIpGroupId(null);
    setEditingGroupOriginalMembers([]);
  }

  function resetConditionGroupDraft() {
    setEditingConditionGroupId(null);
    setConditionGroupDraft({
      name: "",
      group_type: "allowed_os",
      description: "",
      valuesText: "",
    });
  }

  function validateIpDraft(draft: IpObjectDraft): string | null {
    if (!draft.name.trim()) {
      return "Object name is required.";
    }
    if (!draft.value.trim()) {
      return "Object value is required.";
    }
    if (draft.type === "host" && !/^\d{1,3}(\.\d{1,3}){3}$/.test(draft.value.trim())) {
      return "Host value should look like an IPv4 address (for example 10.20.30.40).";
    }
    if (draft.type === "cidr" && !/^\d{1,3}(\.\d{1,3}){3}\/\d{1,2}$/.test(draft.value.trim())) {
      return "CIDR value should look like 10.20.30.0/24.";
    }
    return null;
  }

  async function saveIpObject() {
    const error = validateIpDraft(ipDraft);
    if (error) {
      pushToast({ tone: "error", title: "Invalid IP object", description: error });
      return;
    }

    try {
      if (editingIpObjectId) {
        await api.updateIpObject(editingIpObjectId, {
          name: ipDraft.name.trim(),
          object_type: ipDraft.type,
          value: ipDraft.value.trim(),
          description: ipDraft.description.trim() || null,
        });
        pushToast({ tone: "success", title: "IP object updated" });
      } else {
        await api.createIpObject({
          name: ipDraft.name.trim(),
          object_type: ipDraft.type,
          value: ipDraft.value.trim(),
          description: ipDraft.description.trim() || null,
        });
        pushToast({ tone: "success", title: "IP object created" });
      }
      setIpModalOpen(false);
      resetIpDraft();
      await loadData();
    } catch (saveError) {
      pushToast({
        tone: "error",
        title: "Failed to save IP object",
        description: saveError instanceof Error ? saveError.message : "Unknown error",
      });
    }
  }

  async function saveIpGroup() {
    if (!groupDraft.name.trim()) {
      pushToast({ tone: "error", title: "Group name is required" });
      return;
    }
    if (groupDraft.memberObjectIds.length === 0) {
      pushToast({ tone: "error", title: "Select at least one object for this group" });
      return;
    }

    try {
      let currentGroupName = groupDraft.name.trim();
      if (editingIpGroupId) {
        const updated = await api.updateIpGroup(editingIpGroupId, {
          name: groupDraft.name.trim(),
          description: groupDraft.description.trim() || null,
        });
        const updatedGroup = updated as ApiIpGroup;
        currentGroupName = updatedGroup.name;
        const wanted = new Set(groupDraft.memberObjectIds);
        const current = new Set(editingGroupOriginalMembers);

        for (const objectId of wanted) {
          if (!current.has(objectId)) {
            await api.addObjectToGroup(currentGroupName, objectId);
          }
        }
        for (const objectId of current) {
          if (!wanted.has(objectId)) {
            await api.removeObjectFromGroup(currentGroupName, objectId);
          }
        }
        pushToast({ tone: "success", title: "IP group updated" });
      } else {
        const created = await api.createIpGroup({
          name: groupDraft.name.trim(),
          description: groupDraft.description.trim() || null,
        });
        const createdGroup = created as ApiIpGroup;
        currentGroupName = createdGroup.name;
        for (const objectId of groupDraft.memberObjectIds) {
          await api.addObjectToGroup(currentGroupName, objectId);
        }
        pushToast({ tone: "success", title: "IP group created" });
      }

      setGroupModalOpen(false);
      resetGroupDraft();
      await loadData();
    } catch (saveError) {
      pushToast({
        tone: "error",
        title: "Failed to save group",
        description: saveError instanceof Error ? saveError.message : "Unknown error",
      });
    }
  }

  async function saveConditionGroup() {
    if (!conditionGroupDraft.name.trim()) {
      pushToast({ tone: "error", title: "Group name is required" });
      return;
    }

    const values = conditionGroupDraft.valuesText
      .split(/[\n,]/)
      .map((value) => value.trim())
      .filter(Boolean);
    if (values.length === 0) {
      pushToast({ tone: "error", title: "At least one value is required" });
      return;
    }

    try {
      if (editingConditionGroupId !== null) {
        await api.updateConditionGroup(editingConditionGroupId, {
          name: conditionGroupDraft.name.trim(),
          group_type: conditionGroupDraft.group_type,
          description: conditionGroupDraft.description.trim() || null,
          values,
        });
        pushToast({ tone: "success", title: "Condition group updated" });
      } else {
        await api.createConditionGroup({
          name: conditionGroupDraft.name.trim(),
          group_type: conditionGroupDraft.group_type,
          description: conditionGroupDraft.description.trim() || null,
          values,
        });
        pushToast({ tone: "success", title: "Condition group created" });
      }

      setConditionGroupModalOpen(false);
      resetConditionGroupDraft();
      await loadData();
    } catch (error) {
      pushToast({
        tone: "error",
        title: "Failed to save condition group",
        description: error instanceof Error ? error.message : "Unknown error",
      });
    }
  }

  async function removeIpObject(item: ApiIpObject) {
    if (!window.confirm(`Delete IP object "${item.name}"?`)) {
      return;
    }
    try {
      await api.deleteIpObject(item.object_id);
      pushToast({ tone: "success", title: "IP object deleted" });
      await loadData();
    } catch (error) {
      pushToast({
        tone: "error",
        title: "Failed to delete object",
        description: error instanceof Error ? error.message : "Unknown error",
      });
    }
  }

  async function removeIpGroup(item: ApiIpGroup) {
    if (!window.confirm(`Delete IP group "${item.name}"?`)) {
      return;
    }
    try {
      await api.deleteIpGroup(item.group_id);
      pushToast({ tone: "success", title: "IP group deleted" });
      await loadData();
    } catch (error) {
      pushToast({
        tone: "error",
        title: "Failed to delete group",
        description: error instanceof Error ? error.message : "Unknown error",
      });
    }
  }

  async function removeConditionGroup(item: ConditionGroup) {
    if (!window.confirm(`Delete condition group "${item.name}"?`)) {
      return;
    }
    try {
      await api.deleteConditionGroup(item.id);
      pushToast({ tone: "success", title: "Condition group deleted" });
      await loadData();
    } catch (error) {
      pushToast({
        tone: "error",
        title: "Failed to delete condition group",
        description: error instanceof Error ? error.message : "Unknown error",
      });
    }
  }

  function openEditIpObject(item: ApiIpObject) {
    setEditingIpObjectId(item.object_id);
    setIpDraft({
      name: item.name,
      description: item.description ?? "",
      type: item.object_type === "cidr" ? "cidr" : "host",
      value: item.value,
    });
    setIpModalOpen(true);
  }

  function openEditIpGroup(item: ApiIpGroup) {
    setEditingIpGroupId(item.group_id);
    setEditingGroupOriginalMembers([...item.member_object_ids]);
    setGroupDraft({
      name: item.name,
      description: item.description ?? "",
      memberObjectIds: [...item.member_object_ids],
    });
    setGroupModalOpen(true);
  }

  function openEditConditionGroup(item: ConditionGroup) {
    setEditingConditionGroupId(item.id);
    setConditionGroupDraft({
      name: item.name,
      group_type: item.group_type,
      description: item.description ?? "",
      valuesText: item.values.join(", "),
    });
    setConditionGroupModalOpen(true);
  }

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="Reusable Resources"
        title="Objects"
        description="Manage IP objects plus policy allow-groups (OS, patches, antivirus families)."
        actions={
          <>
            <Button variant="secondary" onClick={() => void loadData()} disabled={loading}>
              <RefreshCcw className="mr-2 h-4 w-4" />
              {loading ? "Refreshing..." : "Refresh"}
            </Button>
            <Button variant="secondary" onClick={() => { resetIpDraft(); setIpModalOpen(true); }}>
              <Plus className="mr-2 h-4 w-4" />
              New IP object
            </Button>
            <Button onClick={() => { resetGroupDraft(); setGroupModalOpen(true); }} disabled={ipObjects.length === 0}>
              <Plus className="mr-2 h-4 w-4" />
              New IP group
            </Button>
            <Button
              variant="secondary"
              onClick={() => { resetConditionGroupDraft(); setConditionGroupModalOpen(true); }}
            >
              <Plus className="mr-2 h-4 w-4" />
              New allow-group
            </Button>
          </>
        }
      />

      <Tabs
        tabs={[
          { label: "IP Objects", value: "ip-objects" },
          { label: "IP Groups", value: "ip-groups" },
          { label: "Policy Allow-Groups", value: "condition-groups" },
        ]}
        value={activeTab}
        onChange={(value) => setActiveTab(value as "ip-objects" | "ip-groups" | "condition-groups")}
      />

      <FilterBar
        searchValue={search}
        onSearchChange={setSearch}
        searchPlaceholder={
          activeTab === "ip-objects"
            ? "Search objects by name, value, or description"
            : activeTab === "ip-groups"
              ? "Search groups or members"
              : "Search allow-groups"
        }
        filters={
          activeTab === "ip-objects"
            ? [
                {
                  id: "type",
                  label: "Type",
                  value: typeFilter,
                  onChange: (value) => setTypeFilter(value as "all" | IpObjectType),
                  options: [
                    { label: "All types", value: "all" },
                    { label: "Host", value: "host" },
                    { label: "CIDR", value: "cidr" },
                  ],
                },
              ]
            : []
        }
      />

      {activeTab === "ip-objects" ? (
        <Card>
          <CardBody className="p-0">
            {filteredIpObjects.length === 0 ? (
              <EmptyState
                icon={Boxes}
                title="No IP objects"
                description="Create host and CIDR objects here. Policies can also create endpoint host objects dynamically."
                action={<Button onClick={() => { resetIpDraft(); setIpModalOpen(true); }}>Create object</Button>}
              />
            ) : (
              <DataTable
                data={filteredIpObjects}
                getRowKey={(item) => item.object_id}
                columns={[
                  {
                    id: "name",
                    header: "Name",
                    cell: (item) => (
                      <div>
                        <div className="font-medium text-white">{item.name}</div>
                        <div className="text-xs text-slate-500">{item.description ?? "No description"}</div>
                      </div>
                    ),
                    sortAccessor: (item) => item.name,
                  },
                  {
                    id: "type",
                    header: "Type",
                    cell: (item) => item.object_type,
                    sortAccessor: (item) => item.object_type,
                  },
                  { id: "value", header: "Value", cell: (item) => item.value, sortAccessor: (item) => item.value },
                  {
                    id: "managed",
                    header: "Managed by",
                    cell: (item) => item.managed_by,
                    sortAccessor: (item) => item.managed_by,
                  },
                  {
                    id: "groups",
                    header: "Groups",
                    cell: (item) => item.group_count,
                    sortAccessor: (item) => item.group_count,
                  },
                  {
                    id: "updated",
                    header: "Updated",
                    cell: (item) => formatDateTime(item.updated_at),
                    sortAccessor: (item) => item.updated_at,
                  },
                  {
                    id: "actions",
                    header: "Actions",
                    cell: (item) => (
                      <div className="flex gap-2">
                        <Button variant="ghost" className="px-2 py-1.5" onClick={(event) => { event.stopPropagation(); openEditIpObject(item); }}>
                          <Edit3 className="h-4 w-4" />
                        </Button>
                        <Button
                          variant="ghost"
                          className="px-2 py-1.5 text-rose-300 hover:text-rose-200"
                          onClick={(event) => { event.stopPropagation(); void removeIpObject(item); }}
                        >
                          <Trash2 className="h-4 w-4" />
                        </Button>
                      </div>
                    ),
                  },
                ]}
              />
            )}
          </CardBody>
        </Card>
      ) : activeTab === "ip-groups" ? (
        <Card>
          <CardBody className="p-0">
            {filteredIpGroups.length === 0 ? (
              <EmptyState
                icon={Boxes}
                title="No IP groups"
                description="Create groups and assign IP objects. Policy actions can automatically add or remove endpoint IPs."
                action={<Button onClick={() => { resetGroupDraft(); setGroupModalOpen(true); }}>Create group</Button>}
              />
            ) : (
              <DataTable
                data={filteredIpGroups}
                getRowKey={(item) => item.group_id}
                columns={[
                  {
                    id: "name",
                    header: "Group",
                    cell: (item) => (
                      <div>
                        <div className="font-medium text-white">{item.name}</div>
                        <div className="text-xs text-slate-500">{item.description ?? "No description"}</div>
                      </div>
                    ),
                    sortAccessor: (item) => item.name,
                  },
                  {
                    id: "members",
                    header: "Members",
                    cell: (item) => item.member_count,
                    sortAccessor: (item) => item.member_count,
                  },
                  {
                    id: "list",
                    header: "Member objects",
                    cell: (item) =>
                      item.member_object_ids
                        .slice(0, 3)
                        .map((id) => objectNameById.get(id) ?? id)
                        .join(", ") + (item.member_object_ids.length > 3 ? ` +${item.member_object_ids.length - 3}` : ""),
                    sortAccessor: (item) => item.member_count,
                  },
                  {
                    id: "updated",
                    header: "Updated",
                    cell: (item) => formatDateTime(item.updated_at),
                    sortAccessor: (item) => item.updated_at,
                  },
                  {
                    id: "actions",
                    header: "Actions",
                    cell: (item) => (
                      <div className="flex gap-2">
                        <Button variant="ghost" className="px-2 py-1.5" onClick={(event) => { event.stopPropagation(); openEditIpGroup(item); }}>
                          <Edit3 className="h-4 w-4" />
                        </Button>
                        <Button
                          variant="ghost"
                          className="px-2 py-1.5 text-rose-300 hover:text-rose-200"
                          onClick={(event) => { event.stopPropagation(); void removeIpGroup(item); }}
                        >
                          <Trash2 className="h-4 w-4" />
                        </Button>
                      </div>
                    ),
                  },
                ]}
              />
            )}
          </CardBody>
        </Card>
      ) : (
        <Card>
          <CardBody className="p-0">
            {filteredConditionGroups.length === 0 ? (
              <EmptyState
                icon={Boxes}
                title="No policy allow-groups"
                description="Create allowed OS, patch, and antivirus-family groups used by policy conditions."
                action={
                  <Button onClick={() => { resetConditionGroupDraft(); setConditionGroupModalOpen(true); }}>
                    Create allow-group
                  </Button>
                }
              />
            ) : (
              <DataTable
                data={filteredConditionGroups}
                getRowKey={(item) => String(item.id)}
                columns={[
                  {
                    id: "name",
                    header: "Group",
                    cell: (item) => (
                      <div>
                        <div className="font-medium text-white">{item.name}</div>
                        <div className="text-xs text-slate-500">{item.description ?? "No description"}</div>
                      </div>
                    ),
                    sortAccessor: (item) => item.name,
                  },
                  {
                    id: "type",
                    header: "Type",
                    cell: (item) => item.group_type,
                    sortAccessor: (item) => item.group_type,
                  },
                  {
                    id: "values",
                    header: "Values",
                    cell: (item) =>
                      item.values.slice(0, 3).join(", ") + (item.values.length > 3 ? ` +${item.values.length - 3}` : ""),
                    sortAccessor: (item) => item.values.length,
                  },
                  {
                    id: "updated",
                    header: "Updated",
                    cell: (item) => formatDateTime(item.updated_at),
                    sortAccessor: (item) => item.updated_at,
                  },
                  {
                    id: "actions",
                    header: "Actions",
                    cell: (item) => (
                      <div className="flex gap-2">
                        <Button
                          variant="ghost"
                          className="px-2 py-1.5"
                          onClick={(event) => { event.stopPropagation(); openEditConditionGroup(item); }}
                        >
                          <Edit3 className="h-4 w-4" />
                        </Button>
                        <Button
                          variant="ghost"
                          className="px-2 py-1.5 text-rose-300 hover:text-rose-200"
                          onClick={(event) => { event.stopPropagation(); void removeConditionGroup(item); }}
                        >
                          <Trash2 className="h-4 w-4" />
                        </Button>
                      </div>
                    ),
                  },
                ]}
              />
            )}
          </CardBody>
        </Card>
      )}

      <Modal
        open={ipModalOpen}
        title={editingIpObjectId ? "Edit IP object" : "Create IP object"}
        description="Define host or CIDR objects used by policy and adapter logic."
        onClose={() => { setIpModalOpen(false); resetIpDraft(); }}
        footer={
          <>
            <Button variant="ghost" onClick={() => { setIpModalOpen(false); resetIpDraft(); }}>
              Cancel
            </Button>
            <Button onClick={() => void saveIpObject()} disabled={!ipDraft.name.trim() || !ipDraft.value.trim()}>
              {editingIpObjectId ? "Update object" : "Create object"}
            </Button>
          </>
        }
      >
        <div className="grid gap-4">
          <label className="space-y-2">
            <span className="text-sm text-slate-300">Name</span>
            <input
              value={ipDraft.name}
              onChange={(event) => setIpDraft((current) => ({ ...current, name: event.target.value }))}
              className="w-full rounded-xl border border-border bg-slate-900 px-3 py-2.5 text-sm text-white outline-none focus:border-teal-500"
            />
          </label>
          <label className="space-y-2">
            <span className="text-sm text-slate-300">Description</span>
            <textarea
              rows={3}
              value={ipDraft.description}
              onChange={(event) => setIpDraft((current) => ({ ...current, description: event.target.value }))}
              className="w-full rounded-xl border border-border bg-slate-900 px-3 py-2.5 text-sm text-white outline-none focus:border-teal-500"
            />
          </label>
          <div className="grid gap-4 md:grid-cols-2">
            <label className="space-y-2">
              <span className="text-sm text-slate-300">Type</span>
              <select
                value={ipDraft.type}
                onChange={(event) => setIpDraft((current) => ({ ...current, type: event.target.value as IpObjectType }))}
                className="w-full rounded-xl border border-border bg-slate-900 px-3 py-2.5 text-sm text-white outline-none focus:border-teal-500"
              >
                <option value="host">host</option>
                <option value="cidr">cidr</option>
              </select>
            </label>
            <label className="space-y-2">
              <span className="text-sm text-slate-300">Value</span>
              <input
                value={ipDraft.value}
                onChange={(event) => setIpDraft((current) => ({ ...current, value: event.target.value }))}
                placeholder={ipDraft.type === "host" ? "10.20.30.40" : "10.20.30.0/24"}
                className="w-full rounded-xl border border-border bg-slate-900 px-3 py-2.5 font-mono text-sm text-white outline-none focus:border-teal-500"
              />
            </label>
          </div>
        </div>
      </Modal>

      <Modal
        open={groupModalOpen}
        title={editingIpGroupId ? "Edit IP group" : "Create IP group"}
        description="Groups are used by policy execution to add or remove endpoint IPs dynamically."
        onClose={() => { setGroupModalOpen(false); resetGroupDraft(); }}
        footer={
          <>
            <Button variant="ghost" onClick={() => { setGroupModalOpen(false); resetGroupDraft(); }}>
              Cancel
            </Button>
            <Button onClick={() => void saveIpGroup()} disabled={!groupDraft.name.trim() || groupDraft.memberObjectIds.length === 0}>
              {editingIpGroupId ? "Update group" : "Create group"}
            </Button>
          </>
        }
      >
        <div className="grid gap-4">
          <label className="space-y-2">
            <span className="text-sm text-slate-300">Group name</span>
            <input
              value={groupDraft.name}
              onChange={(event) => setGroupDraft((current) => ({ ...current, name: event.target.value }))}
              className="w-full rounded-xl border border-border bg-slate-900 px-3 py-2.5 text-sm text-white outline-none focus:border-teal-500"
            />
          </label>
          <label className="space-y-2">
            <span className="text-sm text-slate-300">Description</span>
            <textarea
              rows={3}
              value={groupDraft.description}
              onChange={(event) => setGroupDraft((current) => ({ ...current, description: event.target.value }))}
              className="w-full rounded-xl border border-border bg-slate-900 px-3 py-2.5 text-sm text-white outline-none focus:border-teal-500"
            />
          </label>
          <div className="space-y-2">
            <span className="text-sm text-slate-300">Member objects</span>
            {ipObjects.length === 0 ? (
              <p className="rounded-xl border border-border bg-slate-900 px-3 py-3 text-sm text-slate-400">
                No IP objects available.
              </p>
            ) : (
              <div className="max-h-56 space-y-2 overflow-auto rounded-xl border border-border bg-slate-900 p-3">
                {ipObjects.map((item) => {
                  const checked = groupDraft.memberObjectIds.includes(item.object_id);
                  return (
                    <label key={item.object_id} className="flex items-start gap-3 rounded-lg px-2 py-2 hover:bg-slate-800">
                      <input
                        type="checkbox"
                        checked={checked}
                        onChange={(event) => {
                          setGroupDraft((current) => {
                            const set = new Set(current.memberObjectIds);
                            if (event.target.checked) {
                              set.add(item.object_id);
                            } else {
                              set.delete(item.object_id);
                            }
                            return { ...current, memberObjectIds: Array.from(set) };
                          });
                        }}
                      />
                      <span>
                        <span className="block text-sm text-white">{item.name}</span>
                        <span className="block text-xs text-slate-400">
                          {item.object_type} - {item.value}
                        </span>
                      </span>
                    </label>
                  );
                })}
              </div>
            )}
          </div>
        </div>
      </Modal>

      <Modal
        open={conditionGroupModalOpen}
        title={editingConditionGroupId !== null ? "Edit allow-group" : "Create allow-group"}
        description="Allow-groups are used by policy conditions for OS, patches, and antivirus family checks."
        onClose={() => { setConditionGroupModalOpen(false); resetConditionGroupDraft(); }}
        footer={
          <>
            <Button variant="ghost" onClick={() => { setConditionGroupModalOpen(false); resetConditionGroupDraft(); }}>
              Cancel
            </Button>
            <Button onClick={() => void saveConditionGroup()} disabled={!conditionGroupDraft.name.trim()}>
              {editingConditionGroupId !== null ? "Update group" : "Create group"}
            </Button>
          </>
        }
      >
        <div className="grid gap-4">
          <label className="space-y-2">
            <span className="text-sm text-slate-300">Group name</span>
            <input
              value={conditionGroupDraft.name}
              onChange={(event) => setConditionGroupDraft((current) => ({ ...current, name: event.target.value }))}
              className="w-full rounded-xl border border-border bg-slate-900 px-3 py-2.5 text-sm text-white outline-none focus:border-teal-500"
            />
          </label>
          <label className="space-y-2">
            <span className="text-sm text-slate-300">Group type</span>
            <select
              value={conditionGroupDraft.group_type}
              onChange={(event) =>
                setConditionGroupDraft((current) => ({
                  ...current,
                  group_type: event.target.value as ConditionGroup["group_type"],
                }))
              }
              className="w-full rounded-xl border border-border bg-slate-900 px-3 py-2.5 text-sm text-white outline-none focus:border-teal-500"
            >
              <option value="allowed_os">allowed_os</option>
              <option value="allowed_patches">allowed_patches</option>
              <option value="allowed_antivirus_families">allowed_antivirus_families</option>
            </select>
          </label>
          <label className="space-y-2">
            <span className="text-sm text-slate-300">Description</span>
            <textarea
              rows={3}
              value={conditionGroupDraft.description}
              onChange={(event) =>
                setConditionGroupDraft((current) => ({ ...current, description: event.target.value }))
              }
              className="w-full rounded-xl border border-border bg-slate-900 px-3 py-2.5 text-sm text-white outline-none focus:border-teal-500"
            />
          </label>
          <label className="space-y-2">
            <span className="text-sm text-slate-300">Values</span>
            <textarea
              rows={5}
              value={conditionGroupDraft.valuesText}
              onChange={(event) =>
                setConditionGroupDraft((current) => ({ ...current, valuesText: event.target.value }))
              }
              placeholder="Enter values separated by commas or new lines"
              className="w-full rounded-xl border border-border bg-slate-900 px-3 py-2.5 text-sm text-white outline-none focus:border-teal-500"
            />
          </label>
        </div>
      </Modal>
    </div>
  );
}
