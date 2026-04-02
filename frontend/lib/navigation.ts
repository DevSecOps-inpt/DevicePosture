import {
  Activity,
  AlertTriangle,
  Blocks,
  Cable,
  FileClock,
  Gauge,
  HeartPulse,
  Network,
  Puzzle,
  ScrollText,
  Settings,
  UserCog
} from "lucide-react";
import type { LucideIcon } from "lucide-react";

export interface NavigationItem {
  label: string;
  href: string;
  icon: LucideIcon;
}

export interface NavigationGroup {
  title: string;
  items: NavigationItem[];
}

export const navigationGroups: NavigationGroup[] = [
  {
    title: "Overview",
    items: [{ label: "Dashboard", href: "/dashboard", icon: Gauge }]
  },
  {
    title: "Operations",
    items: [
      { label: "Endpoints", href: "/endpoints", icon: Network },
      { label: "Policies", href: "/policies", icon: ScrollText },
      { label: "Objects", href: "/objects", icon: Blocks },
      { label: "Adapters", href: "/adapters", icon: Cable },
      { label: "Extensions", href: "/extensions", icon: Puzzle }
    ]
  },
  {
    title: "Monitoring",
    items: [
      { label: "Events / Logs", href: "/events", icon: Activity },
      { label: "IT Hygiene", href: "/it-hygiene", icon: HeartPulse },
      { label: "Tasks / Jobs", href: "/tasks", icon: FileClock },
      { label: "Alerts / Findings", href: "/alerts", icon: AlertTriangle }
    ]
  },
  {
    title: "Platform",
    items: [
      { label: "User Administration", href: "/users", icon: UserCog },
      { label: "Settings", href: "/settings", icon: Settings }
    ]
  }
];

export const quickSearchSuggestions = [
  "Search endpoints",
  "Open unhealthy adapters",
  "Locate pending policy jobs",
  "Find critical alerts"
];
