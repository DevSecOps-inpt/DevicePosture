import type { IpGroup, IpObject } from "@/types/platform";

const STORAGE_KEY = "device-posture-objects-v1";

export interface ObjectsStoreState {
  ipObjects: IpObject[];
  ipGroups: IpGroup[];
}

export function loadObjectsStore(): ObjectsStoreState {
  if (typeof window === "undefined") {
    return { ipObjects: [], ipGroups: [] };
  }

  const raw = window.localStorage.getItem(STORAGE_KEY);
  if (!raw) {
    return { ipObjects: [], ipGroups: [] };
  }

  try {
    const parsed = JSON.parse(raw) as Partial<ObjectsStoreState>;
    return {
      ipObjects: Array.isArray(parsed.ipObjects) ? parsed.ipObjects : [],
      ipGroups: Array.isArray(parsed.ipGroups) ? parsed.ipGroups : []
    };
  } catch {
    return { ipObjects: [], ipGroups: [] };
  }
}

export function saveObjectsStore(state: ObjectsStoreState): void {
  if (typeof window === "undefined") {
    return;
  }
  window.localStorage.setItem(STORAGE_KEY, JSON.stringify(state));
}

export function createObjectId(prefix: string): string {
  return `${prefix}-${Math.random().toString(36).slice(2, 10)}`;
}

function parseIpv4(value: string): number[] | null {
  const trimmed = value.trim();
  const parts = trimmed.split(".");
  if (parts.length !== 4) {
    return null;
  }

  const octets: number[] = [];
  for (const part of parts) {
    if (!/^\d+$/.test(part)) {
      return null;
    }
    const num = Number(part);
    if (!Number.isInteger(num) || num < 0 || num > 255) {
      return null;
    }
    octets.push(num);
  }
  return octets;
}

export function isValidIpv4(value: string): boolean {
  return parseIpv4(value) !== null;
}

export function isValidIpv4Cidr(value: string): boolean {
  const trimmed = value.trim();
  const slashIdx = trimmed.indexOf("/");
  if (slashIdx <= 0) {
    return false;
  }

  const ipPart = trimmed.slice(0, slashIdx);
  const prefixPart = trimmed.slice(slashIdx + 1);

  if (!isValidIpv4(ipPart) || !/^\d+$/.test(prefixPart)) {
    return false;
  }

  const prefix = Number(prefixPart);
  return Number.isInteger(prefix) && prefix >= 0 && prefix <= 32;
}
