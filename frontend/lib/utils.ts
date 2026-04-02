export function cn(...classes: Array<string | false | null | undefined>) {
  return classes.filter(Boolean).join(" ");
}

export function formatDateTime(value: string) {
  return new Intl.DateTimeFormat("en", {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit"
  }).format(new Date(value));
}

export function formatDate(value: string) {
  return new Intl.DateTimeFormat("en", {
    year: "numeric",
    month: "short",
    day: "numeric"
  }).format(new Date(value));
}

export function relativeTime(value: string) {
  const date = new Date(value);
  const diff = date.getTime() - Date.now();
  const minutes = Math.round(diff / 60000);
  const formatter = new Intl.RelativeTimeFormat("en", { numeric: "auto" });

  if (Math.abs(minutes) < 60) {
    return formatter.format(minutes, "minute");
  }

  const hours = Math.round(minutes / 60);
  if (Math.abs(hours) < 24) {
    return formatter.format(hours, "hour");
  }

  return formatter.format(Math.round(hours / 24), "day");
}

export function relativeTimeFromSeconds(secondsSince: number | null | undefined) {
  if (secondsSince === null || secondsSince === undefined || Number.isNaN(secondsSince)) {
    return "Unavailable";
  }

  const formatter = new Intl.RelativeTimeFormat("en", { numeric: "auto" });
  if (secondsSince < 60) {
    return formatter.format(-Math.round(secondsSince), "second");
  }

  const minutes = Math.round(secondsSince / 60);
  if (minutes < 60) {
    return formatter.format(-minutes, "minute");
  }

  const hours = Math.round(minutes / 60);
  if (hours < 24) {
    return formatter.format(-hours, "hour");
  }

  return formatter.format(-Math.round(hours / 24), "day");
}
