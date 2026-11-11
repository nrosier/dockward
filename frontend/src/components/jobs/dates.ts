import { t } from "../../i18n";

const MINUTE = 60_000;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;

function pad(n: number): string {
  return String(n).padStart(2, "0");
}

// Relative within 24 hours ("2 min ago"), else `YYYY-MM-DD HH:mm` in local
// time (specs/frontend.md, the list pages). The caller puts the full RFC 3339
// value in a `title`.
export function formatWhen(iso: string | null, now: number = Date.now()): string {
  if (iso === null) {
    return "";
  }
  const at = new Date(iso);
  if (Number.isNaN(at.getTime())) {
    return "";
  }
  const age = now - at.getTime();
  if (age < DAY) {
    if (age < MINUTE) {
      return t("jobs.time.justNow");
    }
    if (age < HOUR) {
      return t("jobs.time.minutesAgo", { n: Math.floor(age / MINUTE) });
    }
    return t("jobs.time.hoursAgo", { n: Math.floor(age / HOUR) });
  }
  return `${at.getFullYear()}-${pad(at.getMonth() + 1)}-${pad(at.getDate())} ${pad(at.getHours())}:${pad(at.getMinutes())}`;
}

// `YYYY-MM-DD HH:mm` in local time, for a time in the future (the next attempt).
// Unlike formatWhen, it never says "Just now" for a future time.
export function formatDateTime(iso: string | null): string {
  if (iso === null) {
    return "";
  }
  const at = new Date(iso);
  if (Number.isNaN(at.getTime())) {
    return "";
  }
  return `${at.getFullYear()}-${pad(at.getMonth() + 1)}-${pad(at.getDate())} ${pad(at.getHours())}:${pad(at.getMinutes())}`;
}

// `YYYY-MM-DD` in local time, for "first seen".
export function formatDate(iso: string | null): string {
  if (iso === null) {
    return "";
  }
  const at = new Date(iso);
  if (Number.isNaN(at.getTime())) {
    return "";
  }
  return `${at.getFullYear()}-${pad(at.getMonth() + 1)}-${pad(at.getDate())}`;
}

// `HH:mm:ss` in local time, for a log line.
export function formatClock(iso: string): string {
  const at = new Date(iso);
  if (Number.isNaN(at.getTime())) {
    return "";
  }
  return `${pad(at.getHours())}:${pad(at.getMinutes())}:${pad(at.getSeconds())}`;
}
