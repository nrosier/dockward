import { t, type MessageKey } from "../../i18n";
import type { SyncJob } from "../../types/api";

// The catalog key for a job's trigger. A trigger the client does not know shows as Webhook,
// the API's default.
export function triggerLabel(trigger: SyncJob["trigger"]): string {
  const keys: Record<SyncJob["trigger"], MessageKey> = {
    webhook: "syncJobs.trigger.webhook",
    poll: "syncJobs.trigger.poll",
    schedule: "syncJobs.trigger.schedule",
  };
  return t(keys[trigger] ?? "syncJobs.trigger.webhook");
}

// Fixed notes and messages the server keeps in last_error, shown as catalog text. Any other
// text is shown as the server stored it (fixed server text, no upstream content).
const NOTES: Record<string, MessageKey> = {
  "covered by parent index": "sync.note.coveredByParent",
  "no tagged image to scan": "sync.note.noTaggedImage",
  "a scan of this image is already running": "sync.note.scanAlreadyRunning",
};

export function noteText(lastError: string): string {
  const key = NOTES[lastError];
  return key === undefined ? lastError : t(key);
}

// The line a scheduled scan shows: the CVE ids new for the scanned image, or that nothing is
// new (#191). Null when the job is not a finished scheduled scan.
export function newVulnsText(job: SyncJob): string | null {
  const ids = job.report?.new_cve_ids;
  if (ids === null || ids === undefined) {
    return null;
  }
  return ids.length === 0 ? t("syncJobs.noNewVulns") : t("syncJobs.newVulns", { ids: ids.join(", ") });
}
