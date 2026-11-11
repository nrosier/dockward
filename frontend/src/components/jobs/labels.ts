import { t, type MessageKey } from "../../i18n";
import type { Job } from "../../types/api";

// The label for a job's trigger, from the payload. A trigger the client does not know shows as
// its raw value, never as a made-up label: an unknown trigger is shown, not hidden as Webhook.
export function triggerLabel(trigger: Job["trigger"]): string {
  const keys: Record<string, MessageKey> = {
    discovery: "jobs.trigger.discovery",
    first_pull: "jobs.trigger.firstPull",
    tag_moved: "jobs.trigger.tagMoved",
    db_update: "jobs.trigger.dbUpdate",
    manual: "jobs.trigger.manual",
  };
  if (trigger === null) {
    return t("jobs.trigger.none");
  }
  const key = keys[trigger];
  return key === undefined ? trigger : t(key);
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
export function newVulnsText(job: Job): string | null {
  const ids = job.report?.new_cve_ids;
  if (ids === null || ids === undefined) {
    return null;
  }
  return ids.length === 0 ? t("jobs.noNewVulns") : t("jobs.newVulns", { ids: ids.join(", ") });
}
