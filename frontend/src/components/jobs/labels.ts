import { t, type MessageKey } from "../../i18n";
import type { Job } from "../../types/api";
import { shortDigest } from "../ui/ShaBadge";

// The label for a job's trigger, from the payload. Never blank or "None": a job with no trigger
// is a scheduled one. A trigger the client does not know shows as its raw value.
export function triggerLabel(trigger: Job["trigger"]): string {
  const keys: Record<string, MessageKey> = {
    discovery: "jobs.trigger.discovery",
    first_pull: "jobs.trigger.onPull",
    tag_moved: "jobs.trigger.onTag",
    db_update: "jobs.trigger.scheduledDbUpdate",
    manual: "jobs.trigger.manual",
    scheduled: "jobs.trigger.scheduled",
  };
  if (trigger === null || trigger.trim() === "") {
    return t("jobs.trigger.scheduled");
  }
  const key = keys[trigger];
  return key === undefined ? trigger : t(key);
}

function imageName(job: Job): string | null {
  const { repo_full_name: repo, tag } = job.image;
  if (repo === null) {
    return null;
  }
  return tag === null ? repo : `${repo}:${tag}`;
}

// What a job did, named by its kind. Never empty: a missing detail drops to the plain phrase.
export function jobSubject(job: Job): string {
  const image = imageName(job);
  switch (job.kind) {
    case "db_update": {
      const scanner = scannerLabel(job.scanner);
      return scanner === null ? t("jobs.subject.dbUpdate") : t("jobs.subject.dbUpdateScanner", { scanner });
    }
    case "pull": {
      if (image !== null) {
        return t("jobs.subject.pulled", { image });
      }
      const digest = job.image.digest;
      return digest === null ? t("jobs.subject.pulledPlain") : t("jobs.subject.pulled", { image: shortDigest(digest) });
    }
    case "scan":
      return image === null ? t("jobs.subject.scannedPlain") : t("jobs.subject.scanned", { image });
    case "discover": {
      const repo = job.image.repo_full_name;
      return repo === null ? t("jobs.subject.discoveryPlain") : t("jobs.subject.discovery", { repo });
    }
    case "publish":
      return image === null ? t("jobs.subject.publishedPlain") : t("jobs.subject.published", { image });
    case "cleanup":
      return t("jobs.subject.cleanup");
    case "retention":
      return t("jobs.subject.retention");
    default:
      return t("jobs.subject.unknown");
  }
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

// The name of the scanner a db_update job or run refreshes. An unknown scanner shows as its raw
// value. Null when the job or run has none.
export function scannerLabel(scanner: string | null | undefined): string | null {
  if (scanner === null || scanner === undefined) {
    return null;
  }
  if (scanner === "trivy") {
    return t("jobs.scanner.trivy");
  }
  return scanner === "grype" ? t("jobs.scanner.grype") : scanner;
}
