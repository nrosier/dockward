import { describe, expect, it } from "vitest";
import { t } from "../../i18n";
import type { Job } from "../../types/api";
import { jobSubject, triggerLabel } from "./labels";

function job(over: Partial<Job>): Job {
  return {
    id: "j1",
    mapping_id: "m1",
    status: "done",
    attempts: 1,
    next_attempt_at: null,
    last_error: null,
    created_at: null,
    updated_at: null,
    trigger: null,
    image: { repo_full_name: null, tag: null, digest: null },
    report: null,
    ...over,
  };
}

const KINDS = ["discover", "pull", "scan", "publish", "db_update", "cleanup", "retention"];

describe("jobSubject", () => {
  it("subject_is_never_empty_for_any_job_kind", () => {
    for (const kind of [...KINDS, null, "unknown"]) {
      expect(jobSubject(job({ kind })).trim()).not.toBe("");
    }
  });

  it("subject_names_the_work_for_each_kind", () => {
    const image = { repo_full_name: "ghcr.io/team/app", tag: "1.2", digest: "sha256:9f2c41e0aabbccdd" };
    expect(jobSubject(job({ kind: "db_update", scanner: "trivy" }))).toBe("Vulnerability DB update (Trivy)");
    expect(jobSubject(job({ kind: "db_update", scanner: "grype" }))).toBe("Vulnerability DB update (Grype)");
    expect(jobSubject(job({ kind: "db_update" }))).toBe("Vulnerability DB update");
    expect(jobSubject(job({ kind: "pull", image }))).toBe("New image pulled: ghcr.io/team/app:1.2");
    expect(
      jobSubject(job({ kind: "pull", image: { repo_full_name: null, tag: null, digest: image.digest } })),
    ).toBe("New image pulled: sha256:9f2c41e0");
    expect(jobSubject(job({ kind: "scan", image }))).toBe("Vulnerability scan: ghcr.io/team/app:1.2");
    expect(jobSubject(job({ kind: "scan" }))).toBe("Vulnerability scan");
    expect(jobSubject(job({ kind: "discover", image: { ...image, tag: null } }))).toBe("Discovery: ghcr.io/team/app");
    expect(jobSubject(job({ kind: "discover" }))).toBe("Discovery");
    expect(jobSubject(job({ kind: "publish", image }))).toBe("Publish to GitHub: ghcr.io/team/app:1.2");
    expect(jobSubject(job({ kind: "publish" }))).toBe("Publish to GitHub");
    expect(jobSubject(job({ kind: "cleanup" }))).toBe("Housekeeping: cleanup");
    expect(jobSubject(job({ kind: "retention" }))).toBe("Housekeeping: retention");
  });
});

describe("triggerLabel", () => {
  it("trigger_label_is_never_none_or_blank", () => {
    expect(triggerLabel(null)).toBe("Scheduled");
    expect(triggerLabel("")).toBe("Scheduled");
    expect(triggerLabel("first_pull")).toBe("On new image");
    expect(triggerLabel("tag_moved")).toBe("On new tag");
    expect(triggerLabel("manual")).toBe("Manual");
    expect(triggerLabel("db_update")).toBe("Scheduled DB update");
    expect(triggerLabel("scheduled")).toBe("Scheduled");
    expect(triggerLabel("something_else")).toBe("something_else");
    expect(t("jobs.trigger.scheduled")).toBe("Scheduled");
  });
});
