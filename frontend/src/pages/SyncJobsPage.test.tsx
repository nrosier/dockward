import { screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { formatDateTime } from "../components/syncjobs/dates";
import { t } from "../i18n";
import { json, renderAt, stubApi, user } from "../test/render";
import type { SyncJob } from "../types/api";
import SyncJobsPage from "./SyncJobsPage";

const failed: SyncJob = {
  id: "j9",
  mapping_id: "m1",
  status: "failed",
  attempts: 5,
  next_attempt_at: null,
  last_error: "GitHub rejected the SARIF upload (403).",
  created_at: "2026-10-01T14:46:00Z",
  updated_at: "2026-10-01T14:47:00Z",
  trigger: "poll",
  image: { repo_full_name: "platform/billing-worker", tag: "3.8.1", digest: "sha256:51ab07d3ffff" },
  report: null,
};

const retrying: SyncJob = {
  id: "j7",
  mapping_id: "m1",
  status: "queued",
  attempts: 6,
  next_attempt_at: "2026-11-05T12:30:00Z",
  last_error: "Harbor returned 503 while fetching the report.",
  created_at: "2026-11-05T11:00:00Z",
  updated_at: "2026-11-05T12:00:00Z",
  trigger: "webhook",
  image: { repo_full_name: "platform/walley", tag: "2.4.0", digest: "sha256:0c9e1f" },
  report: null,
};

const neverRun: SyncJob = {
  ...retrying,
  id: "j8",
  attempts: 0,
  next_attempt_at: null,
  // Stale text on a job that has not run. The page must not show it.
  last_error: "An error from an earlier run.",
  image: { repo_full_name: "platform/billing-worker", tag: "3.9.0", digest: "sha256:ff00aa" },
};

function stub(items: SyncJob[] = [failed]) {
  return stubApi((path) => {
    if (path === "/api/v1/account/me") return json({ user: user("user") });
    if (path.startsWith("/api/v1/sync-jobs")) return json({ items, page: 1, page_size: 50, total: items.length });
    if (path.startsWith("/api/v1/mappings")) return json({ items: [], page: 1, page_size: 200, total: 0 });
    return undefined;
  });
}

describe("SyncJobsPage", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("shows the trigger and the error row for a failed job", async () => {
    stub();
    renderAt(<SyncJobsPage />);
    expect(await screen.findByText(t("syncJobs.trigger.poll"))).toBeInTheDocument();
    expect(screen.getByText("GitHub rejected the SARIF upload (403).")).toBeInTheDocument();
    expect(screen.getByText(t("syncJobs.attempts", { attempts: 5, max: 8 }))).toBeInTheDocument();
  });

  it("a scheduled scan shows its trigger and only the new vulnerabilities (#191)", async () => {
    const report = {
      image_tag: "3.8.1",
      image_digest: "sha256:51ab07d3ffff",
      commit_sha: null,
      vulnerability_summary: {},
      sarif_status: "success" as const,
      synced_at: "2026-11-05T12:00:00Z",
    };
    stub([
      { ...failed, id: "s1", status: "done", last_error: null, trigger: "schedule", report: { ...report, new_cve_ids: ["CVE-2026-0003", "CVE-2026-0004"] } },
      { ...failed, id: "s2", status: "done", last_error: null, trigger: "schedule", report: { ...report, new_cve_ids: [] } },
      { ...failed, id: "s3", status: "done", last_error: null, trigger: "webhook", report: { ...report, new_cve_ids: null } },
    ]);
    renderAt(<SyncJobsPage />);
    const table = await screen.findByRole("table");
    expect(await within(table).findAllByText(t("syncJobs.trigger.schedule"))).toHaveLength(2);
    expect(within(table).getByText(t("syncJobs.newVulns", { ids: "CVE-2026-0003, CVE-2026-0004" }))).toBeInTheDocument();
    expect(within(table).getAllByText(t("syncJobs.noNewVulns"))).toHaveLength(1);
  });

  it("a failed job still shows its error", async () => {
    stub([failed]);
    renderAt(<SyncJobsPage />);
    expect(await screen.findByText(t("syncJobs.trigger.poll"))).toBeInTheDocument();
    expect(screen.getByText("GitHub rejected the SARIF upload (403).")).toBeInTheDocument();
    expect(within(screen.getByRole("table")).getByText(t("pill.failed"))).toBeInTheDocument();
  });

  it("a queued job with attempts 6 shows its retry state and its error", async () => {
    stub([retrying]);
    renderAt(<SyncJobsPage />);
    expect(await screen.findByText(t("syncJobs.trigger.webhook"))).toBeInTheDocument();
    const table = screen.getByRole("table");
    expect(within(table).getByText(t("syncJobs.retrying", { attempts: 6, max: 8 }))).toBeInTheDocument();
    expect(within(table).queryByText(t("pill.queued"))).not.toBeInTheDocument();
    expect(within(table).getByText("Harbor returned 503 while fetching the report.")).toBeInTheDocument();
    expect(within(table).getByText(t("syncJobs.nextAttempt", { time: formatDateTime(retrying.next_attempt_at) }))).toBeInTheDocument();
  });

  it("a long retry error is capped at 300 characters", async () => {
    // 400 code points. The emoji sits at code point 300, so the cut falls right after it.
    const kept = `${"a".repeat(299)}😀`;
    const full = `${kept}${"b".repeat(100)}`;
    expect(Array.from(kept)).toHaveLength(300);
    expect(Array.from(full)).toHaveLength(400);
    stub([{ ...retrying, next_attempt_at: null, last_error: full }]);
    renderAt(<SyncJobsPage />);
    expect(await screen.findByText(t("syncJobs.trigger.webhook"))).toBeInTheDocument();
    const table = screen.getByRole("table");
    expect(within(table).getByText(`${kept}…`)).toBeInTheDocument();
    expect(within(table).queryByText(full)).not.toBeInTheDocument();
  });

  it("a queued job with attempts 0 shows Queued and no error", async () => {
    stub([neverRun]);
    renderAt(<SyncJobsPage />);
    expect(await screen.findByText(t("syncJobs.trigger.webhook"))).toBeInTheDocument();
    const table = screen.getByRole("table");
    expect(within(table).getByText(t("pill.queued"))).toBeInTheDocument();
    expect(within(table).queryByText(t("syncJobs.retrying", { attempts: 0, max: 8 }))).not.toBeInTheDocument();
    expect(within(table).queryByText("An error from an earlier run.")).not.toBeInTheDocument();
  });

  it("status filter is kept in the URL", async () => {
    const fetchMock = stub();
    const { router } = renderAt(<SyncJobsPage />);
    await screen.findByText(t("syncJobs.trigger.poll"));
    await userEvent.click(screen.getByRole("button", { name: t("pill.failed") }));
    expect(router.state.location.search).toContain("status=failed");
    await vi.waitFor(() =>
      expect(fetchMock.mock.calls.some(([path]) => String(path).includes("/sync-jobs?") && String(path).includes("status=failed"))).toBe(true),
    );
    expect(screen.getByRole("button", { name: t("pill.failed") })).toHaveAttribute("aria-pressed", "true");
  });
});
