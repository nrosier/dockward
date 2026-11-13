import { screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { formatDateTime } from "../components/jobs/dates";
import { t } from "../i18n";
import { json, renderAt, stubApi, user } from "../test/render";
import type { Job } from "../types/api";
import JobsPage from "./JobsPage";

const failed: Job = {
  id: "j9",
  mapping_id: "m1",
  status: "failed",
  attempts: 5,
  next_attempt_at: null,
  last_error: "GitHub rejected the SARIF upload (403).",
  created_at: "2026-10-01T14:46:00Z",
  updated_at: "2026-10-01T14:47:00Z",
  trigger: "discovery",
  image: { repo_full_name: "platform/billing-worker", tag: "3.8.1", digest: "sha256:51ab07d3ffff" },
  report: null,
};

const retrying: Job = {
  id: "j7",
  mapping_id: "m1",
  status: "queued",
  attempts: 6,
  next_attempt_at: "2026-11-05T12:30:00Z",
  last_error: "Harbor returned 503 while fetching the report.",
  created_at: "2026-11-05T11:00:00Z",
  updated_at: "2026-11-05T12:00:00Z",
  trigger: "first_pull",
  image: { repo_full_name: "platform/walley", tag: "2.4.0", digest: "sha256:0c9e1f" },
  report: null,
};

const neverRun: Job = {
  ...retrying,
  id: "j8",
  attempts: 0,
  next_attempt_at: null,
  // Stale text on a job that has not run. The page must not show it.
  last_error: "An error from an earlier run.",
  image: { repo_full_name: "platform/billing-worker", tag: "3.9.0", digest: "sha256:ff00aa" },
};

function stub(items: Job[] = [failed]) {
  return stubApi((path) => {
    if (path === "/api/v1/account/me") return json({ user: user("user") });
    if (path.startsWith("/api/v1/jobs")) return json({ items, page: 1, page_size: 50, total: items.length });
    if (path.startsWith("/api/v1/mappings")) return json({ items: [], page: 1, page_size: 200, total: 0 });
    return undefined;
  });
}

describe("JobsPage", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("db_update row shows the scanner", async () => {
    stub([
      { ...failed, id: "d1", trigger: "db_update", scanner: "grype", source_id: null, image: { repo_full_name: null, tag: null, digest: null } },
    ]);
    renderAt(<JobsPage />);
    expect(await screen.findByText(t("jobs.scanner.refreshes", { scanner: t("jobs.scanner.grype") }))).toBeInTheDocument();
  });

  it("shows the trigger and the error row for a failed job", async () => {
    stub();
    renderAt(<JobsPage />);
    expect(await screen.findByText(t("jobs.trigger.discovery"))).toBeInTheDocument();
    expect(screen.getByText("GitHub rejected the SARIF upload (403).")).toBeInTheDocument();
    expect(screen.getByText(t("jobs.attempts", { attempts: 5, max: 8 }))).toBeInTheDocument();
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
      { ...failed, id: "s1", status: "done", last_error: null, trigger: "db_update", report: { ...report, new_cve_ids: ["CVE-2026-0003", "CVE-2026-0004"] } },
      { ...failed, id: "s2", status: "done", last_error: null, trigger: "db_update", report: { ...report, new_cve_ids: [] } },
      { ...failed, id: "s3", status: "done", last_error: null, trigger: "tag_moved", report: { ...report, new_cve_ids: null } },
    ]);
    renderAt(<JobsPage />);
    const table = await screen.findByRole("table");
    expect(await within(table).findAllByText(t("jobs.trigger.scheduledDbUpdate"))).toHaveLength(2);
    expect(within(table).getByText(t("jobs.newVulns", { ids: "CVE-2026-0003, CVE-2026-0004" }))).toBeInTheDocument();
    expect(within(table).getAllByText(t("jobs.noNewVulns"))).toHaveLength(1);
  });

  it("shows the source's display name as the job subject, or its repository when unnamed (#323)", async () => {
    stubApi((path) => {
      if (path === "/api/v1/account/me") return json({ user: user("user") });
      if (path.startsWith("/api/v1/jobs")) return json({ items: [{ ...failed, source_id: "s1" }], page: 1, page_size: 50, total: 1 });
      if (path === "/api/v1/image-sources?page_size=200") {
        return json({
          items: [{ id: "s1", repository: "platform/billing-worker", name: "Billing" }],
          page: 1,
          page_size: 200,
          total: 1,
        });
      }
      return undefined;
    });
    renderAt(<JobsPage />, "/jobs");
    // The subject is the display name, shown in the job's row.
    const row = (await screen.findByText("platform/billing-worker")).closest("tr") as HTMLElement;
    expect(within(row).getByText("Billing")).toBeInTheDocument();
  });

  it("a failed job of a source the user owns shows Retry, from the source lookup (#323 follow-up)", async () => {
    const requested: string[] = [];
    stubApi((path) => {
      requested.push(path);
      if (path === "/api/v1/account/me") return json({ user: user("user") });
      if (path.startsWith("/api/v1/jobs")) return json({ items: [{ ...failed, source_id: "s1" }], page: 1, page_size: 50, total: 1 });
      if (path.startsWith("/api/v1/image-sources?")) {
        return json({ items: [{ id: "s1", user_id: "u1", repository: "platform/billing-worker", name: "Billing" }], page: 1, page_size: 200, total: 1 });
      }
      // The mapping lookup is not the owner check any more: no mapping is returned.
      if (path.startsWith("/api/v1/mappings")) return json({ items: [], page: 1, page_size: 200, total: 0 });
      return undefined;
    });
    renderAt(<JobsPage />, "/jobs");
    const table = await screen.findByRole("table");
    expect(within(table).getByRole("button", { name: t("jobs.retry") })).toBeInTheDocument();
    expect(requested.some((path) => path.startsWith("/api/v1/mappings"))).toBe(false);
  });

  it("the mapping filter sends source_id, the key the jobs route reads (#323 follow-up)", async () => {
    const requested: string[] = [];
    stubApi((path) => {
      requested.push(path);
      if (path === "/api/v1/account/me") return json({ user: user("user") });
      if (path.startsWith("/api/v1/jobs")) return json({ items: [], page: 1, page_size: 50, total: 0 });
      if (path.startsWith("/api/v1/image-sources?")) return json({ items: [], page: 1, page_size: 200, total: 0 });
      return undefined;
    });
    renderAt(<JobsPage />, "/jobs?source_id=s9");
    await screen.findByText(t("jobs.empty"));
    const jobsCalls = requested.filter((path) => path.startsWith("/api/v1/jobs?"));
    expect(jobsCalls.length).toBeGreaterThan(0);
    for (const call of jobsCalls) {
      const query = new URL(call, "http://x").searchParams;
      expect(query.get("source_id")).toBe("s9");
      expect(query.has("mapping_id")).toBe(false);
    }
  });

  it("shows a View log button on every row", async () => {
    stub([failed, neverRun]);
    renderAt(<JobsPage />);
    expect(await screen.findAllByRole("button", { name: t("jobs.log.open") })).toHaveLength(2);
  });

  it("View log opens the log dialog", async () => {
    const fetchMock = stubApi((path) => {
      if (path === "/api/v1/account/me") return json({ user: user("user") });
      if (path.startsWith("/api/v1/jobs/j9/log")) {
        return json({ job_id: "j9", kind: "scan", scanner: "trivy", status: "done", attempt: 1, steps: [], lines: [], next_after: null });
      }
      if (path.startsWith("/api/v1/jobs")) return json({ items: [failed], page: 1, page_size: 50, total: 1 });
      if (path.startsWith("/api/v1/mappings")) return json({ items: [], page: 1, page_size: 200, total: 0 });
      return undefined;
    });
    renderAt(<JobsPage />);
    await userEvent.click(await screen.findByRole("button", { name: t("jobs.log.open") }));
    expect(await screen.findByRole("dialog", { name: t("jobs.log.title") })).toBeInTheDocument();
    expect(fetchMock.mock.calls.some((call) => String(call[0]).startsWith("/api/v1/jobs/j9/log"))).toBe(true);
  });

  it("a failed job still shows its error", async () => {
    stub([failed]);
    renderAt(<JobsPage />);
    expect(await screen.findByText(t("jobs.trigger.discovery"))).toBeInTheDocument();
    expect(screen.getByText("GitHub rejected the SARIF upload (403).")).toBeInTheDocument();
    expect(within(screen.getByRole("table")).getByText(t("pill.failed"))).toBeInTheDocument();
  });

  it("a queued job with attempts 6 shows its retry state and its error", async () => {
    stub([retrying]);
    renderAt(<JobsPage />);
    expect(await screen.findByText(t("jobs.trigger.onPull"))).toBeInTheDocument();
    const table = screen.getByRole("table");
    expect(within(table).getByText(t("jobs.retrying", { attempts: 6, max: 8 }))).toBeInTheDocument();
    expect(within(table).queryByText(t("pill.queued"))).not.toBeInTheDocument();
    expect(within(table).getByText("Harbor returned 503 while fetching the report.")).toBeInTheDocument();
    expect(within(table).getByText(t("jobs.nextAttempt", { time: formatDateTime(retrying.next_attempt_at) }))).toBeInTheDocument();
  });

  it("a long retry error is capped at 300 characters", async () => {
    // 400 code points. The emoji sits at code point 300, so the cut falls right after it.
    const kept = `${"a".repeat(299)}😀`;
    const full = `${kept}${"b".repeat(100)}`;
    expect(Array.from(kept)).toHaveLength(300);
    expect(Array.from(full)).toHaveLength(400);
    stub([{ ...retrying, next_attempt_at: null, last_error: full }]);
    renderAt(<JobsPage />);
    expect(await screen.findByText(t("jobs.trigger.onPull"))).toBeInTheDocument();
    const table = screen.getByRole("table");
    expect(within(table).getByText(`${kept}…`)).toBeInTheDocument();
    expect(within(table).queryByText(full)).not.toBeInTheDocument();
  });

  it("a queued job with attempts 0 shows Queued and no error", async () => {
    stub([neverRun]);
    renderAt(<JobsPage />);
    expect(await screen.findByText(t("jobs.trigger.onPull"))).toBeInTheDocument();
    const table = screen.getByRole("table");
    expect(within(table).getByText(t("pill.queued"))).toBeInTheDocument();
    expect(within(table).queryByText(t("jobs.retrying", { attempts: 0, max: 8 }))).not.toBeInTheDocument();
    expect(within(table).queryByText("An error from an earlier run.")).not.toBeInTheDocument();
  });

  it("status filter is kept in the URL", async () => {
    const fetchMock = stub();
    const { router } = renderAt(<JobsPage />);
    await screen.findByText(t("jobs.trigger.discovery"));
    await userEvent.click(screen.getByRole("button", { name: t("pill.failed") }));
    expect(router.state.location.search).toContain("status=failed");
    await vi.waitFor(() =>
      expect(fetchMock.mock.calls.some(([path]) => String(path).includes("/jobs?") && String(path).includes("status=failed"))).toBe(true),
    );
    expect(screen.getByRole("button", { name: t("pill.failed") })).toHaveAttribute("aria-pressed", "true");
  });
});
