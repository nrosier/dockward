import { screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { t } from "../i18n";
import { json, renderAt, stubApi } from "../test/render";
import AdminJobsPage from "./AdminJobsPage";

const run = {
  id: "r1",
  job_kind: "db_update",
  started_at: "2026-11-11T10:00:00Z",
  finished_at: "2026-11-11T10:00:10Z",
  status: "done",
  processed_count: 1,
  error_summary: null,
  scanner: "trivy",
  job_id: "j1",
};

describe("AdminJobsPage", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("shows View log only on a run with a job_id", async () => {
    stubApi((path) =>
      path.startsWith("/api/v1/admin/jobs")
        ? json({ items: [run, { ...run, id: "r2", job_kind: "cleanup", job_id: null }], page: 1, page_size: 50, total: 2 })
        : undefined,
    );
    renderAt(<AdminJobsPage />);
    expect(await screen.findAllByRole("button", { name: t("admin.jobs.viewLog") })).toHaveLength(1);
  });

  it("db_update row shows the scanner", async () => {
    stubApi((path) =>
      path.startsWith("/api/v1/admin/jobs")
        ? json({ items: [run, { ...run, id: "r3", scanner: "grype" }, { ...run, id: "r4", job_kind: "cleanup", scanner: null }], page: 1, page_size: 50, total: 3 })
        : undefined,
    );
    renderAt(<AdminJobsPage />);
    expect(await screen.findByText(t("jobs.scanner.trivy"))).toBeInTheDocument();
    expect(screen.getByText(t("jobs.scanner.grype"))).toBeInTheDocument();
  });

  it("filters offer the backend's kinds, not poll", async () => {
    stubApi(() => json({ items: [], page: 1, page_size: 50, total: 0 }));
    renderAt(<AdminJobsPage />);
    await screen.findByRole("button", { name: t("admin.jobs.cleanup") });
    expect(screen.queryByText("Poll")).toBeNull();
    expect(screen.getByRole("button", { name: t("admin.jobs.dbUpdate") })).toBeInTheDocument();
  });
});
