import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
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

function stub() {
  return stubApi((path) => {
    if (path === "/api/v1/account/me") return json({ user: user("user") });
    if (path.startsWith("/api/v1/sync-jobs")) return json({ items: [failed], page: 1, page_size: 50, total: 1 });
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
