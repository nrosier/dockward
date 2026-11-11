import { screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { t } from "../i18n";
import { json, renderAt, stubApi, user } from "../test/render";
import type { DashboardSummary, Job } from "../types/api";
import DashboardPage from "./DashboardPage";

function job(over: Partial<Job>): Job {
  return {
    id: "j1",
    mapping_id: "m1",
    status: "done",
    attempts: 1,
    next_attempt_at: null,
    last_error: null,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
    trigger: "webhook",
    image: { repo_full_name: "platform/api-gateway", tag: "1.42.0", digest: "sha256:9f2c41e0aabbccdd" },
    report: null,
    ...over,
  };
}

const summary: DashboardSummary = {
  open_cves: { critical: 3, high: 12, medium: 5, low: 6, unknown: 7, total: 33 },
  fixed_cves: 41,
  accepted_cves: 2,
  open_issues: 15,
  failed_syncs: 2,
  recent_syncs: [
    job({ id: "j1" }),
    job({ id: "j2", status: "failed", last_error: "GitHub rejected the SARIF upload (403)." }),
  ],
};

function stub(onRetry?: () => void) {
  return stubApi((path, init) => {
    if (path === "/api/v1/account/me") return json({ user: user("user") });
    if (path.startsWith("/api/v1/dashboard/summary")) return json(summary);
    if (path.startsWith("/api/v1/mappings")) {
      return json({ items: [], page: 1, page_size: 200, total: 0 });
    }
    if (path === "/api/v1/jobs/j2/retry" && init?.method === "POST") {
      onRetry?.();
      return json(job({ id: "j2", status: "queued" }));
    }
    return undefined;
  });
}

describe("DashboardPage", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("shows the five counts from the summary", async () => {
    stub();
    renderAt(<DashboardPage />);
    const critical = await screen.findByRole("link", { name: new RegExp(t("pill.critical")) });
    expect(within(critical).getByText("3")).toBeInTheDocument();
    expect(within(screen.getByRole("link", { name: new RegExp(t("pill.high")) })).getByText("12")).toBeInTheDocument();
    expect(within(screen.getByRole("link", { name: new RegExp(t("pill.medium")) })).getByText("5")).toBeInTheDocument();
    expect(within(screen.getByRole("link", { name: new RegExp(t("pill.low")) })).getByText("6")).toBeInTheDocument();
    expect(within(screen.getByRole("link", { name: new RegExp(t("pill.unknown")) })).getByText("7")).toBeInTheDocument();
    expect(within(screen.getByRole("link", { name: new RegExp(t("dashboard.openCvesTotal")) })).getByText("33")).toBeInTheDocument();
    expect(within(screen.getByRole("link", { name: new RegExp(t("pill.fixed")) })).getByText("41")).toBeInTheDocument();
    const accepted = screen.getByText(t("dashboard.acceptedCves")).parentElement as HTMLElement;
    expect(accepted).toHaveTextContent("2");
    // The Accepted and Issues cards open the CVE list with their filters (#257).
    expect(accepted.closest("a")).toHaveAttribute("href", "/cves?accepted=true");
    expect(screen.getByText(t("dashboard.openIssues")).closest("a")).toHaveAttribute("href", "/cves?has_issue=true");
    const fixedEl = screen.getByRole("link", { name: new RegExp(t("pill.fixed")) });
    const issuesEl = screen.getByText(t("dashboard.openIssues"));
    const follows = (a: Node, b: Node) => Boolean(a.compareDocumentPosition(b) & Node.DOCUMENT_POSITION_FOLLOWING);
    expect(follows(fixedEl, accepted)).toBe(true);
    expect(follows(accepted, issuesEl)).toBe(true);
    expect(screen.getByText(t("dashboard.openIssues")).parentElement).toHaveTextContent("15");
    expect(within(screen.getByRole("link", { name: new RegExp(t("dashboard.failedSyncs")) })).getByText("2")).toBeInTheDocument();
    expect(screen.getByText(summary.recent_syncs[1].last_error ?? "")).toBeInTheDocument();
  });

  it("retry posts to the job and refreshes the summary", async () => {
    const retried = vi.fn();
    const fetchMock = stub(retried);
    renderAt(<DashboardPage />);
    await userEvent.click(await screen.findByRole("button", { name: t("jobs.retry") }));
    await vi.waitFor(() => expect(retried).toHaveBeenCalledTimes(1));
    const summaryCalls = () => fetchMock.mock.calls.filter(([path]) => String(path).startsWith("/api/v1/dashboard/summary"));
    await vi.waitFor(() => expect(summaryCalls().length).toBeGreaterThanOrEqual(2));
  });
});
