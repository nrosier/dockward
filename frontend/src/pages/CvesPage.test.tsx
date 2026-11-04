import { screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { t } from "../i18n";
import { json, renderAt, stubApi, user } from "../test/render";
import type { CveSummary } from "../types/api";
import CvesPage from "./CvesPage";

const medium: CveSummary = {
  id: "m1:CVE-2026-0002",
  mapping_id: "m1",
  cve_id: "CVE-2026-0002",
  severity: "MEDIUM",
  status: "open",
  package: "libfoo",
  first_seen_at: null,
  last_seen_at: null,
  github_issue_url: null,
  accepted: false,
  fixed_in_version: null,
  open_tags: 2,
  tracked_tags: 10,
  github_issue_number: null,
  github_issue_status: null,
};

function stub() {
  return stubApi((path) => {
    if (path === "/api/v1/account/me") return json({ user: user("user") });
    if (path.startsWith("/api/v1/cves")) return json({ items: [medium], page: 1, page_size: 50, total: 1 });
    if (path.startsWith("/api/v1/mappings")) return json({ items: [], page: 1, page_size: 200, total: 0 });
    return undefined;
  });
}

describe("CvesPage", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("maps the Open status filter to status=open and accepted=false", async () => {
    const fetchMock = stub();
    renderAt(<CvesPage />, "/cves?status=fixed");
    await screen.findByText("CVE-2026-0002");
    await userEvent.selectOptions(screen.getByLabelText(t("cves.filter.status")), "open");
    await vi.waitFor(() => {
      const hit = fetchMock.mock.calls
        .map(([path]) => String(path))
        .find((path) => path.startsWith("/api/v1/cves?") && path.includes("status=open"));
      expect(hit).toBeDefined();
      const query = new URLSearchParams((hit ?? "").split("?")[1]);
      expect(query.get("status")).toBe("open");
      expect(query.get("accepted")).toBe("false");
    });
  });

  it("shows Not eligible for a MEDIUM CVE without an issue", async () => {
    stub();
    renderAt(<CvesPage />);
    const row = (await screen.findByText("CVE-2026-0002")).closest("tr") as HTMLElement;
    expect(within(row).getByText(t("cves.issue.notEligible"))).toBeInTheDocument();
    expect(within(row).getByText(t("cves.tags", { open: 2, tracked: 10 }))).toBeInTheDocument();
  });
});
