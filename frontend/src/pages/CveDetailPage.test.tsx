import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { t } from "../i18n";
import { json, renderWithRoutes, stubApi, user } from "../test/render";
import type { CveDetail, Mapping } from "../types/api";
import CveDetailPage from "./CveDetailPage";

const mapping: Mapping = {
  id: "m1",
  user_id: "u1",
  harbor_cred_id: "c1",
  github_cred_id: "c2",
  harbor_base_url: "https://harbor.example.org",
  harbor_project: "platform",
  harbor_repository: "api-gateway",
  github_owner: "example-org",
  github_repo: "api-gateway",
  default_branch: "main",
  auto_create_issues: true,
  min_issue_severity: "HIGH",
  created_at: null,
  scan_schedule: "off",
  scan_time: "00:00",
  scan_weekday: 1,
};

function cve(over: Partial<CveDetail>): CveDetail {
  return {
    id: "m1:CVE-2026-0001",
    mapping_id: "m1",
    cve_id: "CVE-2026-0001",
    severity: "CRITICAL",
    open_severity: "CRITICAL",
    status: "open",
    package: "golang.org/x/crypto",
    first_seen_at: "2026-10-14T10:00:00Z",
    last_seen_at: null,
    github_issue_url: null,
    accepted: false,
    fixed_in_version: "v0.31.0",
    open_tags: 4,
    tracked_tags: 10,
    github_issue_number: null,
    github_issue_status: null,
    tags: [{ image_tag: "1.42.0", status: "open", last_scan_at: "2026-11-03T14:58:00Z", fixed_in_version: "v0.31.0", newest_digest: true }],
    acceptance: null,
    description: "Misuse may cause an authorization bypass.",
    older_tags_only: false,
    ...over,
  };
}

function stub(detail: CveDetail, onAccept?: (body: unknown) => void) {
  return stubApi((path, init) => {
    if (path === "/api/v1/account/me") return json({ user: user("user") });
    if (path === "/api/v1/cves/m1%3ACVE-2026-0001" && init?.method === "GET") return json(detail);
    if (path === "/api/v1/mappings/m1") return json(mapping);
    if (path === "/api/v1/cves/m1%3ACVE-2026-0001/accept" && init?.method === "POST") {
      onAccept?.(JSON.parse(String(init.body)));
      return json({ acceptance: {} }, 201);
    }
    return undefined;
  });
}

const routes = [{ path: "/cves/:id", element: <CveDetailPage /> }];
const url = "/cves/m1%3ACVE-2026-0001";

describe("CveDetailPage", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("shows the older-tags line and marks older tags when only older tags are open", async () => {
    stub(
      cve({
        status: "fixed",
        open_tags: 0,
        older_tags_only: true,
        tags: [
          { image_tag: "0.4", status: "open", last_scan_at: null, fixed_in_version: null, newest_digest: false },
          { image_tag: "0.4.2", status: "open", last_scan_at: null, fixed_in_version: null, newest_digest: false },
          { image_tag: "latest", status: "fixed", last_scan_at: null, fixed_in_version: null, newest_digest: true },
        ],
      }),
    );
    renderWithRoutes(routes, url);
    expect(await screen.findByText(t("cves.detail.olderTagsOnly", { tags: "0.4, 0.4.2" }))).toBeInTheDocument();
    expect(screen.getAllByText(t("cves.detail.olderTag"))).toHaveLength(2);
  });

  it("shows no older-tags line when the newest digest reports the CVE", async () => {
    stub(cve({}));
    renderWithRoutes(routes, url);
    await screen.findByText("1.42.0");
    expect(screen.queryByText(/Open on older tags only/)).toBeNull();
    expect(screen.queryByText(t("cves.detail.olderTag"))).toBeNull();
  });

  it("hides Create issue when the CVE is fixed on every tag", async () => {
    stub(cve({ severity: "CRITICAL", open_severity: null, status: "fixed" }));
    renderWithRoutes(routes, url);
    await screen.findByRole("heading", { name: "CVE-2026-0001" });
    await screen.findByRole("button", { name: t("cves.detail.accept") });
    expect(screen.queryByRole("button", { name: t("cves.detail.createIssue") })).not.toBeInTheDocument();
  });

  it("shows Create issue for MEDIUM", async () => {
    stub(cve({ severity: "MEDIUM", open_severity: "MEDIUM" }));
    renderWithRoutes(routes, url);
    expect(await screen.findByRole("button", { name: t("cves.detail.createIssue") })).toBeEnabled();
  });

  it("disables Create issue while an open issue exists", async () => {
    stub(cve({ github_issue_url: "https://github.com/example-org/api-gateway/issues/214", github_issue_number: 214, github_issue_status: "open" }));
    renderWithRoutes(routes, url);
    const button = await screen.findByRole("button", { name: t("cves.detail.createIssue") });
    expect(button).toBeDisabled();
    expect(button).toHaveAttribute("title", t("cves.detail.createIssueDisabled"));
    expect(screen.getByRole("link", { name: new RegExp("#214") })).toHaveAttribute(
      "href",
      "https://github.com/example-org/api-gateway/issues/214",
    );
  });

  it("accept sends the reason and the end of the expiry day in UTC", async () => {
    const accepted = vi.fn();
    stub(cve({}), accepted);
    renderWithRoutes(routes, url);
    await userEvent.click(await screen.findByRole("button", { name: t("cves.detail.accept") }));
    await userEvent.type(await screen.findByLabelText(t("cves.accept.reason")), "Not reachable in this service");
    await userEvent.type(screen.getByLabelText(t("cves.accept.expires")), "2027-01-31");
    await userEvent.click(screen.getByRole("button", { name: t("cves.accept.submit") }));
    await vi.waitFor(() => expect(accepted).toHaveBeenCalledTimes(1));
    expect(accepted).toHaveBeenCalledWith({ reason: "Not reachable in this service", expires_at: "2027-01-31T23:59:59Z" });
  });
});
