import { screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { t } from "../i18n";
import { json, renderWithRoutes, stubApi, user } from "../test/render";
import type { CveDetail } from "../types/api";
import type { Source } from "../types/sources";
import CveDetailPage from "./CveDetailPage";

const source: Source = {
  id: "s1",
  user_id: "u1",
  hub_id: "h1",
  repository: "ghcr.io/team/app",
  name: null,
  tag_value: "latest",
  github_cred_id: "c2",
  github_owner: "example-org",
  github_repo: "api-gateway",
  default_branch: "main",
  auto_create_issues: true,
  min_issue_severity: "HIGH",
  has_credential: true,
  last_discovery_at: null,
};

function cve(over: Partial<CveDetail>): CveDetail {
  return {
    id: "m1:CVE-2026-0001",
    source_id: "s1",
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

function stub(detail: CveDetail, onAccept?: (body: unknown) => void, onIssue?: (path: string) => void, sourceOverride: Source = source) {
  return stubApi((path, init) => {
    if (path === "/api/v1/account/me") return json({ user: user("user") });
    if (path === "/api/v1/cves/m1%3ACVE-2026-0001" && init?.method === "GET") return json(detail);
    if (path === "/api/v1/cves/m1%3ACVE-2026-0001/issue" && init?.method === "POST") {
      onIssue?.(path);
      return json({ github_issue_url: "https://github.com/example-org/api-gateway/issues/9", github_issue_number: 9 }, 201);
    }
    if (path === "/api/v1/image-sources/s1") return json(sourceOverride);
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

  it("shows View issue linking to the GitHub issue when the issue number is set", async () => {
    stub(
      cve({
        github_issue_url: "https://github.com/example-org/api-gateway/issues/214",
        github_issue_number: 214,
        github_issue_status: "open",
      }),
    );
    renderWithRoutes(routes, url);
    const link = await screen.findByRole("link", { name: t("cves.action.viewIssue") });
    expect(link).toHaveAttribute("href", "https://github.com/example-org/api-gateway/issues/214");
    expect(screen.queryByRole("button", { name: t("cves.detail.createIssue") })).not.toBeInTheDocument();
  });

  it("shows Create issue and no View issue when the issue number is not set", async () => {
    stub(cve({ severity: "HIGH", open_severity: "HIGH" }));
    renderWithRoutes(routes, url);
    expect(await screen.findByRole("button", { name: t("cves.detail.createIssue") })).toBeEnabled();
    expect(screen.queryByRole("link", { name: t("cves.action.viewIssue") })).not.toBeInTheDocument();
  });

  it.each(["MEDIUM", "CRITICAL"] as const)("asks for owner/repo confirmation before creating a %s issue", async (severity) => {
    const onIssue = vi.fn();
    stub(cve({ severity, open_severity: severity }), undefined, onIssue);
    renderWithRoutes(routes, url);
    await userEvent.click(await screen.findByRole("button", { name: t("cves.detail.createIssue") }));
    const dialog = await screen.findByRole("dialog", { name: t("cves.createDialog.title", { cve: "CVE-2026-0001" }) });
    expect(within(dialog).getByText("example-org/api-gateway")).toBeInTheDocument();
    expect(onIssue).not.toHaveBeenCalled();
  });

  it("does not send the create request until the confirmation is accepted", async () => {
    const onIssue = vi.fn();
    stub(cve({ severity: "MEDIUM", open_severity: "MEDIUM" }), undefined, onIssue);
    renderWithRoutes(routes, url);
    await userEvent.click(await screen.findByRole("button", { name: t("cves.detail.createIssue") }));
    const dialog = await screen.findByRole("dialog");
    await userEvent.click(within(dialog).getByRole("button", { name: t("mappings.cancel") }));
    expect(onIssue).not.toHaveBeenCalled();
    await userEvent.click(screen.getByRole("button", { name: t("cves.detail.createIssue") }));
    await userEvent.click(within(await screen.findByRole("dialog")).getByRole("button", { name: t("cves.createDialog.confirm") }));
    await vi.waitFor(() => expect(onIssue).toHaveBeenCalledWith("/api/v1/cves/m1%3ACVE-2026-0001/issue"));
    expect(onIssue).toHaveBeenCalledTimes(1);
  });

  it("shows the source's display name on the header, and the repository when it has none (#323)", async () => {
    stub(cve({}));
    renderWithRoutes(routes, url);
    const header = await screen.findByText("ghcr.io/team/app", { exact: false });
    expect(header.textContent).toContain("ghcr.io/team/app");
  });

  it("shows the display name on the header when one is set (#323)", async () => {
    stub(cve({}), undefined, undefined, { ...source, name: "Team app" });
    renderWithRoutes(routes, url);
    const header = await screen.findByText("Team app", { exact: false });
    expect(header.textContent).toContain("Team app");
    expect(screen.queryByText("ghcr.io/team/app", { exact: false })).not.toBeInTheDocument();
  });

  it("loads the source by source_id and shows its GitHub repository, not a mappings route", async () => {
    const fetchMock = stub(cve({}));
    renderWithRoutes(routes, url);
    expect(await screen.findByText("example-org/api-gateway")).toBeInTheDocument();
    const paths = fetchMock.mock.calls.map(([input]) => String(input));
    expect(paths.some((path) => path.startsWith("/api/v1/mappings"))).toBe(false);
    expect(paths).toContain("/api/v1/image-sources/s1");
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
