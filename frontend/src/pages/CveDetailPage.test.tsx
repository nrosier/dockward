import { screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { t } from "../i18n";
import { formatDate } from "../components/jobs/dates";
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
    alias: null,
    image: null,
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
    tags_total: 1,
    tags: [{ image: "ghcr.io/team/app", image_tag: "1.42.0", status: "open", last_scan_at: "2026-11-03T14:58:00Z", fixed_in_version: "v0.31.0", newest_digest: true }],
    acceptance: null,
    description: "Misuse may cause an authorization bypass.",
    older_tags_only: false,
    aliases: [],
    ...over,
  };
}

function stub(
  detail: CveDetail,
  onAccept?: (body: unknown) => void,
  onIssue?: (path: string) => void,
  sourceOverride: Source = source,
  onUnaccept?: () => void,
) {
  return stubApi((path, init) => {
    if (path === "/api/v1/cves/m1%3ACVE-2026-0001/unaccept" && init?.method === "POST") {
      onUnaccept?.();
      return json({}, 200);
    }
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
          { image: "ghcr.io/team/app", image_tag: "0.4", status: "open", last_scan_at: null, fixed_in_version: null, newest_digest: false },
          { image: "ghcr.io/team/app", image_tag: "0.4.2", status: "open", last_scan_at: null, fixed_in_version: null, newest_digest: false },
          { image: "ghcr.io/team/app", image_tag: "latest", status: "fixed", last_scan_at: null, fixed_in_version: null, newest_digest: true },
        ],
      }),
    );
    renderWithRoutes(routes, url);
    expect(await screen.findByText(t("cves.detail.olderTagsOnly", { tags: "0.4, 0.4.2" }))).toBeInTheDocument();
    expect(screen.getAllByText(t("cves.detail.olderTag"))).toHaveLength(2);
  });

  it("tag_table_shows_image_tag_status_last_scan_fixed_in", async () => {
    stub(
      cve({
        tags_total: 120,
        tags: [
          { image: "ghcr.io/team/app", image_tag: "1.42.0", status: "open", last_scan_at: "2026-11-03T14:58:00Z", fixed_in_version: "v0.31.0", newest_digest: true },
          { image: "ghcr.io/team/worker", image_tag: "2.0", status: "fixed", last_scan_at: "2026-11-01T10:00:00Z", fixed_in_version: null, newest_digest: false },
          { image: "ghcr.io/team/api", image_tag: "3.1", status: "accepted", last_scan_at: null, fixed_in_version: null, newest_digest: false },
        ],
      }),
    );
    renderWithRoutes(routes, url);
    const table = await screen.findByRole("table");
    const headers = within(table).getAllByRole("columnheader").map((h) => h.textContent);
    expect(headers).toEqual([
      t("cves.detail.col.image"),
      t("cves.detail.col.tag"),
      t("cves.col.status"),
      t("cves.detail.col.lastScan"),
      t("cves.col.fixedIn"),
    ]);
    const rows = within(table).getAllByRole("row");
    expect(within(rows[1]).getByText("ghcr.io/team/app")).toBeInTheDocument();
    expect(within(rows[1]).getByText("1.42.0")).toBeInTheDocument();
    expect(within(rows[1]).getByText("v0.31.0")).toBeInTheDocument();
    expect(within(rows[2]).getByText("ghcr.io/team/worker")).toBeInTheDocument();
    expect(within(rows[3]).getByText("ghcr.io/team/api")).toBeInTheDocument();
    expect(screen.getByText(t("cves.detail.tagsShowing", { shown: 3, total: 120 }))).toBeInTheDocument();
  });

  it("empty_state_when_no_tags", async () => {
    stub(cve({ tags: [], tags_total: 0 }));
    renderWithRoutes(routes, url);
    expect(await screen.findByText(t("cves.detail.tagsEmpty"))).toBeInTheDocument();
    expect(screen.queryByRole("table")).toBeNull();
    expect(screen.queryByText(/^Showing /)).toBeNull();
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
    // The tag table now names the image repository (#350); the header does not.
    expect(header.closest("table")).toBeNull();
    expect(header.textContent).not.toContain("ghcr.io/team/app");
  });

  it("shows the primary id as the heading and an alias line under it (#337)", async () => {
    stub(cve({ cve_id: "CVE-2025-64756", aliases: ["GHSA-3g3m-2fjr-6pw4"] }));
    renderWithRoutes(routes, url);
    const heading = await screen.findByRole("heading", { level: 1 });
    expect(heading.textContent).toBe("CVE-2025-64756");
    const line = screen.getByTestId("cve-alias-line");
    expect(line.textContent).toBe(t("cves.detail.aliasOf", { id: "CVE-2025-64756", alias: "GHSA-3g3m-2fjr-6pw4" }));
    // The alias line sits after the title row and before the image line.
    expect(heading.compareDocumentPosition(line) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  });

  it("a GHSA-only record shows its id and no alias line (#337)", async () => {
    stub(cve({ cve_id: "GHSA-8rvm-662m-jvqv", aliases: [] }));
    renderWithRoutes(routes, url);
    const heading = await screen.findByRole("heading", { level: 1 });
    expect(heading.textContent).toBe("GHSA-8rvm-662m-jvqv");
    expect(document.querySelector("[data-testid='cve-alias-line']")).toBeNull();
  });

  it("never shows an alias equal to the primary id (#337)", async () => {
    stub(cve({ cve_id: "CVE-2026-84243", aliases: ["CVE-2026-84243"] }));
    renderWithRoutes(routes, url);
    const heading = await screen.findByRole("heading", { level: 1 });
    expect(heading.textContent).toBe("CVE-2026-84243");
    expect(document.querySelector("[data-testid='cve-alias-line']")).toBeNull();
  });

  it("lists several aliases on one line (#337)", async () => {
    stub(cve({ cve_id: "CVE-2025-64756", aliases: ["GHSA-aaaa-bbbb-cccc", "GHSA-dddd-eeee-ffff"] }));
    renderWithRoutes(routes, url);
    expect(
      await screen.findByText(t("cves.detail.aliasOf", { id: "CVE-2025-64756", alias: "GHSA-aaaa-bbbb-cccc, GHSA-dddd-eeee-ffff" })),
    ).toBeInTheDocument();
  });

  it("keeps View issue in the action group beside Accept risk (#337)", async () => {
    stub(cve({ github_issue_number: 7, github_issue_url: "https://github.com/example-org/api-gateway/issues/7" }));
    renderWithRoutes(routes, url);
    const view = await screen.findByRole("link", { name: t("cves.action.viewIssue") });
    const accept = await screen.findByRole("button", { name: t("cves.detail.accept") });
    expect(view.parentElement).toBe(accept.parentElement);
  });

  it("shows the image reference the CVE is for, from the newest tag (#323, Part B)", async () => {
    stub(cve({ image: "ghcr.io/team/app:latest" }));
    renderWithRoutes(routes, url);
    expect(await screen.findByText(t("cves.detail.image", { image: "ghcr.io/team/app:latest" }))).toBeInTheDocument();
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

describe("CveDetailPage delete (#349)", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  const deletePath = "/api/v1/admin/image-sources/s1/cves/CVE-2026-0001";

  function stubAs(role: "admin" | "user", onDelete: (path: string) => void, deleteStatus = 204) {
    return stubApi((path, init) => {
      if (path === "/api/v1/account/me") return json({ user: user(role) });
      if (path === "/api/v1/cves/m1%3ACVE-2026-0001" && init?.method === "GET") return json(cve({}));
      if (path === "/api/v1/image-sources/s1") return json(source);
      if (path === deletePath && init?.method === "DELETE") {
        onDelete(path);
        return deleteStatus === 204
          ? new Response(null, { status: 204 })
          : json({ error: { code: "conflict", message: "Revoke the acceptance before deleting this CVE record." } }, deleteStatus);
      }
      return undefined;
    });
  }

  it("delete_sends_nothing_until_confirmed", async () => {
    const onDelete = vi.fn();
    stubAs("admin", onDelete);
    renderWithRoutes(routes, url);
    await userEvent.click(await screen.findByRole("button", { name: t("cves.detail.delete") }));
    const dialog = await screen.findByRole("dialog", { name: t("cves.delete.title", { cve: "CVE-2026-0001" }) });
    expect(within(dialog).getByText(t("cves.delete.body", { cve: "CVE-2026-0001", source: "ghcr.io/team/app" }))).toBeInTheDocument();
    expect(onDelete).not.toHaveBeenCalled();
    await userEvent.click(within(dialog).getByRole("button", { name: t("mappings.cancel") }));
    expect(onDelete).not.toHaveBeenCalled();
  });

  it("confirm_sends_one_delete", async () => {
    const onDelete = vi.fn();
    stubAs("admin", onDelete);
    renderWithRoutes(routes, url);
    await userEvent.click(await screen.findByRole("button", { name: t("cves.detail.delete") }));
    const dialog = await screen.findByRole("dialog");
    await userEvent.click(within(dialog).getByRole("button", { name: t("cves.delete.confirm") }));
    await vi.waitFor(() => expect(onDelete).toHaveBeenCalledTimes(1));
    expect(onDelete).toHaveBeenCalledWith(deletePath);
  });

  it("shows the server message when the delete is refused", async () => {
    stubAs("admin", vi.fn(), 409);
    renderWithRoutes(routes, url);
    await userEvent.click(await screen.findByRole("button", { name: t("cves.detail.delete") }));
    await userEvent.click(within(await screen.findByRole("dialog")).getByRole("button", { name: t("cves.delete.confirm") }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Revoke the acceptance before deleting this CVE record.");
  });

  it("offers no delete to a non-admin", async () => {
    stubAs("user", vi.fn());
    renderWithRoutes(routes, url);
    await screen.findByRole("button", { name: t("cves.detail.accept") });
    expect(screen.queryByRole("button", { name: t("cves.detail.delete") })).not.toBeInTheDocument();
  });
});

describe("CveDetailPage acceptance note (#351)", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("accept_submits_with_an_empty_note", async () => {
    const accepted = vi.fn();
    stub(cve({}), accepted);
    renderWithRoutes(routes, url);
    await userEvent.click(await screen.findByRole("button", { name: t("cves.detail.accept") }));
    await screen.findByLabelText(t("cves.accept.reason"));
    await userEvent.click(screen.getByRole("button", { name: t("cves.accept.submit") }));
    await vi.waitFor(() => expect(accepted).toHaveBeenCalledTimes(1));
    expect(accepted).toHaveBeenCalledWith({ reason: "", expires_at: null });
  });

  it("accept_sends_the_note_as_entered", async () => {
    const accepted = vi.fn();
    stub(cve({}), accepted);
    renderWithRoutes(routes, url);
    await userEvent.click(await screen.findByRole("button", { name: t("cves.detail.accept") }));
    await userEvent.type(await screen.findByLabelText(t("cves.accept.reason")), "Vendor patch next sprint");
    await userEvent.click(screen.getByRole("button", { name: t("cves.accept.submit") }));
    await vi.waitFor(() => expect(accepted).toHaveBeenCalledTimes(1));
    expect(accepted).toHaveBeenCalledWith({ reason: "Vendor patch next sprint", expires_at: null });
  });

  it("detail_shows_the_note_and_who_and_when", async () => {
    stub(
      cve({
        accepted: true,
        acceptance: {
          id: "a1",
          mapping_id: "m1",
          cve_id: "CVE-2026-0001",
          reason: "Not reachable in this service",
          created_by: "alice",
          created_at: "2026-11-05T10:00:00Z",
          expires_at: null,
        },
      }),
    );
    renderWithRoutes(routes, url);
    expect(await screen.findByText("Not reachable in this service")).toBeInTheDocument();
    expect(screen.getByText(t("cves.detail.acceptedBy", { user: "alice" }))).toBeInTheDocument();
    expect(screen.getByText(t("cves.detail.acceptedAt", { date: formatDate("2026-11-05T10:00:00Z") }))).toBeInTheDocument();
  });

  it("detail_shows_a_placeholder_for_an_empty_note", async () => {
    stub(
      cve({
        accepted: true,
        acceptance: {
          id: "a1",
          mapping_id: "m1",
          cve_id: "CVE-2026-0001",
          reason: "",
          created_by: "alice",
          created_at: "2026-11-05T10:00:00Z",
          expires_at: null,
        },
      }),
    );
    renderWithRoutes(routes, url);
    expect(await screen.findByText(t("cves.detail.noNote"))).toBeInTheDocument();
  });

  it("un_accept_sends_nothing_until_confirmed", async () => {
    const unaccepted = vi.fn();
    stub(cve({ accepted: true }), undefined, undefined, source, unaccepted);
    renderWithRoutes(routes, url);
    await userEvent.click(await screen.findByRole("button", { name: t("cves.detail.unaccept") }));
    const dialog = await screen.findByRole("dialog");
    expect(unaccepted).not.toHaveBeenCalled();
    await userEvent.click(within(dialog).getByRole("button", { name: t("cves.detail.unaccept") }));
    await vi.waitFor(() => expect(unaccepted).toHaveBeenCalledTimes(1));
  });

  function stubUnacceptBody(detail: CveDetail, onBody: (body: unknown) => void) {
    return stubApi((path, init) => {
      if (path === "/api/v1/account/me") return json({ user: user("user") });
      if (path === "/api/v1/cves/m1%3ACVE-2026-0001" && init?.method === "GET") return json(detail);
      if (path === "/api/v1/image-sources/s1") return json(source);
      if (path === "/api/v1/cves/m1%3ACVE-2026-0001/unaccept" && init?.method === "POST") {
        onBody(init.body === undefined ? undefined : JSON.parse(String(init.body)));
        return json({}, 200);
      }
      return undefined;
    });
  }

  it("un_accept_shows_reopen_checkbox_when_issue_is_closed", async () => {
    stubUnacceptBody(cve({ accepted: true, github_issue_number: 7, github_issue_status: "closed" }), vi.fn());
    renderWithRoutes(routes, url);
    await userEvent.click(await screen.findByRole("button", { name: t("cves.detail.unaccept") }));
    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByRole("checkbox", { name: t("cves.unaccept.reopen") })).not.toBeChecked();
  });

  it("un_accept_hides_reopen_checkbox_without_a_closed_issue", async () => {
    stubUnacceptBody(cve({ accepted: true, github_issue_number: 7, github_issue_status: "open" }), vi.fn());
    renderWithRoutes(routes, url);
    await userEvent.click(await screen.findByRole("button", { name: t("cves.detail.unaccept") }));
    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).queryByRole("checkbox")).toBeNull();
  });

  it("un_accept_sends_reopen_issue_flag", async () => {
    const bodies: unknown[] = [];
    stubUnacceptBody(cve({ accepted: true, github_issue_number: 7, github_issue_status: "closed" }), (body) => bodies.push(body));
    renderWithRoutes(routes, url);
    await userEvent.click(await screen.findByRole("button", { name: t("cves.detail.unaccept") }));
    const dialog = await screen.findByRole("dialog");
    await userEvent.click(within(dialog).getByRole("checkbox", { name: t("cves.unaccept.reopen") }));
    await userEvent.click(within(dialog).getByRole("button", { name: t("cves.detail.unaccept") }));
    await vi.waitFor(() => expect(bodies).toEqual([{ reopen_issue: true }]));
  });

  function stubUnaccept(role: "admin" | "user", onUnaccept: () => void) {
    const foreign: Source = { ...source, user_id: "someone-else" };
    return stubApi((path, init) => {
      if (path === "/api/v1/account/me") return json({ user: user(role) });
      if (path === "/api/v1/cves/m1%3ACVE-2026-0001" && init?.method === "GET") return json(cve({ accepted: true }));
      if (path === "/api/v1/image-sources/s1") return json(foreign);
      if (path === "/api/v1/cves/m1%3ACVE-2026-0001/unaccept" && init?.method === "POST") {
        onUnaccept();
        return json({}, 200);
      }
      return undefined;
    });
  }

  it("un_accept_shows_for_an_admin_who_is_not_the_owner", async () => {
    const unaccepted = vi.fn();
    stubUnaccept("admin", unaccepted);
    renderWithRoutes(routes, url);
    await userEvent.click(await screen.findByRole("button", { name: t("cves.detail.unaccept") }));
    const dialog = await screen.findByRole("dialog");
    expect(unaccepted).not.toHaveBeenCalled();
    await userEvent.click(within(dialog).getByRole("button", { name: t("cves.detail.unaccept") }));
    await vi.waitFor(() => expect(unaccepted).toHaveBeenCalledTimes(1));
  });

  it("un_accept_hidden_for_a_non_admin_non_owner", async () => {
    stubUnaccept("user", vi.fn());
    renderWithRoutes(routes, url);
    await screen.findByRole("heading", { level: 1 });
    expect(screen.queryByRole("button", { name: t("cves.detail.unaccept") })).not.toBeInTheDocument();
  });
});
