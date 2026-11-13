import { screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { t } from "../i18n";
import { json, renderAt, stubApi, user } from "../test/render";
import type { CveSummary } from "../types/api";
import type { Source } from "../types/sources";
import CvesPage from "./CvesPage";

const medium: CveSummary = {
  id: "m1:CVE-2026-0002",
  source_id: "m1",
  mapping_id: "m1",
  cve_id: "CVE-2026-0002",
  severity: "MEDIUM",
  open_severity: "MEDIUM",
  alias: null,
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
  scanners: [],
};

function row(over: Partial<CveSummary>): CveSummary {
  return { ...medium, ...over };
}

// The image sources the list reads for each row's repository, keyed by source_id (#323).
function imageSource(id: string, repository: string, github_repo: string): Source {
  return {
    id,
    user_id: "u1",
    hub_id: "h1",
    repository,
    name: null,
    tag_value: "latest",
    github_cred_id: "c1",
    github_owner: "octo",
    github_repo,
    default_branch: "main",
    auto_create_issues: true,
    min_issue_severity: "HIGH",
    has_credential: true,
    last_discovery_at: null,
  };
}
const sources = [
  imageSource("m1", "platform/api", "api-gh"),
  imageSource("m2", "platform/web", "web-gh"),
  imageSource("m3", "data/etl", "etl-gh"),
];

function stub(items: CveSummary[] = [medium], onIssue?: (path: string) => void, sourceItems: Source[] = sources) {
  return stubApi((path, init) => {
    if (path === "/api/v1/account/me") return json({ user: user("user") });
    if (path.endsWith("/issue") && init?.method === "POST") {
      onIssue?.(path);
      return json({ github_issue_url: "https://github.com/o/r/issues/1", github_issue_number: 1 }, 201);
    }
    if (path.startsWith("/api/v1/cves")) return json({ items, page: 1, page_size: 50, total: items.length });
    if (path.startsWith("/api/v1/image-sources?")) return json({ items: sourceItems, page: 1, page_size: 200, total: sourceItems.length });
    if (/^\/api\/v1\/image-sources\/[^/?]+\/tags/.test(path)) {
      return json({ items: [{ image_tag: "1.42.0", last_scan_at: "2026-11-08T10:00:00Z", open_cves: 3 }] });
    }
    return undefined;
  });
}

function cvesCalls(fetchMock: ReturnType<typeof stub>): string[] {
  return fetchMock.mock.calls.map(([path]) => String(path)).filter((path) => path.startsWith("/api/v1/cves?"));
}

function lastQuery(fetchMock: ReturnType<typeof stub>): URLSearchParams {
  return new URLSearchParams(cvesCalls(fetchMock).at(-1)?.split("?")[1]);
}

const group = (name: Parameters<typeof t>[0]) => within(screen.getByRole("group", { name: t(name) }));

describe("CvesPage", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("sends every severity and the Open status by default, with no toggle", async () => {
    const fetchMock = stub();
    renderAt(<CvesPage />);
    await screen.findByText("CVE-2026-0002");
    const query = lastQuery(fetchMock);
    expect(query.get("severity")).toBeNull();
    expect(query.get("status")).toBe("open");
    expect(query.get("has_issue")).toBeNull();
    expect(screen.queryByRole("group", { name: t("scope.label") })).not.toBeInTheDocument();
  });

  it("sets the URL and the request when the pills are toggled", async () => {
    const fetchMock = stub();
    const { router } = renderAt(<CvesPage />);
    await screen.findByText("CVE-2026-0002");
    expect(group("cves.filter.status").getByRole("button", { name: t("cves.status.open") })).toHaveAttribute("aria-pressed", "true");
    await userEvent.click(group("cves.filter.severity").getByRole("button", { name: "CRITICAL" }));
    await userEvent.click(group("cves.filter.severity").getByRole("button", { name: "HIGH" }));
    await userEvent.click(group("cves.filter.status").getByRole("button", { name: t("cves.status.accepted") }));
    await userEvent.click(group("cves.filter.issue").getByRole("button", { name: t("cves.filter.hasIssue") }));
    await vi.waitFor(() => {
      const query = lastQuery(fetchMock);
      expect(query.get("severity")).toBe("CRITICAL,HIGH");
      expect(query.get("status")).toBe("open,accepted");
      expect(query.get("has_issue")).toBe("true");
    });
    const url = new URLSearchParams(router.state.location.search);
    expect(url.get("severity")).toBe("CRITICAL,HIGH");
    expect(url.get("status")).toBe("open,accepted");
    expect(url.get("has_issue")).toBe("true");
    // Pressing the pressed Has issue pill clears the group; No issue replaces Has issue.
    await userEvent.click(group("cves.filter.issue").getByRole("button", { name: t("cves.filter.noIssue") }));
    expect(new URLSearchParams(router.state.location.search).get("has_issue")).toBe("false");
    await userEvent.click(group("cves.filter.issue").getByRole("button", { name: t("cves.filter.noIssue") }));
    expect(new URLSearchParams(router.state.location.search).get("has_issue")).toBeNull();
  });

  it("filters on whether a fix is available, in the URL and the request", async () => {
    const fetchMock = stub();
    const { router } = renderAt(<CvesPage />);
    await screen.findByText("CVE-2026-0002");
    expect(lastQuery(fetchMock).get("fix")).toBeNull();
    const available = group("cves.filter.fix").getByRole("button", { name: t("cves.filter.fixAvailable") });
    expect(available).toHaveAttribute("aria-pressed", "false");
    await userEvent.click(available);
    expect(available).toHaveAttribute("aria-pressed", "true");
    await vi.waitFor(() => expect(lastQuery(fetchMock).get("fix")).toBe("available"));
    await userEvent.click(group("cves.filter.fix").getByRole("button", { name: t("cves.filter.noFix") }));
    await vi.waitFor(() => expect(lastQuery(fetchMock).get("fix")).toBe("available,none"));
    expect(new URLSearchParams(router.state.location.search).get("fix")).toBe("available,none");
    await userEvent.click(available);
    await vi.waitFor(() => expect(lastQuery(fetchMock).get("fix")).toBe("none"));
  });

  it("combines the fix filter with status and a repository in the request and the URL", async () => {
    const fetchMock = stub();
    const { router } = renderAt(<CvesPage />);
    await screen.findByText("CVE-2026-0002");
    await userEvent.click(group("cves.filter.fix").getByRole("button", { name: t("cves.filter.fixAvailable") }));
    await userEvent.click(group("cves.filter.status").getByRole("button", { name: t("cves.status.accepted") }));
    await userEvent.click(screen.getByRole("combobox", { name: t("cves.filter.repository") }));
    await userEvent.click(await screen.findByRole("option", { name: "platform/api" }));
    await vi.waitFor(() => {
      const query = lastQuery(fetchMock);
      expect(query.get("fix")).toBe("available");
      expect(query.get("status")).toBe("open,accepted");
      expect(query.get("repository")).toBe("platform/api");
    });
    const url = new URLSearchParams(router.state.location.search);
    expect(url.get("fix")).toBe("available");
    expect(url.get("status")).toBe("open,accepted");
    expect(url.get("repository")).toBe("platform/api");
  });

  it("keeps the last Status pill on", async () => {
    stub();
    renderAt(<CvesPage />);
    await screen.findByText("CVE-2026-0002");
    const open = group("cves.filter.status").getByRole("button", { name: t("cves.status.open") });
    await userEvent.click(open);
    expect(open).toHaveAttribute("aria-pressed", "true");
  });

  it("restores the pills from the URL and from old links", async () => {
    const fetchMock = stub();
    renderAt(<CvesPage />, "/cves?severity=LOW&status=fixed&has_issue=false&q=glibc&tag=1.42.0");
    await screen.findByText("CVE-2026-0002");
    expect(group("cves.filter.severity").getByRole("button", { name: "LOW" })).toHaveAttribute("aria-pressed", "true");
    expect(group("cves.filter.severity").getByRole("button", { name: "HIGH" })).toHaveAttribute("aria-pressed", "false");
    expect(group("cves.filter.status").getByRole("button", { name: t("cves.status.fixed") })).toHaveAttribute("aria-pressed", "true");
    expect(group("cves.filter.issue").getByRole("button", { name: t("cves.filter.noIssue") })).toHaveAttribute("aria-pressed", "true");
    expect(screen.getByLabelText(t("cves.filter.search"))).toHaveValue("glibc");
    expect(lastQuery(fetchMock).get("tag")).toBe("1.42.0");
  });

  it("maps accepted=true to the Accepted pill and the dashboard cards open their filters", async () => {
    const fetchMock = stub();
    renderAt(<CvesPage />, "/cves?accepted=true");
    await screen.findByText("CVE-2026-0002");
    expect(group("cves.filter.status").getByRole("button", { name: t("cves.status.accepted") })).toHaveAttribute("aria-pressed", "true");
    expect(group("cves.filter.status").getByRole("button", { name: t("cves.status.open") })).toHaveAttribute("aria-pressed", "false");
    expect(lastQuery(fetchMock).get("status")).toBe("accepted");
    expect(lastQuery(fetchMock).get("accepted")).toBeNull();
  });

  it("searches with a debounce and Clear empties the field at once", async () => {
    const fetchMock = stub();
    const { router } = renderAt(<CvesPage />);
    await screen.findByText("CVE-2026-0002");
    expect(screen.queryByRole("button", { name: t("cves.filter.clear") })).not.toBeInTheDocument();
    await userEvent.type(screen.getByLabelText(t("cves.filter.search")), "100%_x");
    await vi.waitFor(() => expect(lastQuery(fetchMock).get("q")).toBe("100%_x"));
    expect(new URLSearchParams(router.state.location.search).get("q")).toBe("100%_x");
    await userEvent.click(screen.getByRole("button", { name: t("cves.filter.clear") }));
    expect(screen.getByLabelText(t("cves.filter.search"))).toHaveValue("");
    await vi.waitFor(() => expect(lastQuery(fetchMock).get("q")).toBeNull());
  });

  it("narrows the Repository options to the chosen namespace", async () => {
    stub();
    const { router } = renderAt(<CvesPage />, "/cves?repository=data/etl");
    await screen.findByText("CVE-2026-0002");
    const repository = screen.getByRole("combobox", { name: t("cves.filter.repository") });
    await userEvent.click(repository);
    expect(within(await screen.findByRole("listbox", { name: t("cves.filter.repository") })).getAllByRole("option").map((o) => o.textContent)).toEqual([
      t("cves.filter.allRepositories"),
      "data/etl",
      "platform/api",
      "platform/web",
    ]);
    await userEvent.keyboard("{Escape}");
    // Choosing the namespace "platform" narrows the list and clears "data/etl", which is not in it.
    const namespace = screen.getByRole("combobox", { name: t("cves.filter.namespace") });
    await userEvent.click(namespace);
    await userEvent.click(await screen.findByRole("option", { name: "platform" }));
    expect(new URLSearchParams(router.state.location.search).get("namespace")).toBe("platform");
    expect(new URLSearchParams(router.state.location.search).get("repository")).toBeNull();
    await userEvent.click(screen.getByRole("combobox", { name: t("cves.filter.repository") }));
    expect(within(await screen.findByRole("listbox")).getAllByRole("option").map((o) => o.textContent)).toEqual([
      t("cves.filter.allRepositories"),
      "platform/api",
      "platform/web",
    ]);
  });

  it("filters combobox options by typing and picks with the keyboard", async () => {
    const fetchMock = stub();
    renderAt(<CvesPage />);
    await screen.findByText("CVE-2026-0002");
    const mappingBox = screen.getByRole("combobox", { name: t("cves.filter.mapping") });
    expect(mappingBox).toHaveValue(t("cves.filter.allMappings"));
    await userEvent.click(mappingBox);
    await userEvent.type(mappingBox, "etl");
    await userEvent.keyboard("{ArrowDown}{Enter}");
    await vi.waitFor(() => expect(lastQuery(fetchMock).get("source_id")).toBe("m3"));
    expect(screen.getByRole("combobox", { name: t("cves.filter.mapping") })).toHaveValue("data/etl");
  });

  it("offers the tags of the chosen mapping and accepts a typed tag", async () => {
    const fetchMock = stub();
    renderAt(<CvesPage />, "/cves?mapping=m1");
    await screen.findByText("CVE-2026-0002");
    const tag = screen.getByRole("combobox", { name: t("cves.filter.tag") });
    await userEvent.click(tag);
    await userEvent.click(await screen.findByRole("option", { name: "1.42.0" }));
    await vi.waitFor(() => expect(lastQuery(fetchMock).get("tag")).toBe("1.42.0"));
    await userEvent.click(screen.getByRole("combobox", { name: t("cves.filter.tag") }));
    await userEvent.type(screen.getByRole("combobox", { name: t("cves.filter.tag") }), "9.9");
    await userEvent.click(await screen.findByRole("option", { name: t("cves.combo.useValue", { value: "9.9" }) }));
    await vi.waitFor(() => expect(lastQuery(fetchMock).get("tag")).toBe("9.9"));
  });

  it("renders all five severity pills with text labels", async () => {
    const items = (["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"] as const).map((severity, i) =>
      row({ id: `m1:CVE-${i}`, cve_id: `CVE-${i}`, severity, open_severity: severity }),
    );
    stub(items);
    renderAt(<CvesPage />);
    await screen.findByText("CVE-0");
    for (const key of ["pill.critical", "pill.high", "pill.medium", "pill.low", "pill.unknown"] as const) {
      const cell = screen.getAllByText(t(key)).find((el) => el.closest("tbody") !== null);
      expect(cell).toBeDefined();
    }
  });

  it("shows Tags as n of m", async () => {
    stub();
    renderAt(<CvesPage />);
    const tr = (await screen.findByText("CVE-2026-0002")).closest("tr") as HTMLElement;
    expect(within(tr).getByText(t("cves.tags", { open: 2, tracked: 10 }))).toBeInTheDocument();
  });

  it.each(["CRITICAL", "MEDIUM", "LOW"] as const)("asks for confirmation before creating a %s issue", async (severity) => {
    const onIssue = vi.fn();
    stub([row({ severity, open_severity: severity })], onIssue);
    renderAt(<CvesPage />);
    await userEvent.click(await screen.findByRole("button", { name: t("cves.action.createIssue") }));
    const dialog = await screen.findByRole("dialog", { name: t("cves.createDialog.title", { cve: "CVE-2026-0002" }) });
    // The dialog names the GitHub repository and the CVE; nothing is created yet.
    expect(within(dialog).getByText("octo/api-gh")).toBeInTheDocument();
    expect(within(dialog).getByText("CVE-2026-0002")).toBeInTheDocument();
    expect(onIssue).not.toHaveBeenCalled();
    await userEvent.click(within(dialog).getByRole("button", { name: t("mappings.cancel") }));
    expect(onIssue).not.toHaveBeenCalled();
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: t("cves.action.createIssue") }));
    await userEvent.click(within(await screen.findByRole("dialog")).getByRole("button", { name: t("cves.createDialog.confirm") }));
    await vi.waitFor(() => expect(onIssue).toHaveBeenCalledWith("/api/v1/cves/m1%3ACVE-2026-0002/issue"));
    expect(onIssue).toHaveBeenCalledTimes(1);
  });

  it("reads each row's repository from its source_id, not the removed mapping_id (#323)", async () => {
    const fetchMock = stub([row({ source_id: "m3", mapping_id: "stale" })]);
    renderAt(<CvesPage />);
    await userEvent.click(await screen.findByRole("button", { name: t("cves.action.createIssue") }));
    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByText("octo/etl-gh")).toBeInTheDocument();
    const paths = fetchMock.mock.calls.map(([input]) => String(input));
    expect(paths.some((path) => path.startsWith("/api/v1/mappings/stale"))).toBe(false);
    expect(paths.some((path) => path.startsWith("/api/v1/image-sources?"))).toBe(true);
  });

  it("creates nothing when the dialog is closed with Escape", async () => {
    const onIssue = vi.fn();
    stub([medium], onIssue);
    renderAt(<CvesPage />);
    await userEvent.click(await screen.findByRole("button", { name: t("cves.action.createIssue") }));
    await screen.findByRole("dialog");
    await userEvent.keyboard("{Escape}");
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(onIssue).not.toHaveBeenCalled();
  });

  it("shows View issue for a CVE with an issue, with the closed status beside the number", async () => {
    stub([
      row({ github_issue_number: 7, github_issue_url: "https://github.com/octo/api-gh/issues/7", github_issue_status: "closed" }),
    ]);
    renderAt(<CvesPage />);
    const tr = (await screen.findByText("CVE-2026-0002")).closest("tr") as HTMLElement;
    const view = within(tr).getByRole("link", { name: t("cves.action.viewIssue") });
    expect(view).toHaveAttribute("href", "https://github.com/octo/api-gh/issues/7");
    expect(within(tr).getByText("#7")).toBeInTheDocument();
    expect(within(tr).getByText(t("cves.issue.closed"))).toBeInTheDocument();
    expect(within(tr).queryByRole("button", { name: t("cves.action.createIssue") })).not.toBeInTheDocument();
  });

  it("list_row_shows_the_reporting_scanners", async () => {
    stub([
      row({ cve_id: "CVE-2026-0002", id: "m1:CVE-2026-0002", scanners: ["trivy", "grype"] }),
      row({ cve_id: "CVE-2026-0003", id: "m1:CVE-2026-0003", scanners: ["grype"] }),
    ]);
    renderAt(<CvesPage />);
    expect(await screen.findByRole("columnheader", { name: t("cves.col.scanners") })).toBeInTheDocument();
    const both = (await screen.findByText("CVE-2026-0002")).closest("tr") as HTMLElement;
    expect(within(both).getByText(`${t("jobs.scanner.trivy")}, ${t("jobs.scanner.grype")}`)).toBeInTheDocument();
    const one = (await screen.findByText("CVE-2026-0003")).closest("tr") as HTMLElement;
    expect(within(one).getByText(t("jobs.scanner.grype"))).toBeInTheDocument();
    expect(within(one).queryByText(new RegExp(t("jobs.scanner.trivy")))).not.toBeInTheDocument();
  });

  it("disables Create issue while an acceptance is active", async () => {
    stub([row({ accepted: true })]);
    renderAt(<CvesPage />);
    expect(await screen.findByRole("button", { name: t("cves.action.createIssue") })).toBeDisabled();
  });

  it("shows only the primary id in the id cell, with no alias line (#337)", async () => {
    stub([row({ cve_id: "CVE-2025-64756", alias: "GHSA-3g3m-2fjr-6pw4", id: "m1:CVE-2025-64756" })]);
    renderAt(<CvesPage />);
    const link = await screen.findByRole("link", { name: `CVE-2025-64756 ${t("cves.row.inSource", { source: "platform/api" })}` });
    expect((link.closest("td") as HTMLElement).textContent).toContain("CVE-2025-64756");
    expect(screen.queryByText("GHSA-3g3m-2fjr-6pw4", { exact: false })).not.toBeInTheDocument();
  });

  it("shows one row per source for the same CVE, told apart by the Mapping column (#337)", async () => {
    stub([
      row({ id: "m1:CVE-2026-0100", source_id: "m1", cve_id: "CVE-2026-0100" }),
      row({ id: "m2:CVE-2026-0100", source_id: "m2", cve_id: "CVE-2026-0100" }),
    ]);
    renderAt(<CvesPage />);
    const rows = (await screen.findAllByText("CVE-2026-0100", { exact: false })).map((node) => node.closest("tr") as HTMLElement);
    expect(rows).toHaveLength(2);
    expect(within(rows[0]).getByText("platform/api")).toBeInTheDocument();
    expect(within(rows[1]).getByText("platform/web")).toBeInTheDocument();
  });

  it("shows the source display name in the Mapping column when one is set (#337)", async () => {
    stub([row({})], undefined, [{ ...imageSource("m1", "platform/api", "api-gh"), name: "Production API" }]);
    renderAt(<CvesPage />);
    const tr = (await screen.findByText("CVE-2026-0002", { exact: false })).closest("tr") as HTMLElement;
    expect(within(tr).getByText("Production API")).toBeInTheDocument();
    expect(within(tr).queryByText("platform/api")).not.toBeInTheDocument();
  });

  it("gives each id link a hidden suffix naming its source (#337)", async () => {
    stub([row({})]);
    renderAt(<CvesPage />);
    const link = await screen.findByRole("link", { name: `CVE-2026-0002 ${t("cves.row.inSource", { source: "platform/api" })}` });
    expect(link).toHaveAttribute("href", "/cves/m1%3ACVE-2026-0002");
    // The suffix is visually hidden: the visible text is the id plus a screen-reader-only span.
    expect(link.firstChild?.textContent).toBe("CVE-2026-0002");
    expect(within(link).getByText(t("cves.row.inSource", { source: "platform/api" }))).toHaveClass("sr-only");
  });

  it("sends the Mapping filter as source_id on the list request, not as mapping (#323 follow-up)", async () => {
    const fetchMock = stub();
    renderAt(<CvesPage />, "/cves?mapping=m1");
    await screen.findByText("CVE-2026-0002");
    await vi.waitFor(() => {
      const query = lastQuery(fetchMock);
      expect(query.get("source_id")).toBe("m1");
      expect(query.has("mapping")).toBe(false);
    });
  });

  it("sends no request to the removed /mappings routes, and reads tags from the source (#323)", async () => {
    const fetchMock = stub();
    renderAt(<CvesPage />, "/cves?mapping=m1");
    await screen.findByText("CVE-2026-0002");
    await userEvent.click(screen.getByRole("combobox", { name: t("cves.filter.tag") }));
    await userEvent.click(await screen.findByRole("option", { name: "1.42.0" }));
    await vi.waitFor(() => expect(lastQuery(fetchMock).get("tag")).toBe("1.42.0"));
    const paths = fetchMock.mock.calls.map(([input]) => String(input));
    expect(paths.some((path) => path.startsWith("/api/v1/mappings"))).toBe(false);
    expect(paths.some((path) => path.startsWith("/api/v1/image-sources/m1/tags"))).toBe(true);
  });

  it("offers no Create issue for a CVE fixed on every tag", async () => {
    stub([row({ severity: "CRITICAL", open_severity: null, status: "fixed" })]);
    renderAt(<CvesPage />);
    const cell = (await screen.findByText("CVE-2026-0002")).closest("tr") as HTMLElement;
    expect(within(cell).queryByRole("button", { name: t("cves.action.createIssue") })).not.toBeInTheDocument();
    expect(within(cell).getByText(t("cves.issue.notEligible"))).toBeInTheDocument();
  });

  it("opening_a_cve_keeps_the_list_query_for_back", async () => {
    stub();
    renderAt(<CvesPage />, "/cves?severity=HIGH&status=open&q=lib&order=asc");
    const link = await screen.findByRole("link", { name: /^CVE-2026-0002/ });
    const target = new URL(link.getAttribute("href") ?? "", "http://x");
    expect(target.pathname).toBe("/cves/m1%3ACVE-2026-0002");
    expect(target.searchParams.get("from")).toBe("severity=HIGH&status=open&q=lib&order=asc");
  });

  it("clear_filter_removes_all_filters_and_the_search", async () => {
    const fetchMock = stub();
    const { router } = renderAt(<CvesPage />, "/cves?severity=HIGH&status=fixed&q=lib&has_issue=true&order=asc");
    await screen.findByText("CVE-2026-0002");
    await userEvent.click(screen.getByRole("button", { name: t("cves.filter.clearAll") }));
    await vi.waitFor(() => {
      expect(router.state.location.search).toBe("?order=asc");
    });
    await vi.waitFor(() => {
      expect(lastQuery(fetchMock).get("severity")).toBeNull();
    });
    expect(screen.getByRole("searchbox", { name: t("cves.filter.search") })).toHaveValue("");
    expect(screen.getByRole("button", { name: t("cves.filter.clearAll") })).toBeDisabled();
  });

  it("clear_filter_is_disabled_with_no_filters", async () => {
    stub();
    renderAt(<CvesPage />, "/cves");
    await screen.findByText("CVE-2026-0002");
    expect(screen.getByRole("button", { name: t("cves.filter.clearAll") })).toBeDisabled();
  });
});
