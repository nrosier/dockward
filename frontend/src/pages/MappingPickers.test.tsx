import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { t } from "../i18n";
import { json, renderWithRoutes, stubApi } from "../test/render";
import type { Mapping } from "../types/api";
import MappingFormPage from "./MappingFormPage";

const harborCred = (id: string, label: string, base: string) => ({
  id, service_type: "harbor", label, base_url: base, username: "robot", expires_at: null, created_at: null,
});
const HARBOR_A = harborCred("hc1", "harbor-prod", "https://harbor-prod.example.org");
const HARBOR_B = harborCred("hc2", "harbor-lab", "https://harbor-lab.example.org");
const GITHUB = { ...HARBOR_A, id: "gc1", service_type: "github", label: "gh-token", base_url: null, username: null };

const existing: Mapping = {
  id: "m1", user_id: "u1", harbor_cred_id: "hc1", github_cred_id: "gc1", harbor_base_url: HARBOR_A.base_url,
  harbor_project: "gone-project", harbor_repository: "gone-repo", github_owner: "old-org", github_repo: "old-repo",
  default_branch: "main", auto_create_issues: true, min_issue_severity: "HIGH", created_at: null,
};

const page = <T,>(items: T[], extra: Record<string, unknown> = {}) => ({ items, page: 1, page_size: 50, total: items.length, truncated: false, ...extra });
const listResp = <T,>(items: T[]) => ({ items, page: 1, page_size: 200, total: items.length });

interface Opts {
  projects?: (url: URL) => Response;
  repos?: (url: URL) => Response;
  github?: (url: URL) => Response;
  suggestion?: (url: URL) => Response;
  hide?: (body: unknown) => Response;
}

function stub(opts: Opts = {}) {
  return stubApi((path, init) => {
    const url = new URL(path, "http://x");
    const p = url.pathname;
    if (p === "/api/v1/credentials" && url.searchParams.get("service_type") === "harbor") return json(listResp([HARBOR_A, HARBOR_B]));
    if (p === "/api/v1/credentials" && url.searchParams.get("service_type") === "github") return json(listResp([GITHUB]));
    if (p === "/api/v1/mappings" && (init?.method ?? "GET") === "GET") return json(listResp([]));
    if (p === "/api/v1/mappings/m1") return json(existing);
    if (/\/credentials\/hc\d\/harbor-projects$/.test(p)) {
      return opts.projects?.(url) ?? json(page([{ name: "nrosier" }, { name: "library" }]));
    }
    if (/\/harbor-projects\/[^/]+\/repositories$/.test(p)) {
      return opts.repos?.(url) ?? json(page([
        { project: "nrosier", repository: "walley", full_name: "nrosier/walley" },
        { project: "nrosier", repository: "astraya", full_name: "nrosier/astraya" },
      ]));
    }
    if (p === "/api/v1/credentials/gc1/github-repositories") {
      return opts.github?.(url) ?? json(page([
        { owner: "nrosier", repo: "walley", full_name: "nrosier/walley", private: false, archived: false },
        { owner: "nrosier", repo: "old-service", full_name: "nrosier/old-service", private: true, archived: true },
      ]));
    }
    if (p.endsWith("/source-suggestion")) {
      return opts.suggestion?.(url) ?? json({ suggestion: null, reason: "no_label" });
    }
    if (p === "/api/v1/pickers/hidden" && init?.method === "POST") {
      return opts.hide?.(JSON.parse(String(init.body))) ?? json({ id: "h1", source: "github", full_name: "x/y", harbor_base_url: null, created_at: "2026-11-05T10:00:00Z" }, 201);
    }
    return undefined;
  });
}

const routes = [
  { path: "/mappings/new", element: <MappingFormPage /> },
  { path: "/mappings/:id", element: <MappingFormPage /> },
];

class NoopResizeObserver { observe() {} unobserve() {} disconnect() {} }

const calls = (fetchMock: ReturnType<typeof stub>, fragment: string) =>
  fetchMock.mock.calls.map((c) => String(c[0])).filter((u) => u.includes(fragment));

async function pickProject(name: string) {
  const list = await screen.findByRole("list", { name: t("mapping.picker.projectList") });
  await userEvent.click(await within(list).findByRole("button", { name }));
}

describe("Mapping form pickers", () => {
  beforeEach(() => { vi.stubGlobal("ResizeObserver", NoopResizeObserver); });
  afterEach(() => { vi.unstubAllGlobals(); });

  it("loads the project list once a credential is picked, and the repository list from a project", async () => {
    const fetchMock = stub();
    renderWithRoutes(routes, "/mappings/new");
    await pickProject("nrosier");
    const repos = await screen.findByRole("list", { name: t("mapping.picker.repositoryList") });
    // The repository is shown without the project prefix.
    expect(within(repos).getByRole("button", { name: "walley" })).toBeInTheDocument();
    expect(calls(fetchMock, "/credentials/hc1/harbor-projects?")[0]).toContain("page_size=50");
    await userEvent.click(within(repos).getByRole("button", { name: "walley" }));
    // The saved value keeps project/repository.
    expect(screen.getByLabelText(t("mappings.form.harborProject"))).toHaveValue("nrosier");
    expect(screen.getByLabelText(t("mappings.form.harborRepository"))).toHaveValue("walley");
    expect(screen.getAllByText(t("mapping.picker.saved", { value: "nrosier/walley" })).length).toBeGreaterThan(0);
  });

  it("opens the repository list only from a picked project", async () => {
    const fetchMock = stub();
    renderWithRoutes(routes, "/mappings/new");
    await screen.findByRole("list", { name: t("mapping.picker.projectList") });
    expect(screen.queryByRole("list", { name: t("mapping.picker.repositoryList") })).not.toBeInTheDocument();
    expect(calls(fetchMock, "/repositories")).toEqual([]);
  });

  it("sends q after the debounce, one request for a burst of typing", async () => {
    const fetchMock = stub();
    renderWithRoutes(routes, "/mappings/new");
    await screen.findByRole("list", { name: t("mapping.picker.projectList") });
    await userEvent.type(screen.getByLabelText(t("mapping.picker.searchProjects")), "lib");
    await waitFor(() => expect(calls(fetchMock, "q=lib")).toHaveLength(1));
    expect(calls(fetchMock, "q=l&")).toEqual([]);
    expect(calls(fetchMock, "q=li&")).toEqual([]);
  });

  it("changes the request when paging", async () => {
    const fetchMock = stub({ projects: () => json(page([{ name: "a" }], { total: 120 })) });
    renderWithRoutes(routes, "/mappings/new");
    const nav = (await screen.findAllByRole("navigation", { name: t("pagination.label") }))[0];
    await userEvent.click(within(nav).getByRole("button", { name: t("pagination.next") }));
    await waitFor(() => expect(calls(fetchMock, "harbor-projects?").some((u) => u.includes("page=2"))).toBe(true));
  });

  it("shows the cut note only when truncated is true", async () => {
    stub({ projects: () => json(page([{ name: "a" }], { truncated: true })) });
    renderWithRoutes(routes, "/mappings/new");
    expect(await screen.findByText(t("mapping.picker.cut"))).toBeInTheDocument();
  });

  it("shows no cut note when the list is not truncated", async () => {
    stub();
    renderWithRoutes(routes, "/mappings/new");
    await screen.findByRole("list", { name: t("mapping.picker.projectList") });
    expect(screen.queryByText(t("mapping.picker.cut"))).not.toBeInTheDocument();
  });

  it("clears the repository when a different project is picked", async () => {
    stub();
    renderWithRoutes(routes, "/mappings/new");
    await pickProject("nrosier");
    const repos = await screen.findByRole("list", { name: t("mapping.picker.repositoryList") });
    await userEvent.click(within(repos).getByRole("button", { name: "walley" }));
    expect(screen.getByLabelText(t("mappings.form.harborRepository"))).toHaveValue("walley");
    await pickProject("library");
    expect(screen.getByLabelText(t("mappings.form.harborRepository"))).toHaveValue("");
    expect(screen.getByLabelText(t("mappings.form.harborProject"))).toHaveValue("library");
  });

  it("clears the picks when the Harbor credential changes and lists the new instance", async () => {
    const fetchMock = stub();
    renderWithRoutes(routes, "/mappings/new");
    await pickProject("nrosier");
    await waitFor(() => expect(screen.getByLabelText(t("mappings.form.harborCredential"))).toHaveValue("hc1"));
    await userEvent.selectOptions(screen.getByLabelText(t("mappings.form.harborCredential")), "hc2");
    expect(screen.getByLabelText(t("mappings.form.harborProject"))).toHaveValue("");
    await waitFor(() => expect(calls(fetchMock, "/credentials/hc2/harbor-projects?").length).toBeGreaterThan(0));
    expect(screen.queryByRole("list", { name: t("mapping.picker.repositoryList") })).not.toBeInTheDocument();
  });

  it("still accepts typed entry", async () => {
    stub();
    renderWithRoutes(routes, "/mappings/new");
    await userEvent.type(await screen.findByLabelText(t("mappings.form.harborProject")), "typed-project");
    await userEvent.type(screen.getByLabelText(t("mappings.form.harborRepository")), "typed-repo");
    expect(screen.getByLabelText(t("mappings.form.harborProject"))).toHaveValue("typed-project");
    expect(screen.getByLabelText(t("mappings.form.harborRepository"))).toHaveValue("typed-repo");
  });

  it("the edit form shows the current values even when absent from the lists", async () => {
    stub();
    renderWithRoutes(routes, "/mappings/m1");
    expect(await screen.findByLabelText(t("mappings.form.harborProject"))).toHaveValue("gone-project");
    expect(screen.getByLabelText(t("mappings.form.harborRepository"))).toHaveValue("gone-repo");
    expect(screen.getByLabelText(t("mappings.form.githubOwner"))).toHaveValue("old-org");
    expect(screen.getAllByText(t("mapping.picker.saved", { value: "gone-project/gone-repo" })).length).toBeGreaterThan(0);
  });

  it("hides a Harbor project with the picked credential's base URL, then refreshes", async () => {
    const hide = vi.fn(() => json({ id: "h1", source: "harbor", full_name: "library", harbor_base_url: HARBOR_A.base_url, created_at: "2026-11-05T10:00:00Z" }, 201));
    const fetchMock = stub({ hide });
    renderWithRoutes(routes, "/mappings/new");
    const list = await screen.findByRole("list", { name: t("mapping.picker.projectList") });
    await waitFor(() => expect(screen.getByLabelText(t("mappings.form.harborCredential"))).toHaveValue("hc1"));
    const before = calls(fetchMock, "harbor-projects?").length;
    await userEvent.click(within(list).getByRole("button", { name: `${t("mapping.hide.action")}library` }));
    await waitFor(() => expect(hide).toHaveBeenCalledWith({ source: "harbor", full_name: "library", harbor_base_url: HARBOR_A.base_url }));
    await waitFor(() => expect(calls(fetchMock, "harbor-projects?").length).toBeGreaterThan(before));
  });
});

describe("GitHub picker", () => {
  beforeEach(() => { vi.stubGlobal("ResizeObserver", NoopResizeObserver); });
  afterEach(() => { vi.unstubAllGlobals(); });

  it("always shows the org note, with the private and archived flags as text", async () => {
    stub();
    renderWithRoutes(routes, "/mappings/new");
    const table = await screen.findByRole("table");
    expect(screen.getByText(t("mapping.github.orgNote"))).toBeInTheDocument();
    expect(screen.queryByText(t("mapping.github.cut"))).not.toBeInTheDocument();
    expect(within(table).getByText(t("mapping.github.private"))).toBeInTheDocument();
    expect(within(table).getByText(t("mapping.github.public"))).toBeInTheDocument();
    expect(within(table).getByText(t("mapping.github.archived"))).toBeInTheDocument();
    expect(screen.getByText(t("mapping.github.count", { count: 2 }))).toBeInTheDocument();
  });

  it("shows the cut note only when truncated", async () => {
    stub({ github: () => json(page([{ owner: "a", repo: "b", full_name: "a/b", private: false, archived: false }], { truncated: true })) });
    renderWithRoutes(routes, "/mappings/new");
    expect(await screen.findByText(t("mapping.github.cut"))).toBeInTheDocument();
    expect(screen.getByText(t("mapping.github.orgNote"))).toBeInTheDocument();
  });

  it("Use fills the owner and repository fields", async () => {
    stub();
    renderWithRoutes(routes, "/mappings/new");
    await userEvent.click(await screen.findByRole("button", { name: t("mapping.github.useNamed", { name: "nrosier/walley" }) }));
    expect(screen.getByLabelText(t("mappings.form.githubOwner"))).toHaveValue("nrosier");
    expect(screen.getByLabelText(t("mappings.form.githubRepository"))).toHaveValue("walley");
  });

  it("Hide posts the GitHub item without a base URL and refreshes the list", async () => {
    const hide = vi.fn(() => json({ id: "h1", source: "github", full_name: "nrosier/walley", harbor_base_url: null, created_at: "2026-11-05T10:00:00Z" }, 201));
    const fetchMock = stub({ hide });
    renderWithRoutes(routes, "/mappings/new");
    const before = calls(fetchMock, "github-repositories").length;
    await userEvent.click(await screen.findByRole("button", { name: `${t("mapping.hide.action")}nrosier/walley` }));
    await waitFor(() => expect(hide).toHaveBeenCalledWith({ source: "github", full_name: "nrosier/walley" }));
    await waitFor(() => expect(calls(fetchMock, "github-repositories").length).toBeGreaterThan(before));
  });

  it("shows the cap message for a 422 on hide", async () => {
    stub({ hide: () => json({ error: { code: "validation_failed", message: "RAW SERVER CAP TEXT" } }, 422) });
    renderWithRoutes(routes, "/mappings/new");
    await userEvent.click(await screen.findByRole("button", { name: `${t("mapping.hide.action")}nrosier/walley` }));
    expect(await screen.findByText(t("mapping.hide.cap"))).toBeInTheDocument();
    expect(screen.queryByText("RAW SERVER CAP TEXT")).not.toBeInTheDocument();
  });
});

const suggestion = (listed: boolean | null) =>
  json({ suggestion: { github_owner: "acme-corp", github_repo: "platform", image_tag: "v1.2", github_listed: listed }, reason: null });

async function pickRepository() {
  await pickProject("nrosier");
  const repos = await screen.findByRole("list", { name: t("mapping.picker.repositoryList") });
  await userEvent.click(within(repos).getByRole("button", { name: "walley" }));
}

describe("Source suggestion", () => {
  beforeEach(() => { vi.stubGlobal("ResizeObserver", NoopResizeObserver); });
  afterEach(() => { vi.unstubAllGlobals(); });

  it("state A: listed pill, built URL, no note; sends github_cred_id", async () => {
    const fetchMock = stub({ suggestion: () => suggestion(true) });
    renderWithRoutes(routes, "/mappings/new");
    await pickRepository();
    expect(await screen.findByText(t("mapping.suggest.listed"))).toBeInTheDocument();
    expect(screen.getByText(t("mapping.suggest.source", { url: "https://github.com/acme-corp/platform" }))).toBeInTheDocument();
    expect(screen.queryByText(t("mapping.suggest.notListedNote"))).not.toBeInTheDocument();
    const url = calls(fetchMock, "source-suggestion")[0];
    expect(url).toContain("project=nrosier");
    expect(url).toContain("repository=walley");
    expect(url).toContain("github_cred_id=gc1");
  });

  it("state B: not-listed pill and the note", async () => {
    stub({ suggestion: () => suggestion(false) });
    renderWithRoutes(routes, "/mappings/new");
    await pickRepository();
    expect(await screen.findByText(t("mapping.suggest.notListed"))).toBeInTheDocument();
    expect(screen.getByText(t("mapping.suggest.notListedNote"))).toBeInTheDocument();
  });

  it("a null suggestion shows no panel", async () => {
    const fetchMock = stub();
    renderWithRoutes(routes, "/mappings/new");
    await pickRepository();
    await waitFor(() => expect(calls(fetchMock, "source-suggestion")).toHaveLength(1));
    expect(screen.queryByRole("region", { name: t("mapping.suggest.title") })).not.toBeInTheDocument();
  });

  it("Confirm fills the fields and saves nothing", async () => {
    const fetchMock = stub({ suggestion: () => suggestion(true) });
    renderWithRoutes(routes, "/mappings/new");
    await pickRepository();
    await userEvent.click(await screen.findByRole("button", { name: t("mapping.suggest.confirm") }));
    expect(screen.getByLabelText(t("mappings.form.githubOwner"))).toHaveValue("acme-corp");
    expect(screen.getByLabelText(t("mappings.form.githubRepository"))).toHaveValue("platform");
    const writes = fetchMock.mock.calls.filter((c) => ((c[1] as RequestInit | undefined)?.method ?? "GET") !== "GET");
    expect(writes).toEqual([]);
  });

  it("Dismiss hides the panel for that pair", async () => {
    stub({ suggestion: () => suggestion(true) });
    renderWithRoutes(routes, "/mappings/new");
    await pickRepository();
    await userEvent.click(await screen.findByRole("button", { name: t("mapping.suggest.dismiss") }));
    expect(screen.queryByRole("button", { name: t("mapping.suggest.confirm") })).not.toBeInTheDocument();
  });
});

describe("Picker errors", () => {
  beforeEach(() => { vi.stubGlobal("ResizeObserver", NoopResizeObserver); });
  afterEach(() => { vi.unstubAllGlobals(); });

  it("429 shows the fixed message and a countdown, and makes no automatic second request", async () => {
    const fetchMock = stub({
      projects: () =>
        new Response(JSON.stringify({ error: { code: "rate_limited", message: "RAW HARBOR TEXT" } }), {
          status: 429,
          headers: { "Content-Type": "application/json", "Retry-After": "900" },
        }),
    });
    renderWithRoutes(routes, "/mappings/new");
    expect(await screen.findByText(t("mapping.errors.rateLimit.message"))).toBeInTheDocument();
    expect(screen.getByRole("button", { name: t("mapping.errors.rateLimit.wait", { time: "15:00" }) })).toBeDisabled();
    await new Promise((resolve) => setTimeout(resolve, 600));
    expect(calls(fetchMock, "harbor-projects?")).toHaveLength(1);
    expect(screen.queryByText("RAW HARBOR TEXT")).not.toBeInTheDocument();
  });

  it("502 shows the fixed message and a manual try-again that refetches once", async () => {
    let n = 0;
    const fetchMock = stub({
      projects: () => (n++ === 0 ? json({ error: { code: "upstream_unreachable", message: "RAW 502 TEXT" } }, 502) : json(page([{ name: "back" }]))),
    });
    renderWithRoutes(routes, "/mappings/new");
    expect(await screen.findByText(t("mapping.errors.upstream.message"))).toBeInTheDocument();
    expect(calls(fetchMock, "harbor-projects?")).toHaveLength(1);
    await userEvent.click(screen.getByRole("button", { name: t("mapping.errors.tryAgain") }));
    expect(await screen.findByRole("button", { name: "back" })).toBeInTheDocument();
    expect(calls(fetchMock, "harbor-projects?")).toHaveLength(2);
  });

  it.each([
    ["harbor_identity", "mapping.errors.detail.harborIdentity"],
    ["robot_scope", "mapping.errors.detail.robotScope"],
    ["github_token", "mapping.errors.detail.githubToken"],
    ["wrong_credential_type", "mapping.errors.detail.wrongCredentialType"],
  ] as const)("422 with detail %s shows its catalog message, not the server text", async (detail, key) => {
    stub({
      projects: () => json({ error: { code: "validation_failed", message: "RAW SERVER TEXT", detail } }, 422),
    });
    renderWithRoutes(routes, "/mappings/new");
    const alert = await screen.findByText(t(key));
    expect(alert.closest("[role=alert]")).not.toBeNull();
    expect(screen.queryByText("RAW SERVER TEXT")).not.toBeInTheDocument();
  });
});
