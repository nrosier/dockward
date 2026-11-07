import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { t } from "../i18n";
import { json, renderWithRoutes, stubApi, user } from "../test/render";
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
  extraGithub?: boolean;
  // Signs in as the mapping owner, so the edit form is not read-only.
  owner?: boolean;
}

function stub(opts: Opts = {}) {
  return stubApi((path, init) => {
    const url = new URL(path, "http://x");
    const p = url.pathname;
    if (opts.owner === true && p === "/api/v1/account/me") return json({ user: user("user") });
    if (p === "/api/v1/credentials" && url.searchParams.get("service_type") === "harbor") return json(listResp([HARBOR_A, HARBOR_B]));
    if (p === "/api/v1/credentials" && url.searchParams.get("service_type") === "github") return json(listResp(opts.extraGithub === true ? [GITHUB, { ...GITHUB, id: "gc2", label: "gh-other" }] : [GITHUB]));
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
    if (/^\/api\/v1\/credentials\/gc\d\/github-repositories$/.test(p)) {
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

// The Harbor fields are comboboxes: focusing the input opens the list.
async function openProjects() {
  await userEvent.click(await screen.findByLabelText(t("mappings.form.harborProject")));
  return screen.findByRole("listbox", { name: t("mapping.picker.projectList") });
}

async function openRepositories() {
  await userEvent.click(screen.getByLabelText(t("mappings.form.harborRepository")));
  return screen.findByRole("listbox", { name: t("mapping.picker.repositoryList") });
}

async function pickProject(name: string) {
  const list = await openProjects();
  await userEvent.click(await within(list).findByRole("option", { name }));
}

describe("Mapping form pickers", () => {
  beforeEach(() => { vi.stubGlobal("ResizeObserver", NoopResizeObserver); });
  afterEach(() => { vi.unstubAllGlobals(); });

  it("loads the project list once a credential is picked, and the repository list from a project", async () => {
    const fetchMock = stub();
    renderWithRoutes(routes, "/mappings/new");
    await pickProject("nrosier");
    const repos = await openRepositories();
    // The repository is shown without the project prefix.
    expect(within(repos).getByRole("option", { name: "walley" })).toBeInTheDocument();
    expect(calls(fetchMock, "/credentials/hc1/harbor-projects?")[0]).toContain("page_size=50");
    await userEvent.click(within(repos).getByRole("option", { name: "walley" }));
    // The saved value keeps project/repository.
    expect(screen.getByLabelText(t("mappings.form.harborProject"))).toHaveValue("nrosier");
    expect(screen.getByLabelText(t("mappings.form.harborRepository"))).toHaveValue("walley");
  });

  it("the Harbor repository is disabled until a project has a value, then enabled", async () => {
    stub();
    renderWithRoutes(routes, "/mappings/new");
    const repository = await screen.findByLabelText(t("mappings.form.harborRepository"));
    expect(repository).toBeDisabled();
    await pickProject("nrosier");
    expect(screen.getByLabelText(t("mappings.form.harborRepository"))).toBeEnabled();
  });

  it("opens the repository list only from a picked project", async () => {
    const fetchMock = stub();
    renderWithRoutes(routes, "/mappings/new");
    await openProjects();
    await userEvent.click(screen.getByLabelText(t("mappings.form.harborRepository")));
    expect(screen.queryByRole("listbox", { name: t("mapping.picker.repositoryList") })).not.toBeInTheDocument();
    expect(calls(fetchMock, "/repositories")).toEqual([]);
  });

  it("sends q after the debounce, one request for a burst of typing", async () => {
    const fetchMock = stub();
    renderWithRoutes(routes, "/mappings/new");
    await openProjects();
    await userEvent.type(screen.getByLabelText(t("mappings.form.harborProject")), "lib");
    await waitFor(() => expect(calls(fetchMock, "q=lib")).toHaveLength(1));
    expect(calls(fetchMock, "q=l&")).toEqual([]);
    expect(calls(fetchMock, "q=li&")).toEqual([]);
  });

  it("changes the request when paging", async () => {
    const fetchMock = stub({ projects: () => json(page([{ name: "a" }], { total: 120 })) });
    renderWithRoutes(routes, "/mappings/new");
    await openProjects();
    const nav = (await screen.findAllByRole("navigation", { name: t("pagination.label") }))[0];
    await userEvent.click(within(nav).getByRole("button", { name: t("pagination.next") }));
    await waitFor(() => expect(calls(fetchMock, "harbor-projects?").some((u) => u.includes("page=2"))).toBe(true));
  });

  it("shows the cut note only when truncated is true", async () => {
    stub({ projects: () => json(page([{ name: "a" }], { truncated: true })) });
    renderWithRoutes(routes, "/mappings/new");
    await openProjects();
    expect(await screen.findByText(t("mapping.picker.cut"))).toBeInTheDocument();
  });

  it("shows no cut note when the list is not truncated", async () => {
    stub();
    renderWithRoutes(routes, "/mappings/new");
    await openProjects();
    expect(screen.queryByText(t("mapping.picker.cut"))).not.toBeInTheDocument();
  });

  it("clears the repository when a different project is picked", async () => {
    stub();
    renderWithRoutes(routes, "/mappings/new");
    await pickProject("nrosier");
    const repos = await openRepositories();
    await userEvent.click(within(repos).getByRole("option", { name: "walley" }));
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
    await userEvent.click(screen.getByLabelText(t("mappings.form.harborRepository")));
    expect(screen.queryByRole("listbox", { name: t("mapping.picker.repositoryList") })).not.toBeInTheDocument();
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
    expect(screen.getByLabelText(t("mappings.form.githubRepository"))).toHaveValue("old-org/old-repo");
  });

  it("hides a Harbor project with the picked credential's base URL, then refreshes", async () => {
    const hide = vi.fn(() => json({ id: "h1", source: "harbor", full_name: "library", harbor_base_url: HARBOR_A.base_url, created_at: "2026-11-05T10:00:00Z" }, 201));
    const fetchMock = stub({ hide });
    renderWithRoutes(routes, "/mappings/new");
    const list = await openProjects();
    await waitFor(() => expect(screen.getByLabelText(t("mappings.form.harborCredential"))).toHaveValue("hc1"));
    const before = calls(fetchMock, "harbor-projects?").length;
    await userEvent.click(within(list).getByRole("button", { name: `${t("mapping.hide.action")}library` }));
    await waitFor(() => expect(hide).toHaveBeenCalledWith({ source: "harbor", full_name: "library", harbor_base_url: HARBOR_A.base_url }));
    await waitFor(() => expect(calls(fetchMock, "harbor-projects?").length).toBeGreaterThan(before));
  });

  describe("already mapped repositories (#189)", () => {
    const repos = () =>
      json(page([
        { project: "nrosier", repository: "walley", full_name: "nrosier/walley", mapped: true },
        { project: "nrosier", repository: "astraya", full_name: "nrosier/astraya", mapped: false },
      ]));

    it("greys out a mapped repository with the note, and it cannot be picked", async () => {
      stub({ repos });
      renderWithRoutes(routes, "/mappings/new");
      await pickProject("nrosier");
      const list = await openRepositories();
      const taken = within(list).getByRole("option", { name: new RegExp(`^walley\\s*${t("mapping.picker.alreadyMapped")}$`) });
      expect(taken).toHaveAttribute("aria-disabled", "true");
      expect(within(taken).getByText(t("mapping.picker.alreadyMapped"))).toBeInTheDocument();
      await userEvent.click(taken);
      expect(screen.getByLabelText(t("mappings.form.harborRepository"))).toHaveValue("");
      // Not hidden: still in the list after the click.
      expect(within(list).getByRole("option", { name: new RegExp("^walley") })).toBeInTheDocument();
    });

    it("lists an unmapped repository as before, and it can be picked", async () => {
      stub({ repos });
      renderWithRoutes(routes, "/mappings/new");
      await pickProject("nrosier");
      const list = await openRepositories();
      const free = within(list).getByRole("option", { name: "astraya" });
      expect(free).not.toHaveAttribute("aria-disabled");
      expect(within(free).queryByText(t("mapping.picker.alreadyMapped"))).not.toBeInTheDocument();
      await userEvent.click(free);
      expect(screen.getByLabelText(t("mappings.form.harborRepository"))).toHaveValue("astraya");
    });

    it("keeps a mapped repository unpickable from the keyboard", async () => {
      stub({ repos });
      renderWithRoutes(routes, "/mappings/new");
      await pickProject("nrosier");
      await openRepositories();
      await userEvent.keyboard("{ArrowDown}{Enter}");
      expect(screen.getByLabelText(t("mappings.form.harborRepository"))).toHaveValue("");
    });

    it("the edit form keeps its own repository pickable, and shows its current value", async () => {
      stub({
        owner: true,
        projects: () => json(page([{ name: "gone-project" }])),
        repos: () =>
          json(page([
            { project: "gone-project", repository: "gone-repo", full_name: "gone-project/gone-repo", mapped: true },
            { project: "gone-project", repository: "other", full_name: "gone-project/other", mapped: true },
          ])),
      });
      renderWithRoutes(routes, "/mappings/m1");
      expect(await screen.findByLabelText(t("mappings.form.harborRepository"))).toHaveValue("gone-repo");
      await pickProject("gone-project");
      const list = await openRepositories();
      const own = within(list).getByRole("option", { name: "gone-repo" });
      expect(own).not.toHaveAttribute("aria-disabled");
      expect(within(list).getByRole("option", { name: new RegExp("^other") })).toHaveAttribute("aria-disabled", "true");
      await userEvent.click(own);
      expect(screen.getByLabelText(t("mappings.form.harborRepository"))).toHaveValue("gone-repo");
    });
  });
});

const GITHUB_LABEL = () => t("mappings.form.githubRepository");

// The list is off until the default GitHub credential is filled in.
async function openGitHub() {
  const input = await screen.findByLabelText(GITHUB_LABEL());
  await waitFor(() => expect(screen.getByLabelText(t("mappings.form.githubCredential"))).toHaveValue("gc1"));
  await userEvent.click(input);
  return screen.findByRole("listbox", { name: t("mapping.github.list") });
}

describe("GitHub repository combobox", () => {
  beforeEach(() => { vi.stubGlobal("ResizeObserver", NoopResizeObserver); });
  afterEach(() => { vi.unstubAllGlobals(); });

  it("opens the list on click and shows the repositories, with no table", async () => {
    stub();
    renderWithRoutes(routes, "/mappings/new");
    const input = await screen.findByLabelText(GITHUB_LABEL());
    expect(input).toHaveAttribute("role", "combobox");
    const box = await openGitHub();
    expect(within(box).getByRole("option", { name: /nrosier\/walley/ })).toBeInTheDocument();
    expect(within(box).getByRole("option", { name: /nrosier\/old-service/ })).toBeInTheDocument();
    expect(screen.queryByRole("table")).not.toBeInTheDocument();
  });

  it("opens the list on focus", async () => {
    stub();
    renderWithRoutes(routes, "/mappings/new");
    const input = await screen.findByLabelText(GITHUB_LABEL());
    await waitFor(() => expect(screen.getByLabelText(t("mappings.form.githubCredential"))).toHaveValue("gc1"));
    input.focus();
    expect(await screen.findByRole("listbox", { name: t("mapping.github.list") })).toBeInTheDocument();
  });

  it("typing sends the search once after the debounce, not per keystroke", async () => {
    const fetchMock = stub({
      github: (url) => json(page(url.searchParams.get("q") === "old"
        ? [{ owner: "nrosier", repo: "old-service", full_name: "nrosier/old-service", private: true, archived: true }]
        : [])),
    });
    renderWithRoutes(routes, "/mappings/new");
    await openGitHub();
    await userEvent.type(screen.getByLabelText(GITHUB_LABEL()), "old");
    await waitFor(() => expect(calls(fetchMock, "github-repositories?q=old")).toHaveLength(0));
    await waitFor(() => expect(calls(fetchMock, "q=old")).toHaveLength(1));
    expect(calls(fetchMock, "q=o&")).toEqual([]);
    expect(calls(fetchMock, "q=ol&")).toEqual([]);
    const box = screen.getByRole("listbox", { name: t("mapping.github.list") });
    expect(await within(box).findByRole("option", { name: /old-service/ })).toBeInTheDocument();
  });

  it("keyboard: arrows move, Enter chooses, Escape closes", async () => {
    stub();
    renderWithRoutes(routes, "/mappings/new");
    const input = await screen.findByLabelText(GITHUB_LABEL());
    await openGitHub();
    await screen.findByRole("option", { name: /nrosier\/walley/ });
    await userEvent.keyboard("{ArrowDown}{ArrowDown}");
    expect(screen.getByRole("option", { name: /old-service/ })).toHaveAttribute("aria-selected", "true");
    await userEvent.keyboard("{ArrowUp}{Enter}");
    expect(input).toHaveValue("nrosier/walley");
    expect(screen.queryByRole("listbox", { name: t("mapping.github.list") })).not.toBeInTheDocument();
    await userEvent.click(input);
    expect(await screen.findByRole("listbox", { name: t("mapping.github.list") })).toBeInTheDocument();
    await userEvent.keyboard("{Escape}");
    expect(screen.queryByRole("listbox", { name: t("mapping.github.list") })).not.toBeInTheDocument();
  });

  it("choosing an item fills owner and repo, and the field reads owner/repo", async () => {
    const fetchMock = stub();
    renderWithRoutes(routes, "/mappings/new");
    await userEvent.type(await screen.findByLabelText(t("mappings.form.harborProject")), "p");
    await userEvent.type(screen.getByLabelText(t("mappings.form.harborRepository")), "r");
    const box = await openGitHub();
    await userEvent.click(within(box).getByRole("option", { name: /nrosier\/walley/ }));
    expect(screen.getByLabelText(GITHUB_LABEL())).toHaveValue("nrosier/walley");
    await waitFor(() => expect(screen.getByLabelText(t("mappings.form.githubCredential"))).toHaveValue("gc1"));
    await waitFor(() => expect(screen.getByLabelText(t("mappings.form.harborCredential"))).toHaveValue("hc1"));
    await userEvent.click(screen.getByRole("button", { name: t("mappings.form.save") }));
    await waitFor(() => {
      const post = fetchMock.mock.calls.find(([u, i]) => String(u) === "/api/v1/mappings" && (i as RequestInit | undefined)?.method === "POST");
      expect(JSON.parse(String((post?.[1] as RequestInit | undefined)?.body))).toMatchObject({ github_owner: "nrosier", github_repo: "walley" });
    });
  });

  it("a typed value that is not in the list still saves", async () => {
    const fetchMock = stub({ github: () => json(page([])) });
    renderWithRoutes(routes, "/mappings/new");
    await userEvent.type(await screen.findByLabelText(t("mappings.form.harborProject")), "p");
    await userEvent.type(screen.getByLabelText(t("mappings.form.harborRepository")), "r");
    await userEvent.type(screen.getByLabelText(GITHUB_LABEL()), "hidden-org/secret");
    await waitFor(() => expect(screen.getByLabelText(t("mappings.form.githubCredential"))).toHaveValue("gc1"));
    await waitFor(() => expect(screen.getByLabelText(t("mappings.form.harborCredential"))).toHaveValue("hc1"));
    await userEvent.click(screen.getByRole("button", { name: t("mappings.form.save") }));
    await waitFor(() => {
      const post = fetchMock.mock.calls.find(([u, i]) => String(u) === "/api/v1/mappings" && (i as RequestInit | undefined)?.method === "POST");
      expect(JSON.parse(String((post?.[1] as RequestInit | undefined)?.body))).toMatchObject({ github_owner: "hidden-org", github_repo: "secret" });
    });
  });

  it("choosing a different GitHub credential clears the pick", async () => {
    stub({ extraGithub: true });
    renderWithRoutes(routes, "/mappings/new");
    const box = await openGitHub();
    await userEvent.click(within(box).getByRole("option", { name: /nrosier\/walley/ }));
    expect(screen.getByLabelText(GITHUB_LABEL())).toHaveValue("nrosier/walley");
    await waitFor(() => expect(screen.getByLabelText(t("mappings.form.githubCredential"))).toHaveValue("gc1"));
    await userEvent.selectOptions(screen.getByLabelText(t("mappings.form.githubCredential")), "gc2");
    expect(screen.getByLabelText(GITHUB_LABEL())).toHaveValue("");
  });

  it("keeps the org note as a tooltip; the cut note only when truncated", async () => {
    stub();
    renderWithRoutes(routes, "/mappings/new");
    await screen.findByLabelText(GITHUB_LABEL());
    const trigger = screen.getByRole("button", { name: t("mapping.github.orgNoteLabel") });
    const tip = document.getElementById(trigger.getAttribute("aria-describedby") ?? "");
    expect(tip).toHaveTextContent(t("mapping.github.orgNote"));
    await openGitHub();
    expect(screen.queryByText(t("mapping.github.cut"))).not.toBeInTheDocument();
  });

  it("shows the cut note when truncated", async () => {
    stub({ github: () => json(page([{ owner: "a", repo: "b", full_name: "a/b", private: false, archived: false }], { truncated: true })) });
    renderWithRoutes(routes, "/mappings/new");
    await openGitHub();
    expect(await screen.findByText(t("mapping.github.cut"))).toBeInTheDocument();
  });

  it("renders the private, public and archived flags as text", async () => {
    stub();
    renderWithRoutes(routes, "/mappings/new");
    const box = await openGitHub();
    await within(box).findByRole("option", { name: /nrosier\/walley/ });
    expect(within(box).getByText(t("mapping.github.private"))).toBeInTheDocument();
    expect(within(box).getByText(t("mapping.github.public"))).toBeInTheDocument();
    expect(within(box).getByText(t("mapping.github.archived"))).toBeInTheDocument();
  });

  it("Hide posts the GitHub item without a base URL and refreshes the list", async () => {
    const hide = vi.fn(() => json({ id: "h1", source: "github", full_name: "nrosier/walley", harbor_base_url: null, created_at: "2026-11-05T10:00:00Z" }, 201));
    const fetchMock = stub({ hide });
    renderWithRoutes(routes, "/mappings/new");
    const box = await openGitHub();
    await within(box).findByRole("option", { name: /nrosier\/walley/ });
    const before = calls(fetchMock, "github-repositories").length;
    await userEvent.click(within(box).getByRole("button", { name: `${t("mapping.hide.action")}nrosier/walley` }));
    await waitFor(() => expect(hide).toHaveBeenCalledWith({ source: "github", full_name: "nrosier/walley" }));
    await waitFor(() => expect(calls(fetchMock, "github-repositories").length).toBeGreaterThan(before));
  });

  it("shows the cap message for a 422 on hide", async () => {
    stub({ hide: () => json({ error: { code: "validation_failed", message: "RAW SERVER CAP TEXT" } }, 422) });
    renderWithRoutes(routes, "/mappings/new");
    const box = await openGitHub();
    await userEvent.click(await within(box).findByRole("button", { name: `${t("mapping.hide.action")}nrosier/walley` }));
    expect(await screen.findByText(t("mapping.hide.cap"))).toBeInTheDocument();
    expect(screen.queryByText("RAW SERVER CAP TEXT")).not.toBeInTheDocument();
  });
});

const suggestion = (listed: boolean | null) =>
  json({ suggestion: { github_owner: "acme-corp", github_repo: "platform", image_tag: "v1.2", github_listed: listed }, reason: null });

async function pickRepository() {
  await pickProject("nrosier");
  const repos = await openRepositories();
  await userEvent.click(within(repos).getByRole("option", { name: "walley" }));
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
    expect(screen.getByLabelText(t("mappings.form.githubRepository"))).toHaveValue("acme-corp/platform");
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
    await openProjects();
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
    await openProjects();
    expect(await screen.findByText(t("mapping.errors.upstream.message"))).toBeInTheDocument();
    expect(calls(fetchMock, "harbor-projects?")).toHaveLength(1);
    await userEvent.click(screen.getByRole("button", { name: t("mapping.errors.tryAgain") }));
    expect(await screen.findByRole("option", { name: "back" })).toBeInTheDocument();
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
    await openProjects();
    const alert = await screen.findByText(t(key));
    expect(alert.closest("[role=alert]")).not.toBeNull();
    expect(screen.queryByText("RAW SERVER TEXT")).not.toBeInTheDocument();
  });
});
