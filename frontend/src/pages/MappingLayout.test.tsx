import { act, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { t } from "../i18n";
import { json, renderWithRoutes, stubApi, user } from "../test/render";
import type { Mapping } from "../types/api";
import { INPUT } from "../components/mappings/styles";
import MappingFormPage from "./MappingFormPage";

const cred = (id: string, type: string) => ({
  id, service_type: type, label: `${type}-cred`, base_url: type === "harbor" ? "https://harbor.example.org" : null,
  username: null, expires_at: null, created_at: null,
});
const list = <T,>(items: T[]) => ({ items, page: 1, page_size: 50, total: items.length, truncated: false });
const other: Mapping = {
  id: "m9", user_id: "u2", harbor_cred_id: "hc", github_cred_id: "gc", harbor_base_url: "https://harbor.example.org",
  harbor_project: "x", harbor_repository: "y", github_owner: "o", github_repo: "r", default_branch: "main",
  auto_create_issues: true, min_issue_severity: "HIGH", created_at: null,
};

function stub() {
  return stubApi((path, init) => {
    const url = new URL(path, "http://x");
    const p = url.pathname;
    if (p === "/api/v1/account/me") return json({ user: user("user") });
    if (p === "/api/v1/credentials" && url.searchParams.get("service_type") === "harbor") return json(list([cred("hc", "harbor")]));
    if (p === "/api/v1/credentials" && url.searchParams.get("service_type") === "github") return json(list([cred("gc", "github")]));
    if (p === "/api/v1/mappings" && (init?.method ?? "GET") === "GET") return json(list([]));
    if (p === "/api/v1/mappings/m9") return json(other);
    if (p === "/api/v1/credentials/hc/harbor-projects") {
      const q = url.searchParams.get("q");
      const all = [{ name: "library" }, { name: "nrosier" }];
      return json(list(q === null ? all : all.filter((x) => x.name.includes(q))));
    }
    if (/\/repositories$/.test(p)) return json(list([{ project: "nrosier", repository: "walley", full_name: "nrosier/walley" }]));
    if (p.endsWith("/github-repositories")) return json(list([]));
    return undefined;
  });
}

const routes = [
  { path: "/mappings/new", element: <MappingFormPage /> },
  { path: "/mappings/:id", element: <MappingFormPage /> },
  { path: "/mappings", element: <output>list</output> },
];

class NoopResizeObserver { observe() {} unobserve() {} disconnect() {} }

describe("Mapping screen layout (#167)", () => {
  beforeEach(() => { vi.stubGlobal("ResizeObserver", NoopResizeObserver); });
  afterEach(() => { vi.unstubAllGlobals(); });

  it("puts the Harbor source and the GitHub target in two columns of one grid", async () => {
    stub();
    renderWithRoutes(routes, "/mappings/new");
    const harbor = (await screen.findByText(t("mappings.form.harborSection"))).closest("[role=group]");
    const github = screen.getByText(t("mappings.form.githubSection")).closest("[role=group]");
    expect(harbor).not.toBeNull();
    expect(github).not.toBeNull();
    expect(harbor?.parentElement).toBe(github?.parentElement);
    expect(harbor?.parentElement?.className).toContain("md:grid-cols-2");
    expect(harbor?.parentElement?.className).toContain("grid-cols-1");
    expect(within(harbor as HTMLElement).getByLabelText(t("mappings.form.harborCredential"))).toBeInTheDocument();
    expect(within(harbor as HTMLElement).getByLabelText(t("mappings.form.harborProject"))).toBeInTheDocument();
    expect(within(harbor as HTMLElement).getByLabelText(t("mappings.form.harborRepository"))).toBeInTheDocument();
    expect(within(github as HTMLElement).getByLabelText(t("mappings.form.githubCredential"))).toBeInTheDocument();
    expect(within(github as HTMLElement).getByLabelText(t("mappings.form.githubRepository"))).toBeInTheDocument();
    expect(within(github as HTMLElement).getByLabelText(t("mappings.form.defaultBranch"))).toBeInTheDocument();
  });

  it("gives the six controls the shared input height class and lines the columns up row by row", async () => {
    stub();
    renderWithRoutes(routes, "/mappings/new");
    await screen.findByLabelText(t("mappings.form.harborProject"));
    const height = INPUT.split(" ").find((c) => c.startsWith("min-h-"));
    expect(height).toBe("min-h-9");
    const labels = [
      "mappings.form.harborCredential", "mappings.form.harborProject", "mappings.form.harborRepository",
      "mappings.form.githubCredential", "mappings.form.githubRepository", "mappings.form.defaultBranch",
    ] as const;
    for (const key of labels) {
      expect(screen.getByLabelText(t(key)).className.split(" ")).toContain(height);
    }
    const harbor = screen.getByText(t("mappings.form.harborSection")).closest("[role=group]");
    const github = screen.getByText(t("mappings.form.githubSection")).closest("[role=group]");
    expect(harbor?.className).toContain("md:grid-rows-subgrid");
    expect(github?.className).toContain("md:grid-rows-subgrid");
    expect(harbor?.children.length).toBe(github?.children.length);
  });

  it("the form card does not clip its popups (#167)", async () => {
    stub();
    renderWithRoutes(routes, "/mappings/new");
    const input = await screen.findByLabelText(t("mappings.form.harborProject"));
    const card = screen.getByText(t("mappings.form.harborSection")).closest("[role=group]")?.parentElement as HTMLElement;
    expect(card.className.split(" ")).not.toContain("overflow-hidden");
    await userEvent.click(input);
    const listbox = await screen.findByRole("listbox", { name: t("mapping.picker.projectList") });
    // No ancestor of the open popup clips it.
    for (let node: HTMLElement | null = listbox; node !== null; node = node.parentElement) {
      expect(node.className.split(" ")).not.toContain("overflow-hidden");
    }
  });

  it("the GitHub org note is a tooltip on the repository label, not a banner", async () => {
    stub();
    renderWithRoutes(routes, "/mappings/new");
    const github = (await screen.findByText(t("mappings.form.githubSection"))).closest("[role=group]") as HTMLElement;
    const note = t("mapping.github.orgNote");
    const trigger = within(github).getByRole("button", { name: t("mapping.github.orgNoteLabel") });
    const tip = document.getElementById(trigger.getAttribute("aria-describedby") ?? "");
    expect(tip).toHaveTextContent(note);
    expect(tip).not.toBeVisible();
    expect(screen.queryByText(note, { selector: "p, div" })).not.toBeInTheDocument();
    act(() => trigger.focus());
    expect(tip).toBeVisible();
    await userEvent.keyboard("{Escape}");
    expect(tip).not.toBeVisible();
  });

  it("the project combobox filters as the user types and sends the search", async () => {
    const fetchMock = stub();
    renderWithRoutes(routes, "/mappings/new");
    const input = await screen.findByLabelText(t("mappings.form.harborProject"));
    expect(input).toHaveAttribute("role", "combobox");
    await userEvent.type(input, "lib");
    const box = await screen.findByRole("listbox", { name: t("mapping.picker.projectList") });
    await waitFor(() => expect(within(box).queryByRole("option", { name: "nrosier" })).not.toBeInTheDocument());
    expect(within(box).getByRole("option", { name: "library" })).toBeInTheDocument();
    expect(fetchMock.mock.calls.some(([u]) => String(u).includes("harbor-projects?") && String(u).includes("q=lib"))).toBe(true);
  });

  it("keyboard: arrows and Enter choose a project, Escape closes the list", async () => {
    stub();
    renderWithRoutes(routes, "/mappings/new");
    const input = await screen.findByLabelText(t("mappings.form.harborProject"));
    await userEvent.click(input);
    await screen.findByRole("option", { name: "library" });
    await userEvent.keyboard("{ArrowDown}{ArrowDown}{Enter}");
    expect(input).toHaveValue("nrosier");
    await userEvent.click(input);
    await userEvent.keyboard("{Escape}");
    expect(screen.queryByRole("listbox", { name: t("mapping.picker.projectList") })).not.toBeInTheDocument();
  });

  it("a typed project and repository outside the list still save", async () => {
    const fetchMock = stub();
    renderWithRoutes(routes, "/mappings/new");
    await userEvent.type(await screen.findByLabelText(t("mappings.form.harborProject")), "not-listed");
    await userEvent.type(screen.getByLabelText(t("mappings.form.harborRepository")), "typed-repo");
    await userEvent.type(screen.getByLabelText(t("mappings.form.githubRepository")), "acme/app");
    await waitFor(() => expect(screen.getByLabelText(t("mappings.form.githubCredential"))).toHaveValue("gc"));
    await userEvent.click(screen.getByRole("button", { name: t("mappings.form.save") }));
    await waitFor(() => {
      const post = fetchMock.mock.calls.find(([u, i]) => String(u) === "/api/v1/mappings" && (i as RequestInit | undefined)?.method === "POST");
      expect(post).toBeDefined();
      expect(JSON.parse(String((post?.[1] as RequestInit | undefined)?.body))).toMatchObject({
        harbor_project: "not-listed", harbor_repository: "typed-repo", github_owner: "acme", github_repo: "app",
      });
    });
  });

  it("choosing a project clears the repository", async () => {
    stub();
    renderWithRoutes(routes, "/mappings/new");
    await userEvent.type(await screen.findByLabelText(t("mappings.form.harborRepository")), "typed-repo");
    await userEvent.click(screen.getByLabelText(t("mappings.form.harborProject")));
    await userEvent.click(await screen.findByRole("option", { name: "library" }));
    expect(screen.getByLabelText(t("mappings.form.harborRepository"))).toHaveValue("");
  });

  it("the automation panel has no Issues heading", async () => {
    stub();
    renderWithRoutes(routes, "/mappings/new");
    await screen.findByRole("switch", { name: t("mappings.form.autoCreate") });
    expect(screen.queryByRole("heading", { name: "Issues" })).not.toBeInTheDocument();
  });

  it("the automation panel keeps the switch and the minimum severity", async () => {
    stub();
    renderWithRoutes(routes, "/mappings/new");
    const sw = await screen.findByRole("switch", { name: t("mappings.form.autoCreate") });
    const critical = screen.getByRole("button", { name: t("mappings.form.sevCritical") });
    expect(critical).toBeEnabled();
    await userEvent.click(critical);
    expect(critical).toHaveAttribute("aria-pressed", "true");
    await userEvent.click(sw);
    expect(critical).toBeDisabled();
  });

  it("Cancel goes back to the list and Save is disabled until the form is filled", async () => {
    stub();
    const { router } = renderWithRoutes(routes, "/mappings/new");
    expect(await screen.findByRole("button", { name: t("mappings.form.save") })).toBeDisabled();
    await userEvent.click(screen.getByRole("link", { name: t("mappings.cancel") }));
    expect(router.state.location.pathname).toBe("/mappings");
  });

  it("shows no read-only note, and no actions, for another user's mapping", async () => {
    stub();
    renderWithRoutes(routes, "/mappings/m9");
    await screen.findByLabelText(t("mappings.form.harborProject"));
    expect(screen.queryByText(t("mappings.form.readOnly"))).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: t("mappings.form.save") })).not.toBeInTheDocument();
  });
});
