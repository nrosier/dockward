import { fireEvent, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { t } from "../i18n";
import { json, renderWithRoutes, stubApi } from "../test/render";
import type { Hub, Source, SourceImage } from "../types/sources";
import SourceFormPage from "./SourceFormPage";
import SourcesPage from "./SourcesPage";

const hubs: Hub[] = [
  { id: "h1", host: "ghcr.io", pull_endpoint: null, kind: "default" },
  { id: "h2", host: "docker.io", pull_endpoint: null, kind: "default" },
];

function source(id: string, repository: string, tag: string, hubId = "h1"): Source {
  return {
    id,
    user_id: "u1",
    hub_id: hubId,
    repository,
    name: null,
    tag_value: tag,
    github_cred_id: "c1",
    github_owner: "acme",
    github_repo: "app",
    default_branch: "main",
    auto_create_issues: false,
    min_issue_severity: "CRITICAL",
    has_credential: false,
    last_discovery_at: 1_700_000_000,
  };
}

const page = <T,>(items: T[]) => ({ items, page: 1, page_size: 200, total: items.length });

const images: SourceImage[] = [
  {
    id: "i1",
    digest: "sha256:aa",
    tags: ["1.0.0"],
    platforms: [
      {
        id: "p1",
        platform: "linux/amd64",
        state: "stored",
        size_bytes: 10,
        pulled_at: 1_700_000_000,
        scans: [
          { scanner: "grype", status: "done", version: "1", error: null, db_built_at: null },
          { scanner: "trivy", status: "running", version: "1", error: null, db_built_at: null },
        ],
      },
      { id: "p2", platform: "linux/arm64", state: "evicted", size_bytes: null, pulled_at: 1_700_000_000, scans: [] },
      { id: "p3", platform: "linux/s390x", state: "failed", size_bytes: null, pulled_at: null, scans: [] },
      { id: "p4", platform: "linux/ppc64le", state: "evicting", size_bytes: 5, pulled_at: 1_700_000_000, scans: [] },
    ],
  },
];

const credentials = page([{ id: "c1", service_type: "github", label: "gh", base_url: null, username: null, expires_at: null, created_at: null }]);

const routes = [
  { path: "/sources", element: <SourcesPage /> },
  { path: "/sources/new", element: <SourceFormPage /> },
  { path: "/sources/:id", element: <SourceFormPage /> },
];

function stubCommon(extra?: (path: string, init?: RequestInit) => Response | undefined) {
  return stubApi((path, init) => {
    const extraResponse = extra?.(path, init);
    if (extraResponse !== undefined) return extraResponse;
    if (path === "/api/v1/hubs") return json(hubs);
    if (path === "/api/v1/credentials?page_size=200") return json(credentials);
    return undefined;
  });
}

beforeEach(() => {
  // Radix Switch measures itself.
  vi.stubGlobal(
    "ResizeObserver",
    class {
      observe() {}
      unobserve() {}
      disconnect() {}
    },
  );
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("SourcesPage", () => {
  it("renders the sources and filters by namespace and tag", async () => {
    stubCommon((path) =>
      path === "/api/v1/image-sources?page_size=200"
        ? json(page([source("s1", "nrosier/walley", "1.*"), source("s2", "other/app", "latest", "h2")]))
        : undefined,
    );
    renderWithRoutes(routes, "/sources");
    expect(await screen.findByText("nrosier/walley")).toBeInTheDocument();
    expect(screen.getByText("other/app")).toBeInTheDocument();
    expect(screen.getByText("docker.io")).toBeInTheDocument();
    expect(screen.getAllByText("acme/app")).toHaveLength(2);

    await userEvent.selectOptions(screen.getByLabelText(t("sources.filter.namespace")), "nrosier");
    expect(screen.getByText("nrosier/walley")).toBeInTheDocument();
    expect(screen.queryByText("other/app")).not.toBeInTheDocument();

    await userEvent.selectOptions(screen.getByLabelText(t("sources.filter.namespace")), "");
    fireEvent.change(screen.getByLabelText(t("sources.filter.tag")), { target: { value: "latest" } });
    expect(screen.queryByText("nrosier/walley")).not.toBeInTheDocument();
    expect(screen.getByText("other/app")).toBeInTheDocument();
  });

  it("shows the empty message when nothing matches", async () => {
    stubCommon((path) => (path === "/api/v1/image-sources?page_size=200" ? json(page([])) : undefined));
    renderWithRoutes(routes, "/sources");
    expect(await screen.findByText(t("sources.empty"))).toBeInTheDocument();
  });
});

describe("SourceFormPage", () => {
  async function fillValid() {
    await screen.findByRole("option", { name: "ghcr.io" });
    await screen.findByRole("option", { name: "gh" });
    await userEvent.selectOptions(screen.getByLabelText(t("sources.form.hub")), "h1");
    await userEvent.selectOptions(screen.getByLabelText(t("sources.form.githubCredential")), "c1");
    fireEvent.change(screen.getByLabelText(t("mappings.form.githubOwner")), { target: { value: "acme" } });
    fireEvent.change(screen.getByLabelText(t("mappings.form.githubRepository")), { target: { value: "app" } });
  }

  it("refuses an invalid repository and sends nothing", async () => {
    const fetchMock = stubCommon();
    renderWithRoutes(routes, "/sources/new");
    await fillValid();
    fireEvent.change(screen.getByLabelText(t("sources.form.repository")), { target: { value: "nginx:latest" } });
    fireEvent.change(screen.getByLabelText(t("sources.form.tag")), { target: { value: "1.0" } });
    await userEvent.click(screen.getByRole("button", { name: t("sources.form.save") }));
    expect(await screen.findByText(t("sources.form.repositoryInvalid"))).toBeInTheDocument();
    expect(fetchMock.mock.calls.some((call) => (call[1] as RequestInit | undefined)?.method === "POST")).toBe(false);
  });

  it("shows a live hint for an exact tag and a glob, and refuses other characters", async () => {
    stubCommon();
    renderWithRoutes(routes, "/sources/new");
    const tag = screen.getByLabelText(t("sources.form.tag"));
    expect(screen.getByText(t("sources.form.tagHelp"))).toBeInTheDocument();
    fireEvent.change(tag, { target: { value: "1.2.3" } });
    expect(screen.getByText(t("sources.form.tagHintExact"))).toBeInTheDocument();
    fireEvent.change(tag, { target: { value: "1.*" } });
    expect(screen.getByText(t("sources.form.tagHintPattern"))).toBeInTheDocument();
    fireEvent.change(tag, { target: { value: "v[0-9]*" } });
    expect(screen.getByText(t("sources.form.tagInvalid"))).toBeInTheDocument();
  });

  it("creates a source with a glob tag value", async () => {
    const fetchMock = stubCommon((path, init) => {
      if (path === "/api/v1/image-sources" && init?.method === "POST") return json(source("s9", "nrosier/walley", "1.*"), 201);
      if (path === "/api/v1/image-sources/s9") return json(source("s9", "nrosier/walley", "1.*"));
      if (path === "/api/v1/image-sources/s9/images") return json(page([]));
      return undefined;
    });
    renderWithRoutes(routes, "/sources/new");
    await fillValid();
    fireEvent.change(screen.getByLabelText(t("sources.form.repository")), { target: { value: "nrosier/walley" } });
    fireEvent.change(screen.getByLabelText(t("sources.form.tag")), { target: { value: "1.*" } });
    await userEvent.click(screen.getByRole("button", { name: t("sources.form.save") }));
    expect(await screen.findByRole("button", { name: t("sources.scan.button") })).toBeInTheDocument();
    const post = fetchMock.mock.calls.find((call) => (call[1] as RequestInit).method === "POST");
    expect(JSON.parse(String(((post ?? [])[1] as RequestInit).body))).toMatchObject({
      hub_id: "h1",
      repository: "nrosier/walley",
      tag_value: "1.*",
      github_cred_id: "c1",
    });
  });

  it("sends the display name on create, and an empty one as null (#323)", async () => {
    const fetchMock = stubCommon((path, init) => {
      if (path === "/api/v1/image-sources" && init?.method === "POST") return json({ ...source("s9", "nrosier/walley", "1.*"), name: "Walley" }, 201);
      if (path === "/api/v1/image-sources/s9") return json(source("s9", "nrosier/walley", "1.*"));
      if (path === "/api/v1/image-sources/s9/images") return json(page([]));
      return undefined;
    });
    renderWithRoutes(routes, "/sources/new");
    await fillValid();
    fireEvent.change(screen.getByLabelText(t("sources.form.repository")), { target: { value: "nrosier/walley" } });
    fireEvent.change(screen.getByLabelText(t("sources.form.tag")), { target: { value: "1.*" } });
    fireEvent.change(screen.getByLabelText(t("sources.form.name")), { target: { value: "Walley" } });
    await userEvent.click(screen.getByRole("button", { name: t("sources.form.save") }));
    await screen.findByRole("button", { name: t("sources.scan.button") });
    const post = fetchMock.mock.calls.find((call) => (call[1] as RequestInit).method === "POST");
    expect(JSON.parse(String(((post ?? [])[1] as RequestInit).body))).toMatchObject({ name: "Walley" });
  });

  it("shows the saved name in the Name field when editing (#323)", async () => {
    stubCommon((path) => {
      if (path === "/api/v1/image-sources/s1") return json({ ...source("s1", "nrosier/walley", "1.*"), name: "Walley" });
      if (path === "/api/v1/image-sources/s1/images") return json(page([]));
      return undefined;
    });
    renderWithRoutes(routes, "/sources/s1");
    expect(await screen.findByLabelText(t("sources.form.name"))).toHaveValue("Walley");
  });

  it("notes that Docker Hub works without a credential", async () => {
    stubCommon();
    renderWithRoutes(routes, "/sources/new");
    await screen.findByRole("option", { name: "docker.io" });
    await userEvent.selectOptions(screen.getByLabelText(t("sources.form.hub")), "h2");
    expect(screen.getByText(t("sources.form.noCredentialDockerHub"))).toBeInTheDocument();
  });

  it("Scan now calls the route once and shows the queued count", async () => {
    const fetchMock = stubCommon((path, init) => {
      if (path === "/api/v1/image-sources/s1") return json(source("s1", "nrosier/walley", "1.*"));
      if (path === "/api/v1/image-sources/s1/images") return json(page(images));
      if (path === "/api/v1/image-sources/s1/scan" && init?.method === "POST") return json({ queued: 3 });
      return undefined;
    });
    renderWithRoutes(routes, "/sources/s1");
    await userEvent.click(await screen.findByRole("button", { name: t("sources.scan.button") }));
    expect(await screen.findByText("3 images queued.")).toBeInTheDocument();
    const scans = fetchMock.mock.calls.filter((call) => String(call[0]).endsWith("/scan"));
    expect(scans).toHaveLength(1);
  });

  it("Scan now shows the fixed rate-limit message", async () => {
    stubCommon((path, init) => {
      if (path === "/api/v1/image-sources/s1") return json(source("s1", "nrosier/walley", "1.*"));
      if (path === "/api/v1/image-sources/s1/images") return json(page([]));
      if (path === "/api/v1/image-sources/s1/scan" && init?.method === "POST") {
        return json({ error: { code: "rate_limited", message: "server text" } }, 429);
      }
      return undefined;
    });
    renderWithRoutes(routes, "/sources/s1");
    await userEvent.click(await screen.findByRole("button", { name: t("sources.scan.button") }));
    expect(await screen.findByText(t("sources.scan.rateLimited"))).toBeInTheDocument();
    expect(screen.queryByText("server text")).not.toBeInTheDocument();
  });

  it("the images table renders each state and the scan status per scanner", async () => {
    stubCommon((path) => {
      if (path === "/api/v1/image-sources/s1") return json(source("s1", "nrosier/walley", "1.*"));
      if (path === "/api/v1/image-sources/s1/images") return json(page(images));
      return undefined;
    });
    renderWithRoutes(routes, "/sources/s1");
    const table = await screen.findByRole("table");
    for (const state of ["stored", "evicting", "evicted", "failed"] as const) {
      expect(within(table).getByText(t(`sources.state.${state}`))).toBeInTheDocument();
    }
    expect(within(table).getByText("linux/amd64")).toBeInTheDocument();
    expect(within(table).getByText("grype")).toBeInTheDocument();
    expect(within(table).getByText("trivy")).toBeInTheDocument();
    expect(within(table).getByText(t("pill.running"))).toBeInTheDocument();
  });
});
