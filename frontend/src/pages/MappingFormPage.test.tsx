import { screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { t } from "../i18n";
import { json, renderWithRoutes, stubApi, user } from "../test/render";
import type { Mapping } from "../types/api";
import MappingFormPage from "./MappingFormPage";

const SECRET_URL = "https://harborgate.example.org/api/v1/webhooks/harbor/fake-token-for-tests";
const SECRET_VALUE = "fake-auth-secret-for-tests";

const existing: Mapping = {
  id: "m1",
  user_id: "u1",
  harbor_cred_id: "hc",
  github_cred_id: "gc",
  harbor_base_url: "https://harbor.example.org",
  harbor_project: "platform",
  harbor_repository: "billing-worker",
  github_owner: "example-org",
  github_repo: "billing",
  default_branch: "main",
  auto_create_issues: true,
  min_issue_severity: "HIGH",
  created_at: null,
};

const harborCred = {
  id: "hc",
  service_type: "harbor",
  label: "harbor-robot",
  base_url: "https://harbor.example.org",
  username: "robot",
  expires_at: null,
  created_at: null,
};
const githubCred = { ...harborCred, id: "gc", service_type: "github", label: "gh-token", base_url: null, username: null };

const PW_URL = "https://harborgate.example.org/api/v1/webhooks/harbor/project/fake-project-token";
const PW_SECRET = "Bearer fake-project-secret-for-tests";

interface Options {
  create?: () => Response;
  // The save responses' `project_webhook_exists` (#179). Default false.
  projectWebhookExists?: boolean;
  createProjectWebhook?: () => Response;
}

function stub(options: Options = {}) {
  return stubApi((path, init) => {
    if (path === "/api/v1/account/me") return json({ user: user("user") });
    if (path.startsWith("/api/v1/credentials?service_type=harbor")) {
      return json({ items: [harborCred], page: 1, page_size: 200, total: 1 });
    }
    if (path.startsWith("/api/v1/credentials?service_type=github")) {
      return json({ items: [githubCred], page: 1, page_size: 200, total: 1 });
    }
    if (path === "/api/v1/mappings?page_size=200") {
      return json({ items: [{ ...existing, open_cves: { critical: 0, high: 0, medium: 0, low: 0, unknown: 0, total: 0 }, last_sync: null }], page: 1, page_size: 200, total: 1 });
    }
    if (path === "/api/v1/mappings" && init?.method === "POST") {
      return (
        options.create?.() ??
        json(
          {
            mapping: { ...existing, id: "m2", github_repo: "new-repo" },
            webhook_url: SECRET_URL,
            auth_secret: SECRET_VALUE,
            project_webhook_exists: options.projectWebhookExists ?? false,
          },
          201,
        )
      );
    }
    if (path === "/api/v1/mappings/m1" && init?.method === "PUT") {
      return json({ ...existing, default_branch: "develop", project_webhook_exists: options.projectWebhookExists ?? false });
    }
    if (path === "/api/v1/project-webhooks" && init?.method === "POST") {
      return options.createProjectWebhook?.() ?? json({ id: "pw1", webhook_url: PW_URL, auth_secret: PW_SECRET }, 201);
    }
    if (path === "/api/v1/mappings/m1" && (init?.method ?? "GET") === "GET") return json(existing);
    if (path === "/api/v1/mappings/m1/rotate-webhook-token" && init?.method === "POST") {
      return json({ webhook_url: SECRET_URL });
    }
    return undefined;
  });
}

const routes = [
  { path: "/mappings/new", element: <MappingFormPage /> },
  { path: "/mappings/:id", element: <MappingFormPage /> },
  { path: "/mappings", element: <output>list</output> },
];

async function fillNew(githubRepo: string) {
  await userEvent.type(await screen.findByLabelText(t("mappings.form.harborProject")), "platform");
  await userEvent.type(screen.getByLabelText(t("mappings.form.harborRepository")), "billing-api");
  await userEvent.type(screen.getByLabelText(t("mappings.form.githubRepository")), `example-org/${githubRepo}`);
  // Wait for the credential selects to default to their first option.
  await vi.waitFor(() => expect(screen.getByLabelText(t("mappings.form.githubCredential"))).toHaveValue("gc"));
  await vi.waitFor(() => expect(screen.getByLabelText(t("mappings.form.harborCredential"))).toHaveValue("hc"));
}

// jsdom has no ResizeObserver; the Radix Switch measures its button with one.
class NoopResizeObserver {
  observe() {}
  unobserve() {}
  disconnect() {}
}

describe("MappingFormPage", () => {
  beforeEach(() => {
    vi.stubGlobal("ResizeObserver", NoopResizeObserver);
  });
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("allows a GitHub repository that another mapping already targets", async () => {
    stub();
    renderWithRoutes(routes, "/mappings/new");
    await fillNew("Billing");
    const message = t("mappings.form.duplicate", { name: "platform/billing-worker" });
    expect(screen.queryByText(message)).not.toBeInTheDocument();
    expect(screen.getByLabelText(t("mappings.form.githubRepository"))).not.toHaveAttribute("aria-invalid", "true");
    expect(screen.getByRole("button", { name: t("mappings.form.save") })).toBeEnabled();
  });

  it("blocks save and shows the duplicate Harbor repository under the repository field", async () => {
    stub();
    renderWithRoutes(routes, "/mappings/new");
    await userEvent.type(await screen.findByLabelText(t("mappings.form.harborProject")), "platform");
    await userEvent.type(screen.getByLabelText(t("mappings.form.harborRepository")), "billing-worker");
    await userEvent.type(screen.getByLabelText(t("mappings.form.githubRepository")), "example-org/other");
    const message = t("mappings.form.duplicate", { name: "platform/billing-worker" });
    expect(await screen.findByText(message)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: t("mappings.form.save") })).toBeDisabled();
  });

  it.each([409, 422])("shows fixed catalog text, not the raw server message, for a %i save error", async (status) => {
    stub({ create: () => json({ error: { code: "conflict", message: "RAW 409 detail" } }, status) });
    renderWithRoutes(routes, "/mappings/new");
    await fillNew("other-repo");
    await userEvent.click(screen.getByRole("button", { name: t("mappings.form.save") }));
    expect(await screen.findByText(t("errors.generic"))).toBeInTheDocument();
    expect(screen.queryByText("RAW 409 detail")).not.toBeInTheDocument();
  });

  it("shows the catalog duplicate text for a Harbor repository mapped by another user, naming no one", async () => {
    const otherUser = "u-other-7f3a";
    const otherMapping = "m-other-91c2";
    stub({
      create: () =>
        json(
          {
            error: {
              code: "conflict",
              detail: "harbor_repository_mapped",
              message: `RAW mapping ${otherMapping} of ${otherUser}`,
            },
          },
          409,
        ),
    });
    const { container } = renderWithRoutes(routes, "/mappings/new");
    await fillNew("other-repo");
    await userEvent.click(screen.getByRole("button", { name: t("mappings.form.save") }));
    expect(await screen.findByText(t("mappings.form.harborRepositoryMapped"))).toBeInTheDocument();
    expect(screen.queryByText(t("errors.generic"))).not.toBeInTheDocument();
    expect(container.textContent).not.toContain(otherUser);
    expect(container.textContent).not.toContain(otherMapping);
  });

  it("keeps the generic text for a 409 conflict without the duplicate detail", async () => {
    stub({ create: () => json({ error: { code: "conflict", message: "the mapping changed, try again." } }, 409) });
    renderWithRoutes(routes, "/mappings/new");
    await fillNew("other-repo");
    await userEvent.click(screen.getByRole("button", { name: t("mappings.form.save") }));
    expect(await screen.findByText(t("errors.generic"))).toBeInTheDocument();
    expect(screen.queryByText(t("mappings.form.harborRepositoryMapped"))).not.toBeInTheDocument();
  });

  it("shows the webhook URL and auth secret once after create", async () => {
    stub();
    const { router } = renderWithRoutes(routes, "/mappings/new");
    await fillNew("new-repo");
    await userEvent.click(screen.getByRole("button", { name: t("mappings.form.save") }));
    expect(await screen.findByDisplayValue(SECRET_URL)).toBeInTheDocument();
    expect(screen.getByDisplayValue(SECRET_VALUE)).toBeInTheDocument();
    expect(screen.getByText(t("mappings.shownOnce.warningBoth"))).toBeInTheDocument();
    // Shown in place: no navigation, and no secret in the URL.
    expect(router.state.location.pathname).toBe("/mappings/new");
    expect(router.state.location.search).toBe("");
    await userEvent.click(screen.getByRole("button", { name: t("mappings.shownOnce.done") }));
    expect(router.state.location.pathname).toBe("/mappings");
    expect(screen.queryByDisplayValue(SECRET_URL)).not.toBeInTheDocument();
  });

  it("shown-once values are not in the query cache", async () => {
    stub();
    const { client } = renderWithRoutes(routes, "/mappings/new");
    await fillNew("new-repo");
    await userEvent.click(screen.getByRole("button", { name: t("mappings.form.save") }));
    await screen.findByDisplayValue(SECRET_URL);
    const cached = JSON.stringify(client.getQueryCache().getAll().map((query) => query.state.data ?? null));
    const mutations = JSON.stringify(client.getMutationCache().getAll().map((mutation) => mutation.state.data ?? null));
    for (const text of [cached, mutations]) {
      expect(text).not.toContain(SECRET_URL);
      expect(text).not.toContain(SECRET_VALUE);
    }
    expect(JSON.stringify(Object.entries(localStorage))).not.toContain(SECRET_VALUE);
  });

  it("rotate asks for confirmation and shows the new value", async () => {
    const fetchMock = stub();
    renderWithRoutes(routes, "/mappings/m1");
    await userEvent.click(await screen.findByRole("button", { name: t("mappings.webhook.rotateUrl") }));
    expect(await screen.findByText(t("mappings.webhook.confirm"))).toBeInTheDocument();
    const rotated = () => fetchMock.mock.calls.some(([path]) => String(path).endsWith("/rotate-webhook-token"));
    expect(rotated()).toBe(false);
    const dialog = screen.getByRole("dialog");
    const confirm = Array.from(dialog.querySelectorAll("button")).find((b) => b.textContent === t("mappings.webhook.rotateUrl"));
    await userEvent.click(confirm as HTMLElement);
    expect(await screen.findByDisplayValue(SECRET_URL)).toBeInTheDocument();
    expect(rotated()).toBe(true);
    expect(screen.getByText(t("mappings.shownOnce.warningOne"))).toBeInTheDocument();
  });

  it("shows the Pull scans panel to the owner", async () => {
    stub();
    renderWithRoutes(routes, "/mappings/m1");
    expect(await screen.findByRole("button", { name: t("mapping.pull.button") })).toBeEnabled();
  });

  describe("project webhook proposal (#179)", () => {
    const proposalText = t("mapping.projectWebhook.propose", { project: "platform" });

    it("proposes the project webhook after creating the first mapping in a project with none", async () => {
      stub({ projectWebhookExists: false });
      renderWithRoutes(routes, "/mappings/new");
      await fillNew("new-repo");
      await userEvent.click(screen.getByRole("button", { name: t("mappings.form.save") }));
      const banner = await screen.findByRole("region", { name: t("mapping.projectWebhook.label") });
      // Names the Harbor project, and no repository.
      expect(within(banner).getByText(proposalText)).toBeInTheDocument();
      expect(banner.textContent).not.toContain("billing-worker");
      expect(banner.textContent).not.toContain("billing-api");
      // Not a modal: the shown-once values stay on the page beside it.
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
      expect(screen.getByDisplayValue(SECRET_URL)).toBeInTheDocument();
    });

    it("shows no proposal when the project already has a project webhook", async () => {
      const fetchMock = stub({ projectWebhookExists: true });
      renderWithRoutes(routes, "/mappings/new");
      await fillNew("new-repo");
      await userEvent.click(screen.getByRole("button", { name: t("mappings.form.save") }));
      await screen.findByDisplayValue(SECRET_URL);
      expect(screen.queryByRole("region", { name: t("mapping.projectWebhook.label") })).not.toBeInTheDocument();
      expect(screen.queryByRole("button", { name: t("mapping.projectWebhook.create") })).not.toBeInTheDocument();
      expect(screen.getByText(t("mapping.projectWebhook.exists", { project: "platform" }))).toBeInTheDocument();
      expect(fetchMock.mock.calls.some(([path]) => String(path).includes("/project-webhooks"))).toBe(false);
    });

    it("creates the project webhook from the banner and shows its values once, not cached", async () => {
      const fetchMock = stub({ projectWebhookExists: false });
      const { client } = renderWithRoutes(routes, "/mappings/new");
      await fillNew("new-repo");
      await userEvent.click(screen.getByRole("button", { name: t("mappings.form.save") }));
      await userEvent.click(await screen.findByRole("button", { name: t("mapping.projectWebhook.create") }));
      expect(await screen.findByDisplayValue(PW_URL)).toBeInTheDocument();
      expect(screen.getByDisplayValue(PW_SECRET)).toBeInTheDocument();
      const call = fetchMock.mock.calls.find(([path]) => String(path) === "/api/v1/project-webhooks");
      expect(JSON.parse(String(call?.[1]?.body))).toEqual({ mapping_id: "m2" });
      // The mapping's own values are unchanged.
      expect(screen.getByDisplayValue(SECRET_URL)).toBeInTheDocument();
      const cached = JSON.stringify(client.getMutationCache().getAll().map((mutation) => mutation.state.data ?? null));
      expect(cached).not.toContain(PW_URL);
      expect(cached).not.toContain(PW_SECRET);
    });

    it("shows the setup note when another user created the project webhook first (409)", async () => {
      stub({
        projectWebhookExists: false,
        createProjectWebhook: () => json({ error: { code: "conflict", message: "RAW exists" } }, 409),
      });
      renderWithRoutes(routes, "/mappings/new");
      await fillNew("new-repo");
      await userEvent.click(screen.getByRole("button", { name: t("mappings.form.save") }));
      await userEvent.click(await screen.findByRole("button", { name: t("mapping.projectWebhook.create") }));
      expect(await screen.findByText(t("mapping.projectWebhook.exists", { project: "platform" }))).toBeInTheDocument();
      expect(screen.queryByText("RAW exists")).not.toBeInTheDocument();
    });

    it("can be dismissed without blocking the page", async () => {
      stub({ projectWebhookExists: false });
      const { router } = renderWithRoutes(routes, "/mappings/new");
      await fillNew("new-repo");
      await userEvent.click(screen.getByRole("button", { name: t("mappings.form.save") }));
      await screen.findByText(proposalText);
      await userEvent.click(screen.getByRole("button", { name: t("mapping.projectWebhook.dismiss") }));
      expect(screen.queryByText(proposalText)).not.toBeInTheDocument();
      expect(screen.getByDisplayValue(SECRET_URL)).toBeInTheDocument();
      await userEvent.click(screen.getByRole("button", { name: t("mappings.shownOnce.done") }));
      expect(router.state.location.pathname).toBe("/mappings");
    });

    it("proposes after an edit save in a project with none, and again on the next save", async () => {
      stub({ projectWebhookExists: false });
      const { router } = renderWithRoutes(routes, "/mappings/m1");
      const branch = await screen.findByLabelText(t("mappings.form.defaultBranch"));
      await userEvent.clear(branch);
      await userEvent.type(branch, "develop");
      await userEvent.click(screen.getByRole("button", { name: t("mappings.form.save") }));
      expect(await screen.findByText(proposalText)).toBeInTheDocument();
      expect(router.state.location.pathname).toBe("/mappings/m1");
      await userEvent.click(screen.getByRole("button", { name: t("mapping.projectWebhook.dismiss") }));
      expect(screen.queryByText(proposalText)).not.toBeInTheDocument();
      // A dismissal is not stored: the next save proposes again.
      await userEvent.clear(branch);
      await userEvent.type(branch, "release");
      await userEvent.click(screen.getByRole("button", { name: t("mappings.form.save") }));
      expect(await screen.findByText(proposalText)).toBeInTheDocument();
    });

    it("returns to the list after an edit save when the project has a project webhook", async () => {
      stub({ projectWebhookExists: true });
      const { router } = renderWithRoutes(routes, "/mappings/m1");
      const branch = await screen.findByLabelText(t("mappings.form.defaultBranch"));
      await userEvent.clear(branch);
      await userEvent.type(branch, "develop");
      await userEvent.click(screen.getByRole("button", { name: t("mappings.form.save") }));
      await vi.waitFor(() => expect(router.state.location.pathname).toBe("/mappings"));
      expect(screen.queryByText(proposalText)).not.toBeInTheDocument();
    });
  });
});
