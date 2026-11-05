import { screen } from "@testing-library/react";
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

interface Options {
  create?: () => Response;
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
        json({ mapping: { ...existing, id: "m2", github_repo: "new-repo" }, webhook_url: SECRET_URL, auth_secret: SECRET_VALUE }, 201)
      );
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
  await userEvent.type(screen.getByLabelText(t("mappings.form.githubOwner")), "example-org");
  await userEvent.type(screen.getByLabelText(t("mappings.form.githubRepository")), githubRepo);
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

  it("blocks save and shows the duplicate GitHub target under the repository field", async () => {
    stub();
    renderWithRoutes(routes, "/mappings/new");
    await fillNew("Billing");
    const message = t("mappings.form.duplicate", { name: "platform/billing-worker" });
    expect(await screen.findByText(message)).toBeInTheDocument();
    expect(screen.getByLabelText(t("mappings.form.githubRepository"))).toHaveAttribute("aria-invalid", "true");
    expect(screen.getByRole("button", { name: t("mappings.form.save") })).toBeDisabled();
  });

  it("shows the server message for a 409 the client did not predict", async () => {
    stub({ create: () => json({ error: { code: "conflict", message: "That GitHub repository is already in use." } }, 409) });
    renderWithRoutes(routes, "/mappings/new");
    await fillNew("other-repo");
    await userEvent.click(screen.getByRole("button", { name: t("mappings.form.save") }));
    expect(await screen.findByText("That GitHub repository is already in use.")).toBeInTheDocument();
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
});
