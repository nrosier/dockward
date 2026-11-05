import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { t } from "../i18n";
import { json, renderWithRoutes, stubApi, user } from "../test/render";
import type { ProjectWebhook, UnmatchedRepository } from "../types/api";
import ProjectWebhookPage from "./ProjectWebhookPage";

const webhook: ProjectWebhook = {
  id: "pw1",
  harbor_base_url: "https://harbor.example.com",
  harbor_project: "nrosier",
  owner: "dev",
  created_at: "2026-11-05T09:12:00Z",
  rotated_at: null,
  mappings: ["nrosier/walley", "nrosier/harborgate"],
};

const rows: UnmatchedRepository[] = [
  { repository: "nrosier/cutebot-track", count: 12, last_seen_at: "2026-11-05T10:40:00Z" },
  { repository: "nrosier/bichon", count: 2, last_seen_at: "2026-11-04T18:03:00Z" },
];

const SECRET_URL = "https://hg.example.com/api/v1/webhooks/harbor/project/tok-NEW";
const SECRET_VALUE = "Bearer sec-NEW";

interface Options {
  role?: "admin" | "user";
  username?: string;
  items?: UnmatchedRepository[];
  getStatus?: number;
  rotateStatus?: number;
}

function stub(options: Options = {}) {
  const { role = "user", username = "dev", items = rows, getStatus = 200, rotateStatus = 200 } = options;
  return stubApi((path, init) => {
    if (path === "/api/v1/account/me") return json({ user: { ...user(role), username } });
    if (path === "/api/v1/project-webhooks/pw1" && (init?.method ?? "GET") === "GET") {
      return getStatus === 200
        ? json(webhook)
        : json({ error: { code: "forbidden", message: "Backend text." } }, getStatus);
    }
    if (path.startsWith("/api/v1/project-webhooks/pw1/unmatched")) {
      return json({ items, page: 1, page_size: 50, total: items.length });
    }
    if (path === "/api/v1/project-webhooks/pw1/rotate-token") {
      return rotateStatus === 200
        ? json({ webhook_url: SECRET_URL, mappings: webhook.mappings })
        : json({ error: { code: "forbidden", message: "Backend text." } }, rotateStatus);
    }
    if (path === "/api/v1/project-webhooks/pw1/rotate-secret") {
      return json({ auth_secret: SECRET_VALUE, mappings: webhook.mappings });
    }
    return undefined;
  });
}

function renderPage() {
  return renderWithRoutes([{ path: "/project-webhooks/:id", element: <ProjectWebhookPage /> }], "/project-webhooks/pw1");
}

function rotateCalls(mock: ReturnType<typeof stub>) {
  return mock.mock.calls.filter(([path]) => String(path).includes("/rotate-"));
}

describe("ProjectWebhookPage", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("shows the details for the owner, with the Rotate control", async () => {
    stub();
    renderPage();
    expect(await screen.findByRole("button", { name: t("projectWebhook.action.rotate") })).toBeInTheDocument();
    expect(screen.getByText(`${t("projectWebhook.owner.you")} (dev)`)).toBeInTheDocument();
    expect(screen.getByText(t("projectWebhook.rotated.never"))).toBeInTheDocument();
    const receiving = screen.getByRole("rowheader", { name: t("projectWebhook.mappingsReceiving") }).closest("tr");
    expect(receiving).not.toBeNull();
    expect(within(receiving as HTMLElement).getByText("2")).toBeInTheDocument();
  });

  it("hides Rotate from a non-owner user", async () => {
    stub({ username: "someone-else" });
    renderPage();
    expect(await screen.findByText(t("projectWebhook.details.title"))).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: t("projectWebhook.action.rotate") })).not.toBeInTheDocument();
  });

  it("hides Rotate from an admin who is not the owner, and still shows the details", async () => {
    stub({ role: "admin", username: "ops-admin" });
    renderPage();
    expect(await screen.findByText(t("projectWebhook.details.title"))).toBeInTheDocument();
    expect(screen.getByText("dev")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: t("projectWebhook.action.rotate") })).not.toBeInTheDocument();
  });

  it("lists every affected mapping in the dialog and revokes nothing before Confirm", async () => {
    const mock = stub();
    const u = userEvent.setup();
    renderPage();
    await u.click(await screen.findByRole("button", { name: t("projectWebhook.action.rotate") }));
    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByText("nrosier/walley")).toBeInTheDocument();
    expect(within(dialog).getByText("nrosier/harborgate")).toBeInTheDocument();
    expect(within(dialog).getByText(t("projectWebhook.rotate.followUp"))).toBeInTheDocument();
    expect(rotateCalls(mock)).toHaveLength(0);

    await u.click(within(dialog).getByRole("button", { name: t("common.cancel") }));
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
    expect(rotateCalls(mock)).toHaveLength(0);
  });

  it("rotates after Confirm and shows the new values once, in copy-able fields", async () => {
    const mock = stub();
    const u = userEvent.setup();
    const { client } = renderPage();
    await u.click(await screen.findByRole("button", { name: t("projectWebhook.action.rotate") }));
    await u.click(await screen.findByRole("button", { name: t("projectWebhook.rotate.confirm") }));

    const url = await screen.findByLabelText(t("projectWebhook.shownOnce.webhookUrl"));
    expect(url).toHaveValue(SECRET_URL);
    expect(screen.getByLabelText(t("projectWebhook.shownOnce.authSecret"))).toHaveValue(SECRET_VALUE);
    expect(screen.getAllByRole("button", { name: t("common.copy") })).toHaveLength(2);
    expect(rotateCalls(mock)).toHaveLength(2);
    expect(rotateCalls(mock).every(([, init]) => (init as RequestInit).method === "POST")).toBe(true);

    // The values are not in the query cache.
    expect(JSON.stringify(client.getQueryCache().getAll().map((q) => q.state.data))).not.toContain("tok-NEW");

    // Done clears them for good.
    await u.click(screen.getByRole("button", { name: t("projectWebhook.shownOnce.done") }));
    expect(screen.queryByDisplayValue(SECRET_URL)).not.toBeInTheDocument();
    expect(screen.queryByDisplayValue(SECRET_VALUE)).not.toBeInTheDocument();
  });

  it("shows a fixed message for a 403 on rotate, not the backend text", async () => {
    stub({ rotateStatus: 403 });
    const u = userEvent.setup();
    renderPage();
    await u.click(await screen.findByRole("button", { name: t("projectWebhook.action.rotate") }));
    await u.click(await screen.findByRole("button", { name: t("projectWebhook.rotate.confirm") }));
    expect(await screen.findByText(t("projectWebhook.forbidden"))).toBeInTheDocument();
    expect(screen.queryByText("Backend text.")).not.toBeInTheDocument();
  });

  it("shows a fixed message when the read is 403", async () => {
    stub({ getStatus: 403 });
    renderPage();
    expect(await screen.findByText(t("projectWebhook.forbidden"))).toBeInTheDocument();
    expect(screen.queryByText("Backend text.")).not.toBeInTheDocument();
  });

  it("shows the unmatched repositories with a create-mapping link", async () => {
    stub();
    renderPage();
    expect(await screen.findByRole("region", { name: t("projectWebhook.unmatched.title") })).toBeInTheDocument();
    expect(await screen.findByText("nrosier/cutebot-track")).toBeInTheDocument();
    expect(screen.getByText("12")).toBeInTheDocument();
    expect(screen.getByText("nrosier/bichon")).toBeInTheDocument();
    const links = screen.getAllByRole("link", { name: t("projectWebhook.unmatched.createMapping") });
    expect(links).toHaveLength(2);
    expect(links[0]).toHaveAttribute("href", "/mappings/new?harbor_repository=nrosier%2Fcutebot-track");
  });

  it("shows the empty state when nothing is unmatched", async () => {
    stub({ items: [] });
    renderPage();
    expect(await screen.findByText(t("projectWebhook.unmatched.empty"))).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: t("projectWebhook.unmatched.createMapping") })).not.toBeInTheDocument();
  });
});
