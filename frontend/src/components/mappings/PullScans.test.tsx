import { act, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { t } from "../../i18n";
import { json, renderWithRoutes, stubApi } from "../../test/render";
import type { Mapping } from "../../types/api";
import { PullScans } from "./PullScans";

const mapping: Mapping = {
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
  scan_schedule: "off",
  scan_time: "00:00",
  scan_weekday: 1,
};

const PULL = "/api/v1/mappings/m1/pull";
const routes = [
  { path: "/mappings/m1", element: <PullScans mapping={mapping} /> },
  { path: "/sync-jobs", element: <output>jobs</output> },
];

function stub(respond: () => Response) {
  return stubApi((path, init) => (path === PULL && init?.method === "POST" ? respond() : undefined));
}

const button = () => screen.getByRole("button", { name: new RegExp(t("mapping.pull.button")) });

afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

describe("PullScans", () => {
  it("is ready: hint and an enabled button, no request yet", () => {
    const fetchMock = stub(() => json({ queued: 3 }));
    renderWithRoutes(routes, "/mappings/m1");
    expect(screen.getByText(t("mapping.pull.readyHint"))).toBeInTheDocument();
    expect(button()).toBeEnabled();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("shows the queued count, a sync jobs link and starts the cooldown", async () => {
    const fetchMock = stub(() => json({ queued: 3 }));
    renderWithRoutes(routes, "/mappings/m1");
    await userEvent.click(button());
    expect(await screen.findByText(t("mapping.pull.result", { n: 3 }))).toBeInTheDocument();
    expect(screen.getByRole("link", { name: t("mapping.pull.viewSyncJobs") })).toHaveAttribute("href", "/sync-jobs");
    expect(button()).toBeDisabled();
    expect(screen.getByText("5:00")).toBeInTheDocument();
    expect(fetchMock).toHaveBeenCalledWith(PULL, expect.objectContaining({ method: "POST" }));
  });

  it("shows a distinct message when nothing was queued", async () => {
    stub(() => json({ queued: 0 }));
    renderWithRoutes(routes, "/mappings/m1");
    await userEvent.click(button());
    expect(await screen.findByText(t("mapping.pull.zero"))).toBeInTheDocument();
    expect(screen.queryByText(t("mapping.pull.failed"))).not.toBeInTheDocument();
    expect(screen.getByRole("link", { name: t("mapping.pull.viewSyncJobs") })).toBeInTheDocument();
  });

  it("on 429 disables the button and counts down from Retry-After", async () => {
    stub(
      () =>
        new Response(JSON.stringify({ error: { code: "rate_limited", message: "Too many requests. Try again later." } }), {
          status: 429,
          headers: { "Content-Type": "application/json", "Retry-After": "252" },
        }),
    );
    renderWithRoutes(routes, "/mappings/m1");
    await userEvent.click(button());
    expect(await screen.findByText("4:12")).toBeInTheDocument();
    expect(screen.getByText(t("mapping.pull.cooldownHint"))).toBeInTheDocument();
    expect(screen.getByText(t("mapping.pull.cooldownNote"))).toBeInTheDocument();
    expect(button()).toBeDisabled();
    expect(screen.queryByText("Too many requests. Try again later.")).not.toBeInTheDocument();
  });

  it("ticks the countdown and re-enables the button at zero", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    stub(() => new Response(JSON.stringify({ error: { code: "rate_limited", message: "x" } }), { status: 429, headers: { "Retry-After": "2" } }));
    renderWithRoutes(routes, "/mappings/m1");
    await userEvent.setup({ advanceTimers: vi.advanceTimersByTime }).click(button());
    expect(await screen.findByText("0:02")).toBeInTheDocument();
    for (let i = 0; i < 2; i += 1) {
      await act(async () => {
        await vi.advanceTimersByTimeAsync(1000);
      });
    }
    expect(button()).toBeEnabled();
  });

  it("on 502 shows the fixed message, no retry prompt, and the cooldown", async () => {
    stub(() => json({ error: { code: "upstream_unreachable", message: "An upstream service could not be reached." } }, 502));
    renderWithRoutes(routes, "/mappings/m1");
    await userEvent.click(button());
    expect(await screen.findByRole("alert")).toHaveTextContent(t("mapping.pull.failed"));
    expect(screen.queryByText("An upstream service could not be reached.")).not.toBeInTheDocument();
    expect(screen.queryByRole("link", { name: t("mapping.pull.viewSyncJobs") })).not.toBeInTheDocument();
    expect(button()).toBeDisabled();
  });
});
