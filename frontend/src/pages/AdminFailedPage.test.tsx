import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { t } from "../i18n";
import { json, renderAt, stubApi, user } from "../test/render";
import AdminFailedPage from "./AdminFailedPage";

const job = {
  id: "j1",
  mapping_id: "m1",
  status: "failed",
  attempts: 8,
  last_error: "GitHub rejected the SARIF upload (403)",
  updated_at: "2026-11-03T14:47:00Z",
  image: { repo_full_name: "platform/billing-worker", tag: "3.8.1", digest: "sha256:51ab07d3aaaa" },
};

describe("AdminFailedPage", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("retry posts and shows the owner username", async () => {
    let failed = [job];
    const fetchMock = stubApi((path, init) => {
      if (path.startsWith("/api/v1/jobs?")) {
        return json({ items: failed, page: 1, page_size: 50, total: failed.length });
      }
      if (path === "/api/v1/mappings?scope=all&page_size=200") {
        return json({
          items: [{ id: "m1", user_id: "u7", github_owner: "example-org", github_repo: "billing" }],
          page: 1,
          page_size: 200,
          total: 1,
        });
      }
      if (path === "/api/v1/admin/users") {
        return json([{ ...user("user"), id: "u7", username: "j.devries" }]);
      }
      if (path === "/api/v1/jobs/j1/retry" && init?.method === "POST") {
        failed = [];
        return json({ ...job, status: "queued" });
      }
      return undefined;
    });
    renderAt(<AdminFailedPage />, "/admin/failed");

    expect(await screen.findByText(t("admin.failed.owner", { name: "j.devries" }))).toBeInTheDocument();
    expect(screen.getByText("GitHub rejected the SARIF upload (403)")).toBeInTheDocument();
    expect(screen.getByText("example-org/billing")).toBeInTheDocument();

    await userEvent.click(screen.getByRole("button", { name: t("admin.failed.retry") }));
    expect(await screen.findByText(t("admin.failed.empty"))).toBeInTheDocument();
    const retried = fetchMock.mock.calls.some(
      (call) => String(call[0]) === "/api/v1/jobs/j1/retry" && (call[1] as RequestInit).method === "POST",
    );
    expect(retried).toBe(true);
  });
});
