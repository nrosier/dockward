import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { t } from "../i18n";
import { json, renderAt, stubApi } from "../test/render";
import AdminGithubPage from "./AdminGithubPage";

function putBodies(fetchMock: ReturnType<typeof stubApi>): Record<string, unknown>[] {
  return fetchMock.mock.calls
    .filter((call) => (call[1] as RequestInit | undefined)?.method === "PUT")
    .map((call) => JSON.parse(String((call[1] as RequestInit).body)) as Record<string, unknown>);
}

describe("AdminGithubPage", () => {
  beforeEach(() => {
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

  it("saves both addresses, and an empty pair stays empty", async () => {
    const fetchMock = stubApi((path) => {
      if (path === "/api/v1/admin/github-url") {
        return json({ api_base_url: "", web_url: "" });
      }
      return undefined;
    });
    renderAt(<AdminGithubPage />, "/admin/settings/github");
    const api = await screen.findByLabelText(t("admin.github.api"));
    await userEvent.click(screen.getByRole("button", { name: t("admin.github.save") }));
    await screen.findByText(t("admin.github.saved"));
    expect(putBodies(fetchMock)[0]).toEqual({ api_base_url: "", web_url: "" });

    await userEvent.type(api, "https://ghes.example.com/api/v3");
    await userEvent.click(screen.getByRole("button", { name: t("admin.github.save") }));
    await vi.waitFor(() => expect(putBodies(fetchMock)).toHaveLength(2));
    expect(putBodies(fetchMock)[1]).toEqual({ api_base_url: "https://ghes.example.com/api/v3", web_url: "" });
  });

  it("shows the catalog text for a 422", async () => {
    stubApi((path, init) => {
      if (path === "/api/v1/admin/github-url" && init?.method === "PUT") {
        return json({ error: { code: "validation_failed", message: "settings.github_url_invalid" } }, 422);
      }
      if (path === "/api/v1/admin/github-url") {
        return json({ api_base_url: "", web_url: "" });
      }
      return undefined;
    });
    renderAt(<AdminGithubPage />, "/admin/settings/github");
    await screen.findByLabelText(t("admin.github.api"));
    await userEvent.click(screen.getByRole("button", { name: t("admin.github.save") }));
    expect(await screen.findByText(t("settings.github_url_invalid"))).toBeInTheDocument();
  });
});
