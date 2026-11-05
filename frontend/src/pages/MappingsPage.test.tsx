import { screen, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { t } from "../i18n";
import { json, renderAt, stubApi, user } from "../test/render";
import type { MappingListItem } from "../types/api";
import MappingsPage from "./MappingsPage";

function mapping(over: Partial<MappingListItem>): MappingListItem {
  return {
    id: "m1",
    user_id: "u1",
    harbor_cred_id: "c1",
    github_cred_id: "c2",
    harbor_base_url: "https://harbor.example.org",
    harbor_project: "platform",
    harbor_repository: "api-gateway",
    github_owner: "example-org",
    github_repo: "api-gateway",
    default_branch: "main",
    auto_create_issues: true,
    min_issue_severity: "HIGH",
    created_at: null,
    open_cves: { critical: 1, high: 4, medium: 2, low: 3, unknown: 1, total: 11 },
    last_sync: { status: "done", updated_at: new Date().toISOString() },
    ...over,
  };
}

describe("MappingsPage", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("shows open CVE counts and last sync", async () => {
    stubApi((path) => {
      if (path === "/api/v1/account/me") return json({ user: user("user") });
      if (path.startsWith("/api/v1/mappings")) {
        return json({
          items: [
            mapping({}),
            mapping({
              id: "m2",
              user_id: "other",
              harbor_repository: "web",
              auto_create_issues: false,
              open_cves: { critical: 0, high: 2, medium: 0, low: 0, unknown: 0, total: 2 },
              last_sync: null,
            }),
          ],
          page: 1,
          page_size: 50,
          total: 2,
        });
      }
      return undefined;
    });
    renderAt(<MappingsPage />);
    const first = (await screen.findByText("platform/api-gateway")).closest("tr") as HTMLElement;
    expect(within(first).getByText(t("mappings.count.critical", { n: 1 }))).toBeInTheDocument();
    expect(within(first).getByText(t("mappings.count.high", { n: 4 }))).toBeInTheDocument();
    expect(within(first).getByText(t("mappings.count.medium", { n: 2 }))).toBeInTheDocument();
    expect(within(first).getByText(t("mappings.count.low", { n: 3 }))).toBeInTheDocument();
    expect(within(first).getByText(t("mappings.count.unknown", { n: 1 }))).toBeInTheDocument();
    expect(within(first).getByText(t("mappings.count.total", { n: 11 }))).toBeInTheDocument();
    expect(within(first).getByText(t("pill.done"))).toBeInTheDocument();
    expect(within(first).getByRole("link", { name: t("mappings.editNamed", { name: "platform/api-gateway" }) })).toBeInTheDocument();

    const second = screen.getByText("platform/web").closest("tr") as HTMLElement;
    expect(within(second).getByText(t("mappings.never"))).toBeInTheDocument();
    expect(within(second).getByText(t("mappings.issues.offDetail"))).toBeInTheDocument();
    // Not the owner: no Edit link.
    expect(within(second).queryByRole("link")).not.toBeInTheDocument();
  });

  it("mapping with no sync job shows the reason", async () => {
    stubApi((path) => {
      if (path === "/api/v1/account/me") return json({ user: user("user") });
      if (path.startsWith("/api/v1/mappings")) {
        return json({
          items: [mapping({ id: "m2", harbor_repository: "web", last_sync: null })],
          page: 1,
          page_size: 50,
          total: 1,
        });
      }
      return undefined;
    });
    renderAt(<MappingsPage />);
    const row = (await screen.findByText("platform/web")).closest("tr") as HTMLElement;
    expect(within(row).getByText(t("mappings.never"))).toBeInTheDocument();
    expect(within(row).getByText(t("mappings.neverReason"))).toBeInTheDocument();
  });
});
