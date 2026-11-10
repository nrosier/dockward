import { screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { t } from "../i18n";
import { json, renderAt, stubApi } from "../test/render";
import AdminHealthPage from "./AdminHealthPage";

function check(over: Record<string, unknown>) {
  return {
    credential_id: "c",
    label: "gh",
    ok: true,
    reachable: true,
    missing_permissions: [],
    code_scanning: "ok",
    target: null,
    detail: "all good",
    ...over,
  };
}

describe("AdminHealthPage", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("shows missing permissions and code scanning states", async () => {
    stubApi((path) =>
      path === "/api/v1/admin/health"
        ? json({
            github: [
              check({
                credential_id: "g1",
                target: "example-org/billing",
                ok: false,
                missing_permissions: ["code_scanning_alerts"],
                code_scanning: "unavailable",
              }),
              check({ credential_id: "g2", target: "example-org/etl", code_scanning: "no_analysis_yet" }),
              check({ credential_id: "g3", target: "example-org/web", code_scanning: "ok" }),
            ],
            request: { client_ip: "203.0.113.24", source: "x-forwarded-for" },
          })
        : undefined,
    );
    renderAt(<AdminHealthPage />, "/admin/health");

    expect(await screen.findByText(t("admin.health.missing", { list: "code_scanning_alerts" }))).toBeInTheDocument();
    expect(screen.getByText(t("admin.health.scan.unavailable"))).toBeInTheDocument();
    expect(screen.getByText(t("admin.health.scan.none"))).toBeInTheDocument();
    expect(screen.getByText(t("admin.health.scan.ok"))).toBeInTheDocument();
    expect(screen.getByText("203.0.113.24")).toBeInTheDocument();
    expect(screen.getByText(t("admin.health.source.xff"))).toBeInTheDocument();
  });
});
