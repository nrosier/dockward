import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
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

const HEALTH = {
  github: [check({ credential_id: "g1", target: "example-org/web" })],
  request: { client_ip: "203.0.113.24", source: "peer" },
};

function about(checkedAt: string | null, latest: string | null) {
  const idle = {
    in_use: "bundled",
    downloaded_version: null,
    broken_version: null,
    previous_version: null,
    latest_version: latest,
    update_available: false,
    checked_at: checkedAt,
  };
  return { dockward: "0.9.3", trivy: "v0.76.2", grype: "v0.122.0", scanners: { trivy: idle, grype: idle } };
}

const CHECK_PATH = "/api/v1/admin/scanner-releases/check";

function calls(fetchMock: ReturnType<typeof stubApi>, path: string, method = "GET") {
  return fetchMock.mock.calls.filter(
    ([url, init]) => String(url) === path && ((init as RequestInit | undefined)?.method ?? "GET") === method,
  );
}

describe("AdminHealthPage Check now (#461)", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("runs the scanner release check, refetches health, and refreshes the Scanners card", async () => {
    let checked = false;
    const fetchMock = stubApi((path, init) => {
      if (path === CHECK_PATH && init?.method === "POST") {
        checked = true;
        return json({ scanners: { trivy: "current", grype: "current" } });
      }
      if (path === "/api/v1/admin/health") {
        return json(HEALTH);
      }
      if (path === "/api/v1/about") {
        return json(checked ? about("2026-11-17T10:00:00Z", "v0.76.2") : about(null, null));
      }
      return undefined;
    });
    renderAt(<AdminHealthPage />, "/admin/health");
    expect((await screen.findAllByText(t("admin.scanners.notChecked"))).length).toBe(2);
    const healthBefore = calls(fetchMock, "/api/v1/admin/health").length;
    const aboutBefore = calls(fetchMock, "/api/v1/about").length;

    await userEvent.setup().click(screen.getByRole("button", { name: t("admin.health.checkNow") }));

    await waitFor(() => expect(calls(fetchMock, CHECK_PATH, "POST")).toHaveLength(1));
    await waitFor(() => expect(calls(fetchMock, "/api/v1/admin/health").length).toBeGreaterThan(healthBefore));
    await waitFor(() => expect(calls(fetchMock, "/api/v1/about").length).toBeGreaterThan(aboutBefore));
    await waitFor(() => expect(screen.queryByText(t("admin.scanners.notChecked"))).not.toBeInTheDocument());
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it("shows a fixed error on the Scanners card when the check fails, and keeps the health results", async () => {
    stubApi((path, init) => {
      if (path === CHECK_PATH && init?.method === "POST") {
        return json(
          {
            error: { code: "upstream_unreachable", message: "https://api.github.com failed" },
            kind: "release_check_failed",
            scanners: { trivy: "unavailable", grype: "unavailable" },
          },
          502,
        );
      }
      if (path === "/api/v1/admin/health") {
        return json(HEALTH);
      }
      if (path === "/api/v1/about") {
        return json(about(null, null));
      }
      return undefined;
    });
    renderAt(<AdminHealthPage />, "/admin/health");
    await screen.findAllByText(t("admin.scanners.notChecked"));
    await userEvent.setup().click(screen.getByRole("button", { name: t("admin.health.checkNow") }));

    expect(await screen.findByRole("alert")).toHaveTextContent(t("admin.scanners.check.failed"));
    expect(screen.queryByText(/api\.github\.com/)).not.toBeInTheDocument();
    // The health results stay on the page.
    expect(screen.getByText("203.0.113.24")).toBeInTheDocument();
    expect(screen.getByText("example-org/web")).toBeInTheDocument();
    expect(screen.getByText(t("admin.health.scan.ok"))).toBeInTheDocument();
  });

  it("shows the rate-limit line when the check is refused with 429", async () => {
    stubApi((path, init) => {
      if (path === CHECK_PATH && init?.method === "POST") {
        return new Response(JSON.stringify({ error: { code: "rate_limited", message: "x" } }), {
          status: 429,
          headers: { "Content-Type": "application/json", "Retry-After": "60" },
        });
      }
      if (path === "/api/v1/admin/health") {
        return json(HEALTH);
      }
      if (path === "/api/v1/about") {
        return json(about(null, null));
      }
      return undefined;
    });
    renderAt(<AdminHealthPage />, "/admin/health");
    await screen.findAllByText(t("admin.scanners.notChecked"));
    await userEvent.setup().click(screen.getByRole("button", { name: t("admin.health.checkNow") }));
    expect(await screen.findByRole("alert")).toHaveTextContent(t("admin.scanners.check.rateLimited"));
    expect(screen.getByText("203.0.113.24")).toBeInTheDocument();
  });
});
