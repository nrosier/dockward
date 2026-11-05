import { fireEvent, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { AdminLayout } from "../components/shell/AdminLayout";
import { t } from "../i18n";
import { json, renderAt, renderWithRoutes, stubApi } from "../test/render";
import AdminLogPage from "./AdminLogPage";

const LINE = {
  seq: 1,
  timestamp: "2026-11-05T11:14:09Z",
  level: "warn",
  target: "harborgate::services::sync",
  message: "report not yet available… [truncated]",
};

function api(level: string, revertsAt: string | null, items: unknown[] = [LINE]) {
  return (path: string, init?: RequestInit) => {
    if (path.startsWith("/api/v1/admin/logs")) {
      return json({ level, reverts_at: revertsAt, items });
    }
    if (path === "/api/v1/admin/log-level") {
      if (init?.method === "PUT") {
        return json({ level: JSON.parse(String(init.body)).level, reverts_at: "2099-01-01T00:00:00Z" });
      }
      return json({ level, reverts_at: revertsAt });
    }
    return undefined;
  };
}

describe("AdminLogPage", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("renders lines with the truncated marker", async () => {
    stubApi(api("info", null));
    renderAt(<AdminLogPage />, "/admin/log");
    expect(await screen.findByText("harborgate::services::sync")).toBeInTheDocument();
    expect(screen.getByText(t("adminLog.line.truncated"))).toBeInTheDocument();
  });

  it("shows the debug banner while reverts_at is set", async () => {
    stubApi(api("debug", "2099-01-01T00:00:00Z"));
    renderWithRoutes([{ element: <AdminLayout />, children: [{ path: "*", element: <AdminLogPage /> }] }], "/admin/log");
    expect(await screen.findByText(t("adminLog.debugBanner.title"))).toBeInTheDocument();
  });

  it("hides the debug banner when reverts_at is null", async () => {
    stubApi(api("info", null));
    renderWithRoutes([{ element: <AdminLayout />, children: [{ path: "*", element: <AdminLogPage /> }] }], "/admin/log");
    await screen.findByText("harborgate::services::sync");
    expect(screen.queryByText(t("adminLog.debugBanner.title"))).toBeNull();
  });

  it("calls PUT when the level changes", async () => {
    const fetchMock = stubApi(api("info", null));
    renderAt(<AdminLogPage />, "/admin/log");
    const debug = await screen.findByRole("button", { name: "debug" });
    await waitFor(() => expect(debug).toBeEnabled());
    fireEvent.click(debug);
    await waitFor(() => {
      const put = fetchMock.mock.calls.find(([, init]) => init?.method === "PUT");
      expect(String(put?.[0])).toBe("/api/v1/admin/log-level");
      expect(put?.[1]?.body).toBe(JSON.stringify({ level: "debug" }));
    });
  });

  it("sends the filters as the level and q query", async () => {
    const fetchMock = stubApi(api("info", null));
    renderAt(<AdminLogPage />, "/admin/log");
    await screen.findByText("harborgate::services::sync");
    fireEvent.change(screen.getByLabelText(t("adminLog.filter.level")), { target: { value: "warn" } });
    fireEvent.change(screen.getByLabelText(t("adminLog.filter.text")), { target: { value: "backing" } });
    await waitFor(() => {
      const paths = fetchMock.mock.calls.map(([path]) => String(path));
      expect(paths).toContain("/api/v1/admin/logs?level=warn&q=backing");
    });
  });

  it("shows the empty state when no line matches", async () => {
    stubApi(api("info", null, []));
    renderAt(<AdminLogPage />, "/admin/log");
    expect(await screen.findByText(t("adminLog.empty"))).toBeInTheDocument();
  });

  it("shows a fixed message on 403", async () => {
    stubApi((path) =>
      path.startsWith("/api/v1/admin/logs")
        ? json({ error: { code: "forbidden", message: "internal detail" } }, 403)
        : undefined,
    );
    renderAt(<AdminLogPage />, "/admin/log");
    expect(await screen.findByText(t("adminLog.forbidden"))).toBeInTheDocument();
    expect(screen.queryByText("internal detail")).toBeNull();
  });
});
