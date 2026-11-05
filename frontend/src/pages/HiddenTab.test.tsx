import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { t } from "../i18n";
import { json, renderWithRoutes, stubApi } from "../test/render";
import type { HiddenItem } from "../types/api";
import HiddenTab from "./HiddenTab";

const items: HiddenItem[] = [
  { id: "h1", source: "harbor", full_name: "shared-name", harbor_base_url: "https://harbor-prod.example.org", created_at: "2026-11-05T10:12:00Z" },
  { id: "h2", source: "harbor", full_name: "shared-name", harbor_base_url: "https://harbor-lab.example.org", created_at: "2026-11-04T10:12:00Z" },
  { id: "h3", source: "github", full_name: "nrosier/old-service", harbor_base_url: null, created_at: "2026-11-03T18:03:00Z" },
];

class NoopResizeObserver { observe() {} unobserve() {} disconnect() {} }

function stub(state: { items: HiddenItem[]; total?: number; del?: () => Response } = { items }) {
  let current = state.items;
  return stubApi((path, init) => {
    const url = new URL(path, "http://x");
    if (url.pathname === "/api/v1/pickers/hidden" && (init?.method ?? "GET") === "GET") {
      const source = url.searchParams.get("source");
      const shown = source === null ? current : current.filter((i) => i.source === source);
      const size = Number(url.searchParams.get("page_size"));
      const pageNo = Number(url.searchParams.get("page"));
      const total = size === 1 ? (state.total ?? current.length) : (state.total ?? shown.length);
      return json({ items: shown.slice((pageNo - 1) * size, pageNo * size), page: pageNo, page_size: size, total });
    }
    if (url.pathname.startsWith("/api/v1/pickers/hidden/") && init?.method === "DELETE") {
      const id = url.pathname.split("/").pop();
      const res = state.del?.() ?? new Response(null, { status: 204 });
      if (res.ok) current = current.filter((i) => i.id !== id);
      return res;
    }
    return undefined;
  });
}

const routes = [{ path: "/account/hidden", element: <HiddenTab /> }];

describe("Hidden tab", () => {
  beforeEach(() => { vi.stubGlobal("ResizeObserver", NoopResizeObserver); });
  afterEach(() => { vi.unstubAllGlobals(); });

  it("lists the same name on two Harbor instances, and the GitHub no-instance label", async () => {
    stub();
    renderWithRoutes(routes, "/account/hidden");
    const table = await screen.findByRole("table");
    expect(within(table).getAllByRole("cell", { name: "shared-name" })).toHaveLength(2);
    expect(within(table).getByText("https://harbor-prod.example.org")).toBeInTheDocument();
    expect(within(table).getByText("https://harbor-lab.example.org")).toBeInTheDocument();
    expect(within(table).getByText(t("mapping.hidden.noInstance"))).toBeInTheDocument();
    expect(screen.getByText(t("mapping.hidden.instanceNote"))).toBeInTheDocument();
  });

  it("asks newest first", async () => {
    const fetchMock = stub();
    renderWithRoutes(routes, "/account/hidden");
    await screen.findByRole("table");
    const url = fetchMock.mock.calls.map((c) => String(c[0])).find((u) => u.includes("sort=created_at")) ?? "";
    expect(url).toContain("order=desc");
  });

  it("shows the count against the cap and the cap note", async () => {
    stub();
    renderWithRoutes(routes, "/account/hidden");
    expect(await screen.findByText(t("mapping.hidden.count", { count: 3, cap: 1000 }))).toBeInTheDocument();
    expect(screen.getByText(t("mapping.hidden.capNote"))).toBeInTheDocument();
  });

  it("Restore calls DELETE without a confirmation and refreshes", async () => {
    const fetchMock = stub();
    renderWithRoutes(routes, "/account/hidden");
    await screen.findByRole("table");
    await userEvent.click(screen.getByRole("button", { name: `${t("mapping.hidden.restore")}nrosier/old-service` }));
    await waitFor(() => expect(screen.queryByText("nrosier/old-service")).not.toBeInTheDocument());
    const del = fetchMock.mock.calls.find((c) => (c[1] as RequestInit | undefined)?.method === "DELETE");
    expect(String(del?.[0])).toBe("/api/v1/pickers/hidden/h3");
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("filters by source", async () => {
    const fetchMock = stub();
    renderWithRoutes(routes, "/account/hidden");
    await screen.findByRole("table");
    await userEvent.click(screen.getByRole("button", { name: t("mapping.hidden.filterGithub") }));
    await waitFor(() => expect(screen.queryAllByText("shared-name")).toHaveLength(0));
    expect(fetchMock.mock.calls.some((c) => String(c[0]).includes("source=github"))).toBe(true);
  });

  it("pages through the list", async () => {
    const many = Array.from({ length: 30 }, (_, i) => ({ ...items[2], id: `x${i}`, full_name: `o/r${i}` }));
    const fetchMock = stub({ items: many });
    renderWithRoutes(routes, "/account/hidden");
    await screen.findByRole("table");
    await userEvent.click(screen.getByRole("button", { name: t("pagination.next") }));
    await waitFor(() => expect(fetchMock.mock.calls.some((c) => String(c[0]).includes("page=2&page_size=25"))).toBe(true));
  });

  it("an empty list shows the empty text", async () => {
    stub({ items: [] });
    renderWithRoutes(routes, "/account/hidden");
    expect(await screen.findByText(t("mapping.hidden.empty"))).toBeInTheDocument();
  });
});
