import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { t } from "../../i18n";
import { json, renderAt, stubApi, user } from "../../test/render";
import JobsPage from "../../pages/JobsPage";

function stub(count: number, purge: () => Response = () => json({ deleted: count })) {
  return stubApi((path, init) => {
    if (path === "/api/v1/account/me") return json({ user: user("user") });
    if (path.startsWith("/api/v1/jobs/failed-count")) return json({ count });
    if (path.startsWith("/api/v1/jobs/purge-failed") && init?.method === "POST") return purge();
    if (path.startsWith("/api/v1/jobs")) return json({ items: [], page: 1, page_size: 50, total: 0 });
    if (path.startsWith("/api/v1/mappings")) return json({ items: [], page: 1, page_size: 200, total: 0 });
    return undefined;
  });
}

function calls(fetchMock: ReturnType<typeof stub>, fragment: string, method?: string) {
  return fetchMock.mock.calls.filter(
    ([path, init]) => String(path).includes(fragment) && (method === undefined || init?.method === method),
  );
}

describe("PurgeFailed", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("is disabled when the count is zero", async () => {
    const fetchMock = stub(0);
    renderAt(<JobsPage />);
    await vi.waitFor(() => expect(calls(fetchMock, "/jobs/failed-count")).toHaveLength(1));
    expect(screen.getByRole("button", { name: t("jobs.purge.button") })).toBeDisabled();
  });

  it("shows the count in the dialog, then purges once and refreshes the list", async () => {
    const fetchMock = stub(3);
    renderAt(<JobsPage />);
    const button = screen.getByRole("button", { name: t("jobs.purge.button") });
    await vi.waitFor(() => expect(button).toBeEnabled());
    await userEvent.click(button);
    expect(screen.getByText(t("jobs.purge.body", { count: 3 }))).toBeInTheDocument();
    const listBefore = calls(fetchMock, "/jobs?").length;
    await userEvent.click(screen.getByRole("button", { name: t("jobs.purge.confirm", { count: 3 }) }));
    expect(await screen.findByRole("status")).toHaveTextContent(t("jobs.purge.success", { count: 3 }));
    expect(calls(fetchMock, "/jobs/purge-failed", "POST")).toHaveLength(1);
    await vi.waitFor(() => expect(calls(fetchMock, "/jobs?").length).toBeGreaterThan(listBefore));
  });

  it("cancel sends no purge request", async () => {
    const fetchMock = stub(2);
    renderAt(<JobsPage />);
    const button = screen.getByRole("button", { name: t("jobs.purge.button") });
    await vi.waitFor(() => expect(button).toBeEnabled());
    await userEvent.click(button);
    await userEvent.click(screen.getByRole("button", { name: t("jobs.purge.cancel") }));
    expect(calls(fetchMock, "/jobs/purge-failed", "POST")).toHaveLength(0);
  });

  it("a failure shows the catalog message and keeps the dialog open", async () => {
    stub(2, () => json({ error: { code: "internal", message: "server secret text" } }, 500));
    renderAt(<JobsPage />);
    const button = screen.getByRole("button", { name: t("jobs.purge.button") });
    await vi.waitFor(() => expect(button).toBeEnabled());
    await userEvent.click(button);
    await userEvent.click(screen.getByRole("button", { name: t("jobs.purge.confirm", { count: 2 }) }));
    expect(await screen.findByText(t("jobs.purge.failed"))).toBeInTheDocument();
    expect(screen.queryByText("server secret text")).not.toBeInTheDocument();
    expect(screen.getByRole("dialog")).toBeInTheDocument();
  });
});
