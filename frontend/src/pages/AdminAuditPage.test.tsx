import { screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { json, renderAt, stubApi } from "../test/render";
import AdminAuditPage, { describeDetails } from "./AdminAuditPage";

describe("AdminAuditPage", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("renders details as text, not HTML", async () => {
    const hostile = '<img src=x onerror="alert(1)">';
    stubApi((path) => {
      if (path.startsWith("/api/v1/admin/audit-log")) {
        return json({
          items: [
            {
              id: "a1",
              actor_user_id: "u1",
              actor_username: "ops-admin",
              action: "user.create",
              target: "j.devries",
              created_at: 1_793_000_000,
              details: { note: hostile, role: "user" },
            },
          ],
          page: 1,
          page_size: 50,
          total: 1,
        });
      }
      if (path === "/api/v1/admin/users") {
        return json([{ id: "u1", username: "ops-admin", email: "o@example.test", role: "admin", auth_provider: "local", created_at: "2026-11-03T09:00:00Z" }]);
      }
      return undefined;
    });
    const { container } = renderAt(<AdminAuditPage />, "/admin/audit");
    expect(await screen.findByText(`note: ${hostile}, role: user`)).toBeInTheDocument();
    expect(container.querySelector("img")).toBeNull();
    // The actor filter is filled from the bare user array.
    expect(await screen.findByRole("option", { name: "ops-admin" })).toBeInTheDocument();
  });

  it("describes details as key and value pairs", () => {
    expect(describeDetails(null)).toBe("");
    expect(describeDetails({ a: "b", n: 2 })).toBe("a: b, n: 2");
  });
});
