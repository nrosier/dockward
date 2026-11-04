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
      if (path.startsWith("/api/v1/admin/users")) {
        return json({ items: [], page: 1, page_size: 200, total: 0 });
      }
      return undefined;
    });
    const { container } = renderAt(<AdminAuditPage />, "/admin/audit");
    expect(await screen.findByText(`note: ${hostile}, role: user`)).toBeInTheDocument();
    expect(container.querySelector("img")).toBeNull();
  });

  it("describes details as key and value pairs", () => {
    expect(describeDetails(null)).toBe("");
    expect(describeDetails({ a: "b", n: 2 })).toBe("a: b, n: 2");
  });
});
