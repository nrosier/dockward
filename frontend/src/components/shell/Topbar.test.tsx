import { screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { json, renderAt, stubApi, user } from "../../test/render";
import { Topbar } from "./Topbar";

const HEALTH = "/api/v1/admin/health";

describe("Topbar", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("makes no health request for regular users", async () => {
    const fetchMock = stubApi((path) => {
      if (path === "/api/v1/account/me") {
        return json({ user: user("user") });
      }
      if (path === HEALTH) {
        return json({ harbor: [], github: [], robot_accounts: [] });
      }
      return undefined;
    });
    const { client } = renderAt(<Topbar onMenu={() => {}} />);
    await waitFor(() => expect(client.getQueryData(["me"])).toEqual(user("user")));
    expect(screen.getByRole("button", { name: "Sign out" })).toBeInTheDocument();
    // Give any follow-up query a chance to fire before asserting it did not.
    await new Promise((resolve) => setTimeout(resolve, 20));
    const paths = fetchMock.mock.calls.map((call) => String(call[0]));
    expect(paths).toContain("/api/v1/account/me");
    expect(paths).not.toContain(HEALTH);
    expect(screen.queryByRole("status", { name: "Environment status" })).not.toBeInTheDocument();
  });

  it("shows the robot expiry badge within 14 days for admins", async () => {
    stubApi((path) => {
      if (path === "/api/v1/account/me") {
        return json({ user: user("admin") });
      }
      if (path === HEALTH) {
        return json({
          harbor: [{ ok: true, reachable: true }],
          github: [{ ok: true, reachable: true }],
          robot_accounts: [
            { credential_id: "c1", label: "far", expires_at: "2027-06-01T00:00:00Z", days_left: 200 },
            { credential_id: "c2", label: "soon", expires_at: "2026-11-13T00:00:00Z", days_left: 9 },
            { credential_id: "c3", label: "never", expires_at: null, days_left: null },
          ],
          request: { client_ip: "203.0.113.9", source: "peer" },
        });
      }
      return undefined;
    });
    renderAt(<Topbar onMenu={() => {}} />);
    const badge = await screen.findByRole("link", { name: "Robot account expires in 9 days" });
    expect(badge).toHaveAttribute("href", "/admin/health");
    expect(screen.getByText("Harbor reachable")).toBeInTheDocument();
    expect(screen.getByText("GitHub reachable")).toBeInTheDocument();
  });

  it("shows no robot badge when every expiry is more than 14 days away", async () => {
    stubApi((path) => {
      if (path === "/api/v1/account/me") {
        return json({ user: user("admin") });
      }
      if (path === HEALTH) {
        return json({
          harbor: [{ ok: true, reachable: true }],
          github: [],
          robot_accounts: [{ credential_id: "c1", label: "x", expires_at: "2026-11-20T00:00:00Z", days_left: 15 }],
        });
      }
      return undefined;
    });
    renderAt(<Topbar onMenu={() => {}} />);
    expect(await screen.findByText("Harbor reachable")).toBeInTheDocument();
    expect(screen.queryByText(/Robot account/)).not.toBeInTheDocument();
  });
});
