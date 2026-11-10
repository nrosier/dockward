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
        return json({ github: [] });
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

  it("shows GitHub reachability for admins and no Harbor or robot badge", async () => {
    stubApi((path) => {
      if (path === "/api/v1/account/me") {
        return json({ user: user("admin") });
      }
      if (path === HEALTH) {
        return json({
          github: [{ ok: true, reachable: true }],
          request: { client_ip: "203.0.113.9", source: "peer" },
        });
      }
      return undefined;
    });
    renderAt(<Topbar onMenu={() => {}} />);
    expect(await screen.findByText("GitHub reachable")).toBeInTheDocument();
    expect(screen.queryByText(/Harbor/)).not.toBeInTheDocument();
    expect(screen.queryByText(/Robot account/)).not.toBeInTheDocument();
  });
});
