import { screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { useLocation } from "react-router";
import { json, renderWithRoutes, stubApi } from "../test/render";
import { RequireAuth } from "./session";

function Where() {
  const location = useLocation();
  return <output data-testid="where">{`${location.pathname}${location.search}`}</output>;
}

const routes = [
  { path: "/login", element: <Where /> },
  { path: "/setup", element: <Where /> },
  { element: <RequireAuth />, children: [{ path: "/", element: <Where /> }] },
];

function signedOut(setupRequired: boolean) {
  return stubApi((path) => {
    if (path === "/api/v1/account/me") {
      return json({ error: { code: "unauthenticated", message: "Sign in." } }, 401);
    }
    if (path === "/api/v1/auth/setup-status") {
      return json({ setup_required: setupRequired, oidc_enabled: false });
    }
    return undefined;
  });
}

describe("RequireAuth", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("redirects to /setup while setup is required", async () => {
    signedOut(true);
    renderWithRoutes(routes, "/");
    expect(await screen.findByTestId("where")).toHaveTextContent(/^\/setup$/);
  });

  it("redirects to /login and keeps the query string", async () => {
    signedOut(false);
    renderWithRoutes(routes, "/?oidc_error=x");
    expect(await screen.findByTestId("where")).toHaveTextContent(/^\/login\?oidc_error=x$/);
  });
});
