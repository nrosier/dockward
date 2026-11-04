import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { useLocation } from "react-router";
import { t } from "../i18n";
import { ME_QUERY_KEY } from "../lib/session";
import { json, renderWithRoutes, stubApi, user } from "../test/render";
import LoginPage from "./LoginPage";

function Where() {
  const location = useLocation();
  return <output data-testid="where">{`${location.pathname}${location.search}`}</output>;
}

const routes = [
  { path: "/login", element: <LoginPage /> },
  { path: "/setup", element: <Where /> },
  { path: "/", element: <Where /> },
];

function stub(options: { setupRequired?: boolean; oidc?: boolean; login?: () => Response } = {}) {
  return stubApi((path) => {
    if (path === "/api/v1/auth/setup-status") {
      return json({ setup_required: options.setupRequired ?? false, oidc_enabled: options.oidc ?? false });
    }
    if (path === "/api/v1/auth/login" && options.login !== undefined) {
      return options.login();
    }
    return undefined;
  });
}

async function signIn(password = "a-wrong-password") {
  await userEvent.type(await screen.findByLabelText(t("login.username")), "ops-admin");
  await userEvent.type(screen.getByLabelText(t("login.password")), password);
  await userEvent.click(screen.getByRole("button", { name: t("login.submit") }));
}

describe("LoginPage", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("shows the single sign-on button only when OIDC is enabled", async () => {
    stub({ oidc: true });
    const first = renderWithRoutes(routes, "/login");
    const link = await screen.findByRole("link", { name: t("login.sso") });
    expect(link).toHaveAttribute("href", "/api/v1/auth/oidc/start");
    expect(screen.getByText(t("login.divider"))).toBeInTheDocument();
    first.unmount();
    vi.unstubAllGlobals();

    stub({ oidc: false });
    renderWithRoutes(routes, "/login");
    expect(await screen.findByLabelText(t("login.username"))).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: t("login.sso") })).not.toBeInTheDocument();
    expect(screen.queryByText(t("login.divider"))).not.toBeInTheDocument();
  });

  it("shows the same message for invalid_credentials and csrf_invalid", async () => {
    const responses = [
      json({ error: { code: "invalid_credentials", message: "Invalid username or password." } }, 401),
      json({ error: { code: "csrf_invalid", message: "Cross-site request refused." } }, 403),
    ];
    stub({ login: () => responses.shift() ?? json({}, 500) });
    renderWithRoutes(routes, "/login");

    await signIn();
    const first = await screen.findByRole("alert");
    expect(first).toHaveTextContent(t("login.error.failed"));
    expect(screen.getByLabelText(t("login.password"))).toHaveValue("");

    await userEvent.type(screen.getByLabelText(t("login.password")), "another-password");
    await userEvent.click(screen.getByRole("button", { name: t("login.submit") }));
    const second = await screen.findByRole("alert");
    expect(second).toHaveTextContent(t("login.error.failed"));
    expect(second.textContent).toBe(t("login.error.failed"));
    expect(screen.queryByText(/csrf_invalid|invalid_credentials|Cross-site/)).not.toBeInTheDocument();
    expect(screen.getByLabelText(t("login.password"))).toHaveValue("");
  });

  it("shows the single sign-on error and removes oidc_error from the URL", async () => {
    stub({ oidc: true });
    const { router } = renderWithRoutes(routes, "/login?oidc_error=group_denied");
    expect(await screen.findByRole("alert")).toHaveTextContent(t("login.error.sso"));
    await vi.waitFor(() => expect(router.state.location.search).toBe(""));
    expect(router.state.location.pathname).toBe("/login");
    expect(screen.getByRole("alert")).toHaveTextContent(t("login.error.sso"));
    expect(screen.queryByText(/group_denied/)).not.toBeInTheDocument();
  });

  it("goes to setup while setup is required", async () => {
    stub({ setupRequired: true });
    renderWithRoutes(routes, "/login");
    expect(await screen.findByTestId("where")).toHaveTextContent(/^\/setup$/);
  });

  it("signs in and navigates to the dashboard", async () => {
    const admin = user("admin");
    const fetchMock = stub({ login: () => json({ user: admin }) });
    const { client } = renderWithRoutes(routes, "/login");

    await signIn("correct-horse-battery");
    expect(await screen.findByTestId("where")).toHaveTextContent(/^\/$/);
    expect(client.getQueryData(ME_QUERY_KEY)).toEqual(admin);

    const call = fetchMock.mock.calls.find(([path]) => String(path) === "/api/v1/auth/login");
    expect(call?.[1]?.method).toBe("POST");
    expect(JSON.parse(String(call?.[1]?.body))).toEqual({ username: "ops-admin", password: "correct-horse-battery" });
  });
});
