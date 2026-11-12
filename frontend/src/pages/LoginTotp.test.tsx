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
  return <output data-testid="where">{location.pathname}</output>;
}

const routes = [
  { path: "/login", element: <LoginPage /> },
  { path: "/", element: <Where /> },
];

const PASSWORD = ["pw", "for", "totp", "tests", "1234"].join("-");
const CODE = ["12", "34", "56"].join("");
const RECOVERY = "ABCD-EFGH";

function stub(verify: (body: { code: string }) => Response) {
  return stubApi((path, init) => {
    if (path === "/api/v1/auth/setup-status") {
      return json({ setup_required: false, oidc_enabled: false });
    }
    if (path === "/api/v1/auth/login") {
      return json({ totp_required: true });
    }
    if (path === "/api/v1/auth/totp/verify") {
      return verify(JSON.parse(String(init?.body)) as { code: string });
    }
    return undefined;
  });
}

async function passwordStep() {
  await userEvent.type(await screen.findByLabelText(t("login.username")), "dev");
  await userEvent.type(screen.getByLabelText(t("login.password")), PASSWORD);
  await userEvent.click(screen.getByRole("button", { name: t("login.submit") }));
}

describe("LoginPage TOTP step", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("swaps the card to a code prompt, drops the password fields, and focuses the code", async () => {
    stub(() => json({ user: user("user") }));
    renderWithRoutes(routes, "/login");
    await passwordStep();
    const field = await screen.findByLabelText(t("login.totp.code"));
    expect(field).toHaveFocus();
    expect(field).toHaveAttribute("autocomplete", "one-time-code");
    expect(field).toHaveAttribute("inputmode", "numeric");
    expect(screen.getByRole("heading", { name: t("login.totp.title") })).toBeInTheDocument();
    expect(screen.getByText(t("login.totp.help"))).toBeInTheDocument();
    expect(screen.getByText(t("login.totp.timeout"))).toBeInTheDocument();
    expect(screen.queryByLabelText(t("login.username"))).not.toBeInTheDocument();
    expect(screen.queryByLabelText(t("login.password"))).not.toBeInTheDocument();
  });

  it("verifies the code, stores the user and goes to the dashboard", async () => {
    const fetchMock = stub(() => json({ user: user("user") }));
    const { client } = renderWithRoutes(routes, "/login");
    await passwordStep();
    await userEvent.type(await screen.findByLabelText(t("login.totp.code")), CODE);
    await userEvent.click(screen.getByRole("button", { name: t("login.totp.submit") }));
    expect(await screen.findByTestId("where")).toHaveTextContent("/");
    expect(client.getQueryData(ME_QUERY_KEY)).toEqual(user("user"));
    const call = fetchMock.mock.calls.find(([path]) => String(path) === "/api/v1/auth/totp/verify");
    expect(call?.[1]?.method).toBe("POST");
    expect(JSON.parse(String(call?.[1]?.body))).toEqual({ code: CODE });
  });

  it("submits on Enter", async () => {
    stub(() => json({ user: user("user") }));
    renderWithRoutes(routes, "/login");
    await passwordStep();
    await userEvent.type(await screen.findByLabelText(t("login.totp.code")), `${CODE}{Enter}`);
    expect(await screen.findByTestId("where")).toBeInTheDocument();
  });

  it("shows the wrong-password text for a wrong code", async () => {
    stub(() => json({ error: { code: "invalid_credentials", message: "Invalid." } }, 401));
    renderWithRoutes(routes, "/login");
    await passwordStep();
    await userEvent.type(await screen.findByLabelText(t("login.totp.code")), CODE);
    await userEvent.click(screen.getByRole("button", { name: t("login.totp.submit") }));
    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toBe(t("login.error.failed"));
    expect(screen.getByLabelText(t("login.totp.code"))).toHaveValue("");
  });

  it("shows the lockout message with the wait in minutes on a 429", async () => {
    stub(
      () =>
        new Response(JSON.stringify({ error: { code: "rate_limited", message: "x" } }), {
          status: 429,
          headers: { "Content-Type": "application/json", "Retry-After": "900" },
        }),
    );
    renderWithRoutes(routes, "/login");
    await passwordStep();
    await userEvent.type(await screen.findByLabelText(t("login.totp.code")), CODE);
    await userEvent.click(screen.getByRole("button", { name: t("login.totp.submit") }));
    expect((await screen.findByRole("alert")).textContent).toBe(t("login.totp.locked", { minutes: 15 }));
  });

  it("switches to a recovery code and back", async () => {
    const fetchMock = stub(() => json({ user: user("user") }));
    renderWithRoutes(routes, "/login");
    await passwordStep();
    await userEvent.click(await screen.findByRole("button", { name: t("login.totp.useRecovery") }));
    const field = screen.getByLabelText(t("login.totp.recovery.code"));
    expect(field).toHaveFocus();
    expect(field).not.toHaveAttribute("inputmode", "numeric");
    expect(field).not.toHaveAttribute("maxlength");
    expect(screen.getByRole("heading", { name: t("login.totp.recovery.title") })).toBeInTheDocument();
    await userEvent.type(field, RECOVERY);
    await userEvent.click(screen.getByRole("button", { name: t("login.totp.submit") }));
    await screen.findByTestId("where");
    const call = fetchMock.mock.calls.find(([path]) => String(path) === "/api/v1/auth/totp/verify");
    expect(JSON.parse(String(call?.[1]?.body))).toEqual({ code: RECOVERY });
  });

  it("goes back to the sign-in form", async () => {
    stub(() => json({ user: user("user") }));
    renderWithRoutes(routes, "/login");
    await passwordStep();
    await userEvent.click(await screen.findByRole("button", { name: t("login.totp.back") }));
    expect(await screen.findByLabelText(t("login.username"))).toBeInTheDocument();
    expect(screen.getByLabelText(t("login.password"))).toHaveValue("");
  });
});
