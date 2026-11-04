import { fireEvent, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { useLocation } from "react-router";
import { t } from "../i18n";
import { json, renderWithRoutes, stubApi } from "../test/render";
import SetupPage from "./SetupPage";

function Where() {
  const location = useLocation();
  return <output data-testid="where">{`${location.pathname}${location.search}`}</output>;
}

const routes = [
  { path: "/setup", element: <SetupPage /> },
  { path: "/login", element: <Where /> },
  { path: "/", element: <Where /> },
];

function stub(options: { setupRequired?: boolean; setup?: () => Response } = {}) {
  return stubApi((path) => {
    if (path === "/api/v1/auth/setup-status") {
      return json({ setup_required: options.setupRequired ?? true, oidc_enabled: false });
    }
    if (path === "/api/v1/auth/setup" && options.setup !== undefined) {
      return options.setup();
    }
    return undefined;
  });
}

// fireEvent sets the whole value at once, so emoji are not split by typing.
function setPasswords(password: string, confirm = password) {
  fireEvent.change(screen.getByLabelText(t("setup.password")), { target: { value: password } });
  fireEvent.change(screen.getByLabelText(t("setup.confirm")), { target: { value: confirm } });
}

function submitButton() {
  return screen.getByRole("button", { name: t("setup.submit") });
}

describe("SetupPage", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("keeps submit disabled until the password is 15 to 64 characters and matches", async () => {
    stub();
    renderWithRoutes(routes, "/setup");
    await screen.findByLabelText(t("setup.password"));
    expect(submitButton()).toBeDisabled();

    setPasswords("a".repeat(14));
    expect(submitButton()).toBeDisabled();

    setPasswords("a".repeat(15), "a".repeat(15) + "b");
    expect(submitButton()).toBeDisabled();

    setPasswords("a".repeat(15));
    expect(submitButton()).toBeEnabled();

    setPasswords("a".repeat(64));
    expect(submitButton()).toBeEnabled();

    setPasswords("a".repeat(65));
    expect(submitButton()).toBeDisabled();
  });

  it("counts an emoji as one character", async () => {
    stub();
    renderWithRoutes(routes, "/setup");
    await screen.findByLabelText(t("setup.password"));

    // 14 letters and one emoji: 15 characters, but 16 UTF-16 units.
    const fifteen = `${"a".repeat(14)}🔒`;
    setPasswords(fifteen);
    expect(screen.getByText(t("setup.passwordCount", { n: 15 }))).toBeInTheDocument();
    expect(submitButton()).toBeEnabled();

    // 63 letters and one emoji: 64 characters, though `.length` is 65.
    setPasswords(`${"a".repeat(63)}🔒`);
    expect(screen.getByText(t("setup.passwordCount", { n: 64 }))).toBeInTheDocument();
    expect(submitButton()).toBeEnabled();
  });

  it("shows password_too_short from the server", async () => {
    stub({
      setup: () => json({ error: { code: "password_too_short", message: "Too short." } }, 400),
    });
    renderWithRoutes(routes, "/setup");
    await userEvent.type(await screen.findByLabelText(t("setup.username")), "ops-admin");
    await userEvent.type(screen.getByLabelText(t("setup.email")), "ops@example.org");
    setPasswords("correct-horse-battery");
    await userEvent.click(submitButton());

    expect(await screen.findByRole("alert")).toHaveTextContent(t("setup.error.tooShort"));
  });

  it("goes to login when setup is not required", async () => {
    stub({ setupRequired: false });
    renderWithRoutes(routes, "/setup");
    expect(await screen.findByTestId("where")).toHaveTextContent(/^\/login$/);
  });
});
