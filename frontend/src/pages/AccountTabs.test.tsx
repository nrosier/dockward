import { screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { t } from "../i18n";
import { ME_QUERY_KEY } from "../lib/session";
import { json, renderAt, stubApi, testQueryClient, user } from "../test/render";
import { Route, Routes } from "react-router";
import { AccountLayout } from "../components/shell/AccountLayout";
import { ProfileTab } from "./ProfileTab";
import { AppearanceTab } from "./AppearanceTab";
import CredentialsTab from "./CredentialsTab";

function credential(over: Record<string, unknown>) {
  return {
    id: "c1",
    service_type: "harbor",
    label: "harbor-robot",
    base_url: "https://harbor.example.org",
    username: "robot$hg",
    expires_at: null,
    created_at: "2026-10-01T00:00:00Z",
    mapping_count: 0,
    ...over,
  };
}

function stub(items: unknown[], extra?: (path: string, init?: RequestInit) => Response | undefined) {
  return stubApi((path, init) => {
    if (path.startsWith("/api/v1/credentials?")) {
      return json({ items, page: 1, page_size: 200, total: items.length });
    }
    return extra?.(path, init);
  });
}

// Mounts the real account routes at the given tab, so each test reaches its own tab.
function render(
  role: "admin" | "user" = "admin",
  provider: "local" | "oidc" = "local",
  tab: "profile" | "appearance" | "credentials" = "profile",
) {
  const client = testQueryClient();
  client.setQueryData(ME_QUERY_KEY, { ...user(role), auth_provider: provider });
  const routes = (
    <Routes>
      <Route path="/account" element={<AccountLayout />}>
        <Route path="profile" element={<ProfileTab />} />
        <Route path="appearance" element={<AppearanceTab />} />
        <Route path="credentials" element={<CredentialsTab />} />
      </Route>
    </Routes>
  );
  return renderAt(routes, `/account/${tab}`, client);
}

describe("Account tabs", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    window.localStorage.clear();
  });

  it("shows the three account tabs and marks the open one", async () => {
    stub([]);
    render("admin", "local", "appearance");
    const tabs = await screen.findByRole("navigation", { name: t("account.tabs.label") });
    const names = within(tabs).getAllByRole("link").map((link) => link.textContent);
    expect(names).toEqual([
      t("account.tabs.profile"),
      t("account.tabs.appearance"),
      t("account.tabs.credentials"),
    ]);
    expect(within(tabs).getByRole("link", { name: t("account.tabs.appearance") })).toHaveClass("text-text");
  });

  it("keeps the profile section off the appearance tab", async () => {
    stub([]);
    render("admin", "local", "appearance");
    // The appearance heading is in the content, and no profile fields are.
    await screen.findByRole("heading", { name: t("account.appearance.title") });
    expect(screen.queryByText(t("account.profile.username"))).not.toBeInTheDocument();
  });

  it("hides the password card for single sign-on users", async () => {
    stub([]);
    render("user", "oidc");
    await screen.findByText(t("account.profile.sso"));
    expect(screen.queryByText(t("account.password.title"))).not.toBeInTheDocument();
  });

  it("shows the password card for local users", async () => {
    stub([]);
    render();
    expect(await screen.findByText(t("account.password.title"))).toBeInTheDocument();
  });

  it("theme switch stores the theme", async () => {
    stub([]);
    render("admin", "local", "appearance");
    await userEvent.click(await screen.findByRole("button", { name: t("account.appearance.light") }));
    expect(window.localStorage.getItem("hg.theme")).toBe("light");
    expect(document.documentElement.dataset.theme).toBe("light");
    await userEvent.click(screen.getByRole("button", { name: t("account.appearance.dark") }));
    expect(window.localStorage.getItem("hg.theme")).toBe("dark");
  });

  it("shows used by and the expiry warning on credentials", async () => {
    const soon = new Date(Date.now() + 9 * 86_400_000).toISOString();
    stub([
      credential({ id: "c1", label: "soon", expires_at: soon, mapping_count: 4 }),
      credential({ id: "c2", label: "never", expires_at: null, mapping_count: 0 }),
    ]);
    render("admin", "local", "credentials");
    const soonRow = (await screen.findByText("soon")).closest("tr") as HTMLElement;
    expect(within(soonRow).getByText(t("account.credentials.days", { n: 9 }))).toBeInTheDocument();
    expect(within(soonRow).getByText(t("account.credentials.mappings", { n: 4 }))).toBeInTheDocument();
    const neverRow = screen.getByText("never").closest("tr") as HTMLElement;
    expect(within(neverRow).getByText(t("account.credentials.noExpiry"))).toBeInTheDocument();
    expect(within(neverRow).getByText(t("account.credentials.notUsed"))).toBeInTheDocument();
  });

  it("delete conflict explains the credential is in use", async () => {
    stub([credential({ mapping_count: 1 })], (path, init) =>
      path === "/api/v1/credentials/c1" && init?.method === "DELETE"
        ? json({ error: { code: "conflict", message: "In use." } }, 409)
        : undefined,
    );
    render("admin", "local", "credentials");
    await userEvent.click(
      await screen.findByRole("button", { name: t("account.credentials.deleteAria", { label: "harbor-robot" }) }),
    );
    const dialog = await screen.findByRole("dialog");
    await userEvent.click(within(dialog).getByRole("button", { name: t("account.credentials.delete") }));
    expect(await within(dialog).findByText(t("account.credentials.inUse"))).toBeInTheDocument();
  });

  it("tests a GitHub credential with one click and names the repository", async () => {
    let posted: RequestInit | undefined;
    stub([credential({ id: "g1", service_type: "github", label: "gh-pat", base_url: null, username: null })], (path, init) => {
      if (path === "/api/v1/credentials/g1/test" && init?.method === "POST") {
        posted = init;
        return json({
          ok: true,
          repository: "octo/app",
          checks: [{ name: "github_repo", ok: true, detail: "the token can read the repository" }],
        });
      }
      return undefined;
    });
    render("admin", "local", "credentials");
    await userEvent.click(
      await screen.findByRole("button", { name: t("account.credentials.testAria", { label: "gh-pat" }) }),
    );
    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).queryByRole("textbox")).toBeNull();
    await userEvent.click(within(dialog).getByRole("button", { name: t("account.credentials.test") }));
    expect(await within(dialog).findByText(t("credentials.test.repository", { name: "octo/app" }))).toBeInTheDocument();
    expect(posted?.body).toBeUndefined();
  });
});
