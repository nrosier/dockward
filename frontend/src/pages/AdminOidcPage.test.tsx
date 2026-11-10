import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { t } from "../i18n";
import { json, renderAt, stubApi } from "../test/render";
import AdminOidcPage from "./AdminOidcPage";

const settings = {
  issuer_url: "https://login.example.org/realms/platform",
  client_id: "harborgate",
  role_claim: "groups",
  admin_group: "dockward-admins",
  user_group: "dockward-users",
  client_secret_set: true,
  oidc_only_users: false,
};

function putBodies(fetchMock: ReturnType<typeof stubApi>): Record<string, unknown>[] {
  return fetchMock.mock.calls
    .filter((call) => (call[1] as RequestInit | undefined)?.method === "PUT")
    .map((call) => JSON.parse(String((call[1] as RequestInit).body)) as Record<string, unknown>);
}

describe("AdminOidcPage", () => {
  beforeEach(() => {
    vi.stubGlobal(
      "ResizeObserver",
      class {
        observe() {}
        unobserve() {}
        disconnect() {}
      },
    );
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("sends client_secret only when filled", async () => {
    const fetchMock = stubApi((path) => {
      if (path === "/api/v1/admin/oidc") {
        return json(settings);
      }
      return undefined;
    });
    renderAt(<AdminOidcPage />, "/admin/settings/oidc");
    const save = await screen.findByRole("button", { name: t("admin.oidc.save") });
    expect(screen.getByText(t("admin.oidc.secretSet"))).toBeInTheDocument();

    await userEvent.click(save);
    await screen.findByText(t("admin.oidc.saved"));
    expect(putBodies(fetchMock)[0]).not.toHaveProperty("client_secret");

    const secret = screen.getByLabelText(t("admin.oidc.secret"));
    await userEvent.type(secret, "new-secret-value");
    await userEvent.click(screen.getByRole("button", { name: t("admin.oidc.save") }));
    await vi.waitFor(() => expect(putBodies(fetchMock)).toHaveLength(2));
    expect(putBodies(fetchMock)[1].client_secret).toBe("new-secret-value");
    // Cleared from the form after the submit.
    await vi.waitFor(() => expect(screen.getByLabelText(t("admin.oidc.secret"))).toHaveValue(""));
  });

  it("shows the server message on 422", async () => {
    stubApi((path, init) => {
      if (path === "/api/v1/admin/oidc" && init?.method === "PUT") {
        return json({ error: { code: "validation_failed", message: "Issuer must be HTTPS." } }, 422);
      }
      return path === "/api/v1/admin/oidc" ? json(settings) : undefined;
    });
    renderAt(<AdminOidcPage />, "/admin/settings/oidc");
    await userEvent.click(await screen.findByRole("button", { name: t("admin.oidc.save") }));
    expect(await screen.findByText("Issuer must be HTTPS.")).toBeInTheDocument();
  });
});
