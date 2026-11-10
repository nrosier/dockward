import { screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { t } from "../i18n";
import { ME_QUERY_KEY } from "../lib/session";
import { json, renderAt, stubApi, testQueryClient, user } from "../test/render";
import AdminUsersPage from "./AdminUsersPage";

const admin = { ...user("admin"), id: "u1", username: "ops-admin" };
const local = { ...user("user"), id: "u2", username: "j.devries" };
const sso = { ...user("admin"), id: "u3", username: "m.kaya", auth_provider: "oidc" as const };

const oidc = {
  issuer_url: null,
  client_id: null,
  role_claim: "groups",
  admin_group: "dockward-admins",
  user_group: "dockward-users",
  client_secret_set: true,
  oidc_only_users: false,
};

function stub(role?: (init?: RequestInit) => Response) {
  return stubApi((path, init) => {
    if (path === "/api/v1/admin/users") {
      return json([admin, local, sso]);
    }
    if (path === "/api/v1/admin/oidc") {
      return json(oidc);
    }
    if (path === "/api/v1/admin/users/u2/role" && role) {
      return role(init);
    }
    return undefined;
  });
}

function render() {
  const client = testQueryClient();
  client.setQueryData(ME_QUERY_KEY, admin);
  return renderAt(<AdminUsersPage />, "/admin/settings/users", client);
}

describe("AdminUsersPage", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("OIDC users have no role select", async () => {
    stub();
    render();
    const row = (await screen.findByText("m.kaya")).closest("tr") as HTMLElement;
    expect(within(row).queryByRole("combobox")).toBeNull();
    expect(await within(row).findByText(t("admin.users.fromGroup", { group: "dockward-admins" }))).toBeInTheDocument();
    const localRow = screen.getByText("j.devries").closest("tr") as HTMLElement;
    expect(within(localRow).getByRole("combobox")).toBeInTheDocument();
    // Delete is disabled for yourself.
    expect(screen.getByRole("button", { name: t("admin.users.deleteAria", { name: "ops-admin" }) })).toBeDisabled();
  });

  it("reverts the role select on 409", async () => {
    stub(() => json({ error: { code: "conflict", message: "Conflict." } }, 409));
    render();
    const select = await screen.findByLabelText(t("admin.users.roleFor", { name: "j.devries" }));
    expect(select).toHaveValue("user");
    await userEvent.selectOptions(select, "admin");
    expect(await screen.findByText(t("admin.users.lastAdmin"))).toBeInTheDocument();
    expect(screen.getByLabelText(t("admin.users.roleFor", { name: "j.devries" }))).toHaveValue("user");
  });
});
