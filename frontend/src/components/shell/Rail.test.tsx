import { screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import en from "../../i18n/en.json";
import { json, renderAt, stubApi, user } from "../../test/render";
import { Rail } from "./Rail";

describe("Rail", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("renders the app name from the catalog", () => {
    stubApi(() => undefined);
    renderAt(<Rail collapsed={false} onToggle={() => {}} />);
    expect(screen.getByText(en["app.name"])).toBeInTheDocument();
    expect(en["app.name"]).toBe("Dockward");
  });

  it("hides Admin for regular users", async () => {
    stubApi((path) => (path === "/api/v1/account/me" ? json({ user: user("user") }) : undefined));
    renderAt(<Rail collapsed={false} onToggle={() => {}} />);
    // Wait for the user to load, so the check is not made before /me resolves.
    expect(await screen.findByText("dev")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Account" })).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "Admin" })).not.toBeInTheDocument();
  });

  it("shows Admin for admins", async () => {
    stubApi((path) => (path === "/api/v1/account/me" ? json({ user: user("admin") }) : undefined));
    renderAt(<Rail collapsed={false} onToggle={() => {}} />, "/admin/jobs");
    const admin = await screen.findByRole("link", { name: "Admin" });
    expect(admin).toHaveAttribute("href", "/admin");
    expect(admin).toHaveAttribute("aria-current", "page");
  });
});
