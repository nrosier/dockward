import { fireEvent, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { t } from "../i18n";
import { json, renderWithRoutes, stubApi } from "../test/render";
import CredentialFormPage from "./CredentialFormPage";

const routes = [
  { path: "/account/credentials/new", element: <CredentialFormPage /> },
  { path: "/account/credentials/:id", element: <CredentialFormPage /> },
  { path: "/account", element: <p>account</p> },
];

const saved = { id: "c9", service_type: "harbor", label: "x", base_url: null, username: null, expires_at: null };
const passed = { ok: true, checks: [{ name: "harbor_robot", ok: true, detail: "the robot account credential works" }] };

function bodyOf(call: unknown[] | undefined): Record<string, unknown> {
  return JSON.parse(String(((call ?? [])[1] as RequestInit).body)) as Record<string, unknown>;
}

describe("CredentialFormPage", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("save and test saves then shows the check results", async () => {
    const fetchMock = stubApi((path, init) => {
      if (path === "/api/v1/credentials" && init?.method === "POST") {
        return json(saved, 201);
      }
      if (path === "/api/v1/credentials/c9/test") {
        return json(passed);
      }
      return undefined;
    });
    renderWithRoutes(routes, "/account/credentials/new");
    fireEvent.change(screen.getByLabelText(t("credentials.form.label")), { target: { value: "harbor-robot" } });
    fireEvent.change(screen.getByLabelText(t("credentials.form.baseUrl")), { target: { value: "https://harbor.example.org" } });
    fireEvent.change(screen.getByLabelText(t("credentials.form.robot")), { target: { value: "robot$hg" } });
    fireEvent.change(screen.getByLabelText(t("credentials.form.robotSecret")), { target: { value: "s3cret-value" } });
    fireEvent.change(screen.getByLabelText(t("credentials.form.expires")), { target: { value: "2027-11-03" } });
    await userEvent.click(screen.getByRole("button", { name: t("credentials.saveAndTest") }));

    expect(await screen.findByText("the robot account credential works")).toBeInTheDocument();
    expect(screen.getByText(t("credentials.test.title"))).toBeInTheDocument();
    expect(screen.getByRole("link", { name: t("credentials.done") })).toBeInTheDocument();
    const post = fetchMock.mock.calls.find((call) => (call[1] as RequestInit).method === "POST");
    expect(bodyOf(post).expires_at).toBe(Date.parse("2027-11-03T23:59:59Z") / 1000);
    // The secret is cleared from the form after the save.
    expect(screen.getByLabelText(t("credentials.form.robotSecret"))).toHaveValue("");
  });

  it("sends owner and repo with the GitHub test", async () => {
    const fetchMock = stubApi((path, init) => {
      if (path === "/api/v1/credentials" && init?.method === "POST") {
        return json({ ...saved, service_type: "github" }, 201);
      }
      if (path === "/api/v1/credentials/c9/test") {
        return json(passed);
      }
      return undefined;
    });
    renderWithRoutes(routes, "/account/credentials/new");
    await userEvent.click(screen.getByRole("button", { name: t("credentials.service.github") }));
    fireEvent.change(screen.getByLabelText(t("credentials.form.label")), { target: { value: "gh" } });
    fireEvent.change(screen.getByLabelText(t("credentials.form.githubToken")), { target: { value: "ghp_token" } });
    fireEvent.change(screen.getByLabelText(t("credentials.form.owner")), { target: { value: "example-org" } });
    fireEvent.change(screen.getByLabelText(t("credentials.form.repo")), { target: { value: "billing" } });
    await userEvent.click(screen.getByRole("button", { name: t("credentials.saveAndTest") }));

    await screen.findByText(t("credentials.test.title"));
    const test = fetchMock.mock.calls.find((call) => String(call[0]).endsWith("/test"));
    expect(bodyOf(test)).toEqual({ owner: "example-org", repo: "billing" });
    const post = fetchMock.mock.calls.find((call) => String(call[0]) === "/api/v1/credentials");
    expect(bodyOf(post)).not.toHaveProperty("owner");
    expect(bodyOf(post)).not.toHaveProperty("repo");
  });

  it("editing sends no token when the field is empty", async () => {
    const existing = { ...saved, id: "c1", label: "old", base_url: "https://harbor.example.org", username: "robot$hg" };
    const fetchMock = stubApi((path, init) => {
      if (path.startsWith("/api/v1/credentials?")) {
        return json({ items: [existing], page: 1, page_size: 200, total: 1 });
      }
      if (path === "/api/v1/credentials/c1" && init?.method === "PUT") {
        return json(existing);
      }
      if (path === "/api/v1/credentials/c1/test") {
        return json(passed);
      }
      return undefined;
    });
    renderWithRoutes(routes, "/account/credentials/c1");
    const label = await screen.findByLabelText(t("credentials.form.label"));
    expect(screen.getByLabelText(t("credentials.form.robotSecret"))).toHaveAttribute(
      "placeholder",
      t("credentials.form.keepToken"),
    );
    await userEvent.clear(label);
    await userEvent.type(label, "renamed");
    await userEvent.click(screen.getByRole("button", { name: t("credentials.saveAndTest") }));

    await screen.findByText(t("credentials.test.title"));
    const put = fetchMock.mock.calls.find((call) => (call[1] as RequestInit).method === "PUT");
    expect(bodyOf(put)).not.toHaveProperty("token");
    expect(bodyOf(put).label).toBe("renamed");
  });
});
