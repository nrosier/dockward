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

const saved = { id: "c9", service_type: "github", label: "x", base_url: null, username: null, expires_at: null };
const passed = { ok: true, checks: [{ name: "github_repo", ok: true, detail: "the token works" }] };

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
    fireEvent.change(screen.getByLabelText(t("credentials.form.label")), { target: { value: "gh" } });
    fireEvent.change(screen.getByLabelText(t("credentials.form.githubToken")), { target: { value: "s3cret-value" } });
    fireEvent.change(screen.getByLabelText(t("credentials.form.expires")), { target: { value: "2027-11-03" } });
    await userEvent.click(screen.getByRole("button", { name: t("credentials.saveAndTest") }));

    expect(await screen.findByText("the token works")).toBeInTheDocument();
    expect(screen.getByText(t("credentials.test.title"))).toBeInTheDocument();
    expect(screen.getByRole("link", { name: t("credentials.done") })).toBeInTheDocument();
    const post = fetchMock.mock.calls.find((call) => (call[1] as RequestInit).method === "POST");
    expect(bodyOf(post).expires_at).toBe(Date.parse("2027-11-03T23:59:59Z") / 1000);
    // The secret is cleared from the form after the save.
    expect(screen.getByLabelText(t("credentials.form.githubToken"))).toHaveValue("");
  });

  it("GitHub form has no owner or repository field and the test sends no body", async () => {
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
    expect(document.getElementById("cred-owner")).toBeNull();
    expect(document.getElementById("cred-repo")).toBeNull();
    fireEvent.change(screen.getByLabelText(t("credentials.form.label")), { target: { value: "gh" } });
    fireEvent.change(screen.getByLabelText(t("credentials.form.githubToken")), { target: { value: "ghp_token" } });
    const submit = screen.getByRole("button", { name: t("credentials.saveAndTest") });
    expect(submit).toBeEnabled();
    await userEvent.click(submit);

    await screen.findByText(t("credentials.test.title"));
    const test = fetchMock.mock.calls.find((call) => String(call[0]).endsWith("/test"));
    expect(test?.[1]?.body).toBeUndefined();
    const post = fetchMock.mock.calls.find((call) => String(call[0]) === "/api/v1/credentials");
    expect(bodyOf(post)).not.toHaveProperty("owner");
    expect(bodyOf(post)).not.toHaveProperty("repo");
  });

  it("editing sends no token when the field is empty", async () => {
    const existing = { ...saved, id: "c1", label: "old" };
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
    expect(screen.getByLabelText(t("credentials.form.githubToken"))).toHaveAttribute(
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
