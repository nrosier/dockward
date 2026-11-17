import { fireEvent, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { t } from "../i18n";
import { json, renderAt, stubApi } from "../test/render";
import AdminAlertsPage from "./AdminAlertsPage";

const channel = {
  id: "ch1",
  kind: "smtp",
  enabled: true,
  created_at: "2026-10-30T00:00:00Z",
  updated_at: "2026-11-02T00:00:00Z",
};

const emptySettings = { smtp: null };
const savedSettings = {
  smtp: {
    host: "smtp.example.org",
    port: 587,
    tls: "starttls",
    username: "mailer",
    from: "hg@example.org",
    to: ["a@example.org", "b@example.org"],
    password_set: true,
  },
};

describe("AdminAlertsPage", () => {
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

  it("sends to addresses as an array and clears config after save", async () => {
    const fetchMock = stubApi((path, init) => {
      if (path.startsWith("/api/v1/admin/alert-channels?")) {
        return json({ items: [channel], page: 1, page_size: 200, total: 1 });
      }
      if (path === "/api/v1/admin/alert-channels/ch1/settings") {
        return json(emptySettings);
      }
      if (path === "/api/v1/admin/alert-channels/ch1" && init?.method === "PUT") {
        return json(channel);
      }
      return undefined;
    });
    renderAt(<AdminAlertsPage />, "/admin/settings/alerts");
    await userEvent.click(await screen.findByRole("button", { name: t("account.credentials.edit") }));

    fireEvent.change(await screen.findByLabelText(t("admin.alerts.host")), { target: { value: "smtp.example.org" } });
    fireEvent.change(screen.getByLabelText(t("admin.alerts.port")), { target: { value: "465" } });
    fireEvent.change(screen.getByLabelText(t("admin.alerts.password")), { target: { value: "smtp-pass" } });
    fireEvent.change(screen.getByLabelText(t("admin.alerts.from")), { target: { value: "hg@example.org" } });
    fireEvent.change(screen.getByLabelText(t("admin.alerts.to")), { target: { value: "a@example.org,  b@example.org " } });
    await userEvent.click(screen.getByRole("button", { name: t("admin.alerts.save") }));

    await vi.waitFor(() => expect(screen.queryByLabelText(t("admin.alerts.host"))).toBeNull());
    const put = fetchMock.mock.calls.find((call) => (call[1] as RequestInit | undefined)?.method === "PUT");
    const body = JSON.parse(String(((put ?? [])[1] as RequestInit).body)) as {
      enabled: boolean;
      config: Record<string, unknown>;
    };
    expect(body.config.to).toEqual(["a@example.org", "b@example.org"]);
    expect(body.config.port).toBe(465);
    expect(body.config.tls).toBe("implicit");
    expect(body.enabled).toBe(true);

    // Opening the form again shows nothing from the last submit.
    await userEvent.click(screen.getByRole("button", { name: t("account.credentials.edit") }));
    expect(await screen.findByLabelText(t("admin.alerts.password"))).toHaveValue("");
    expect(screen.getByLabelText(t("admin.alerts.to"))).toHaveValue("");
  });

  it("fills the edit form from the saved settings, never the password", async () => {
    const fetchMock = stubApi((path, init) => {
      if (path.startsWith("/api/v1/admin/alert-channels?")) {
        return json({ items: [channel], page: 1, page_size: 200, total: 1 });
      }
      if (path === "/api/v1/admin/alert-channels/ch1/settings") {
        return json(savedSettings);
      }
      if (path === "/api/v1/admin/alert-channels/ch1" && init?.method === "PUT") {
        return json(channel);
      }
      return undefined;
    });
    renderAt(<AdminAlertsPage />, "/admin/settings/alerts");
    await userEvent.click(await screen.findByRole("button", { name: t("account.credentials.edit") }));

    expect(await screen.findByLabelText(t("admin.alerts.host"))).toHaveValue("smtp.example.org");
    expect(screen.getByLabelText(t("admin.alerts.port"))).toHaveValue("587");
    expect(screen.getByLabelText(t("admin.alerts.username"))).toHaveValue("mailer");
    expect(screen.getByLabelText(t("admin.alerts.from"))).toHaveValue("hg@example.org");
    expect(screen.getByLabelText(t("admin.alerts.to"))).toHaveValue("a@example.org, b@example.org");
    expect(screen.getByLabelText(t("admin.alerts.password"))).toHaveValue("");
    expect(screen.getByRole("button", { name: t("admin.alerts.starttls") })).toHaveAttribute("aria-pressed", "true");

    // Saving without a new password keeps the saved one.
    await userEvent.click(screen.getByRole("button", { name: t("admin.alerts.save") }));
    await vi.waitFor(() => expect(screen.queryByLabelText(t("admin.alerts.host"))).toBeNull());
    const put = fetchMock.mock.calls.find((call) => (call[1] as RequestInit | undefined)?.method === "PUT");
    const body = JSON.parse(String(((put ?? [])[1] as RequestInit).body)) as { config: Record<string, unknown> };
    expect(body.config.keep_password).toBe(true);
    expect(body.config).not.toHaveProperty("password");
    expect(body.config.tls).toBe("starttls");
  });

  it("sends a test email with the form values and shows the result", async () => {
    const fetchMock = stubApi((path, init) => {
      if (path.startsWith("/api/v1/admin/alert-channels?")) {
        return json({ items: [channel], page: 1, page_size: 200, total: 1 });
      }
      if (path === "/api/v1/admin/alert-channels/ch1/settings") {
        return json(savedSettings);
      }
      if (path === "/api/v1/admin/alert-channels/test" && init?.method === "POST") {
        return json({ ok: false, error: "alert delivery failed to connect" });
      }
      return undefined;
    });
    renderAt(<AdminAlertsPage />, "/admin/settings/alerts");
    await userEvent.click(await screen.findByRole("button", { name: t("account.credentials.edit") }));
    await screen.findByLabelText(t("admin.alerts.host"));
    await userEvent.click(screen.getByRole("button", { name: t("admin.alerts.test") }));

    expect(
      await screen.findByText(t("admin.alerts.testFailed", { reason: "alert delivery failed to connect" })),
    ).toBeInTheDocument();
    const post = fetchMock.mock.calls.find((call) => (call[1] as RequestInit | undefined)?.method === "POST");
    const body = JSON.parse(String(((post ?? [])[1] as RequestInit).body)) as {
      channel_id: string;
      config: Record<string, unknown>;
    };
    expect(body.channel_id).toBe("ch1");
    expect(body.config.host).toBe("smtp.example.org");
    expect(body.config.keep_password).toBe(true);
  });

  it("has no delete control and toggles enabled with only that field", async () => {
    const fetchMock = stubApi((path, init) => {
      if (path.startsWith("/api/v1/admin/alert-channels?")) {
        return json({ items: [channel], page: 1, page_size: 200, total: 1 });
      }
      if (path === "/api/v1/admin/alert-channels/ch1" && init?.method === "PUT") {
        return json({ ...channel, enabled: false });
      }
      return undefined;
    });
    renderAt(<AdminAlertsPage />, "/admin/settings/alerts");
    await screen.findByRole("switch");
    expect(screen.queryByRole("button", { name: /delete/i })).toBeNull();
    await userEvent.click(screen.getByRole("switch"));
    await vi.waitFor(() =>
      expect(fetchMock.mock.calls.some((call) => (call[1] as RequestInit | undefined)?.method === "PUT")).toBe(true),
    );
    const put = fetchMock.mock.calls.find((call) => (call[1] as RequestInit | undefined)?.method === "PUT");
    expect(JSON.parse(String(((put ?? [])[1] as RequestInit).body))).toEqual({ enabled: false });
  });
});
