import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { t } from "../../i18n";
import { json, renderAt, stubApi } from "../../test/render";
import { ScannersPanel } from "./ScannersPanel";

const idle = {
  in_use: "bundled",
  downloaded_version: null,
  broken_version: null,
  previous_version: null,
  latest_version: null,
  update_available: false,
  checked_at: null,
};

function about(trivy: Record<string, unknown> = {}, grype: Record<string, unknown> = {}) {
  return {
    dockward: "0.8.0",
    trivy: "v0.76.2",
    grype: "v0.121.3",
    scanners: { trivy: { ...idle, ...trivy }, grype: { ...idle, ...grype } },
  };
}

const UPDATE = {
  latest_version: "v0.77.0",
  update_available: true,
  checked_at: "2026-11-14T06:12:00Z",
};

const INSTALL_PATH = "/api/v1/admin/scanners/trivy/install";
const ROLLBACK_PATH = "/api/v1/admin/scanners/trivy/rollback";
const CLEAR_PATH = "/api/v1/admin/scanners/trivy/clear-broken";

function posts(fetchMock: ReturnType<typeof stubApi>, path: string) {
  return fetchMock.mock.calls.filter(
    ([url, init]) => String(url) === path && (init as RequestInit | undefined)?.method === "POST",
  );
}

function refusal(status: number, kind?: string) {
  return json({ error: { code: "conflict", message: "/data/scanners/trivy failed" }, kind }, status);
}

describe("ScannersPanel", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("shows the Update available pill and an Install button when update_available", async () => {
    stubApi((path) =>
      path === "/api/v1/about" ? json(about(UPDATE, { latest_version: "v0.121.3" })) : undefined,
    );
    renderAt(<ScannersPanel />);
    expect(await screen.findByText(t("admin.scanners.status.update"))).toBeInTheDocument();
    expect(screen.getByText(t("admin.scanners.status.upToDate"))).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Install v0\.77\.0/ })).toBeEnabled();
  });

  it("shows Bundled, with a disabled Install, when nothing was checked or downloaded", async () => {
    stubApi((path) => (path === "/api/v1/about" ? json(about()) : undefined));
    renderAt(<ScannersPanel />);
    expect((await screen.findAllByText(t("admin.scanners.status.bundled"))).length).toBe(2);
    expect(screen.queryByText(t("admin.scanners.status.update"))).not.toBeInTheDocument();
    for (const button of screen.getAllByRole("button", { name: t("admin.scanners.install") })) {
      expect(button).toBeDisabled();
    }
  });

  it("opens a confirmation from Install; Cancel makes no call", async () => {
    const fetchMock = stubApi((path) => (path === "/api/v1/about" ? json(about(UPDATE)) : undefined));
    renderAt(<ScannersPanel />);
    const user = userEvent.setup();
    await user.click(await screen.findByRole("button", { name: /Install v0\.77\.0/ }));
    const dialog = await screen.findByRole("dialog", { name: "Install Trivy v0.77.0?" });
    expect(posts(fetchMock, INSTALL_PATH)).toHaveLength(0);
    await user.click(within(dialog).getByRole("button", { name: t("common.cancel") }));
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
    expect(posts(fetchMock, INSTALL_PATH)).toHaveLength(0);
  });

  it("posts install exactly once on confirm, then refreshes the About data", async () => {
    let aboutCalls = 0;
    const fetchMock = stubApi((path) => {
      if (path === "/api/v1/about") {
        aboutCalls += 1;
        return json(about(UPDATE));
      }
      if (path === INSTALL_PATH) {
        return json({ scanner: "trivy", version: "v0.77.0" });
      }
      return undefined;
    });
    renderAt(<ScannersPanel />);
    const user = userEvent.setup();
    await user.click(await screen.findByRole("button", { name: /Install v0\.77\.0/ }));
    const dialog = await screen.findByRole("dialog");
    await user.click(within(dialog).getByRole("button", { name: "Install v0.77.0" }));
    await waitFor(() => expect(posts(fetchMock, INSTALL_PATH)).toHaveLength(1));
    await waitFor(() => expect(aboutCalls).toBe(2));
    expect(posts(fetchMock, INSTALL_PATH)).toHaveLength(1);
    expect(screen.queryByText(t("admin.scanners.failed.title"))).not.toBeInTheDocument();
  });

  it("calls nothing on the install or rollback routes without a confirmation", async () => {
    const fetchMock = stubApi((path) =>
      path === "/api/v1/about"
        ? json(about({ ...UPDATE, in_use: "downloaded", downloaded_version: "v0.76.5", previous_version: "v0.76.2" }))
        : undefined,
    );
    renderAt(<ScannersPanel />);
    const user = userEvent.setup();
    await user.click(await screen.findByRole("button", { name: /Install v0\.77\.0/ }));
    await user.keyboard("{Escape}");
    await user.click(await screen.findByRole("button", { name: /Roll back to v0\.76\.2/ }));
    await user.keyboard("{Escape}");
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
    const writes = fetchMock.mock.calls.filter(([, init]) => (init as RequestInit | undefined)?.method === "POST");
    expect(writes).toHaveLength(0);
  });

  it("closes the dialog on Escape and returns focus to the Install button", async () => {
    stubApi((path) => (path === "/api/v1/about" ? json(about(UPDATE)) : undefined));
    renderAt(<ScannersPanel />);
    const user = userEvent.setup();
    const button = await screen.findByRole("button", { name: /Install v0\.77\.0/ });
    button.focus();
    await user.keyboard("{Enter}");
    await screen.findByRole("dialog");
    await user.keyboard("{Escape}");
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
    await waitFor(() => expect(button).toHaveFocus());
  });

  it("shows the mapped failure with no path, and clears it on the next attempt", async () => {
    let calls = 0;
    stubApi((path) => {
      if (path === "/api/v1/about") {
        return json(about(UPDATE));
      }
      if (path === INSTALL_PATH) {
        calls += 1;
        return calls === 1 ? refusal(502, "signature_invalid") : json({ scanner: "trivy", version: "v0.77.0" });
      }
      return undefined;
    });
    renderAt(<ScannersPanel />);
    const user = userEvent.setup();
    await user.click(await screen.findByRole("button", { name: /Install v0\.77\.0/ }));
    await user.click(within(await screen.findByRole("dialog")).getByRole("button", { name: "Install v0.77.0" }));
    expect(await screen.findByText(t("admin.scanners.failed.title"))).toBeInTheDocument();
    expect(screen.getByText(/the Sigstore bundle did not verify/)).toBeInTheDocument();
    expect(screen.getByText(/Trivy v0\.76\.2 is still in use/)).toBeInTheDocument();
    expect(document.body.textContent).not.toContain("/data/scanners");

    await user.click(screen.getByRole("button", { name: /Install v0\.77\.0/ }));
    await user.click(within(await screen.findByRole("dialog")).getByRole("button", { name: "Install v0.77.0" }));
    await waitFor(() => expect(screen.queryByText(t("admin.scanners.failed.title"))).not.toBeInTheDocument());
  });

  it("maps every install kind to its own message", async () => {
    const kinds = [
      "scanner_busy",
      "unsupported_platform",
      "bundled_version_unknown",
      "release_unavailable",
      "not_newer_than_bundled",
      "already_installed",
      "download_failed",
      "download_too_large",
      "checksum_missing",
      "checksum_mismatch",
      "signature_invalid",
      "archive_refused",
      "storage_failed",
    ] as const;
    const { failureReason } = await import("./ScannersPanel");
    const { ApiError } = await import("../../lib/api");
    const seen = new Set<string>();
    for (const kind of kinds) {
      const text = failureReason(new ApiError(502, "x", "/data/p", undefined, undefined, kind));
      expect(text).not.toBe(t("admin.scanners.failed.unknown"));
      expect(text).not.toContain("/");
      seen.add(text);
    }
    expect(seen.size).toBe(kinds.length);
    expect(failureReason(new ApiError(500, "x", "boom"))).toBe(t("admin.scanners.failed.unknown"));
  });

  it("shows a 429 as its own rate limit message", async () => {
    stubApi((path) => {
      if (path === "/api/v1/about") {
        return json(about(UPDATE));
      }
      if (path === INSTALL_PATH) {
        return new Response(JSON.stringify({ error: { code: "rate_limited", message: "Too many requests." } }), {
          status: 429,
          headers: { "Retry-After": "60" },
        });
      }
      return undefined;
    });
    renderAt(<ScannersPanel />);
    const user = userEvent.setup();
    await user.click(await screen.findByRole("button", { name: /Install v0\.77\.0/ }));
    await user.click(within(await screen.findByRole("dialog")).getByRole("button", { name: "Install v0.77.0" }));
    expect(await screen.findByText(/too many install attempts/)).toBeInTheDocument();
  });

  it("shows the broken card only when broken_version is set, and Clear posts clear-broken", async () => {
    let cleared = false;
    const fetchMock = stubApi((path) => {
      if (path === "/api/v1/about") {
        return json(cleared ? about() : about({ broken_version: "v0.78.0" }));
      }
      if (path === CLEAR_PATH) {
        cleared = true;
        return json({ scanner: "trivy", version: "v0.78.0" });
      }
      return undefined;
    });
    renderAt(<ScannersPanel />);
    expect(await screen.findByText(t("admin.scanners.broken.title"))).toBeInTheDocument();
    expect(screen.getByText(/Trivy v0\.78\.0 did not start/)).toBeInTheDocument();
    const user = userEvent.setup();
    await user.click(screen.getByRole("button", { name: t("admin.scanners.broken.clear") }));
    await waitFor(() => expect(posts(fetchMock, CLEAR_PATH)).toHaveLength(1));
    await waitFor(() => expect(screen.queryByText(t("admin.scanners.broken.title"))).not.toBeInTheDocument());
  });

  it("hides the broken card when nothing is broken", async () => {
    stubApi((path) => (path === "/api/v1/about" ? json(about()) : undefined));
    renderAt(<ScannersPanel />);
    await screen.findByText(t("admin.scanners.title"));
    expect(screen.queryByText(t("admin.scanners.broken.title"))).not.toBeInTheDocument();
  });

  it("hides the data-volume card with no downloaded version", async () => {
    stubApi((path) => (path === "/api/v1/about" ? json(about(UPDATE)) : undefined));
    renderAt(<ScannersPanel />);
    await screen.findByText(t("admin.scanners.title"));
    expect(screen.queryByText(t("admin.scanners.volume.title"))).not.toBeInTheDocument();
  });

  it("shows the data-volume card with a downloaded version", async () => {
    stubApi((path) =>
      path === "/api/v1/about"
        ? json(about({ in_use: "downloaded", downloaded_version: "v0.77.0", previous_version: "v0.76.5" }))
        : undefined,
    );
    renderAt(<ScannersPanel />);
    expect(await screen.findByText(t("admin.scanners.volume.title"))).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Roll back to v0\.76\.5/ })).toBeEnabled();
    expect(screen.getByText(t("admin.scanners.status.verified"))).toBeInTheDocument();
  });

  it("disables Roll back when previous_version is null and shows None", async () => {
    stubApi((path) =>
      path === "/api/v1/about"
        ? json(about({ in_use: "downloaded", downloaded_version: "v0.77.0", previous_version: null }))
        : undefined,
    );
    renderAt(<ScannersPanel />);
    await screen.findByText(t("admin.scanners.volume.title"));
    expect(screen.getByText(t("admin.scanners.none"))).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Roll back/ })).toBeDisabled();
  });

  it("asks before rolling back, then posts rollback and refreshes", async () => {
    let aboutCalls = 0;
    const fetchMock = stubApi((path) => {
      if (path === "/api/v1/about") {
        aboutCalls += 1;
        return json(about({ in_use: "downloaded", downloaded_version: "v0.77.0", previous_version: "v0.76.5" }));
      }
      if (path === ROLLBACK_PATH) {
        return json({ scanner: "trivy", version: "v0.76.5" });
      }
      return undefined;
    });
    renderAt(<ScannersPanel />);
    const user = userEvent.setup();
    await user.click(await screen.findByRole("button", { name: /Roll back to v0\.76\.5/ }));
    const dialog = await screen.findByRole("dialog", { name: "Roll back Trivy to v0.76.5?" });
    expect(posts(fetchMock, ROLLBACK_PATH)).toHaveLength(0);
    await user.click(within(dialog).getByRole("button", { name: t("admin.scanners.rollback") }));
    await waitFor(() => expect(posts(fetchMock, ROLLBACK_PATH)).toHaveLength(1));
    await waitFor(() => expect(aboutCalls).toBe(2));
  });
});
