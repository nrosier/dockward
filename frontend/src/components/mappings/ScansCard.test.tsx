import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { t } from "../../i18n";
import { json, renderWithRoutes, stubApi } from "../../test/render";
import type { Mapping, ScannerList, TagScan } from "../../types/api";
import { ScansCard } from "./ScansCard";

const mapping: Mapping = {
  id: "m1",
  user_id: "u1",
  harbor_cred_id: "hc",
  github_cred_id: "gc",
  harbor_base_url: "https://harbor.example.org",
  harbor_project: "platform",
  harbor_repository: "billing-worker",
  github_owner: "example-org",
  github_repo: "billing",
  default_branch: "main",
  auto_create_issues: true,
  min_issue_severity: "HIGH",
  created_at: null,
  scan_schedule: "off",
  scan_time: "00:00",
  scan_weekday: 1,
};

const TWO: ScannerList = {
  scanner_choice: "available",
  scanners: [
    { uuid: "s1", name: "Trivy", vendor: null, version: null, is_current: true },
    { uuid: "s2", name: "Grype", vendor: null, version: null, is_current: false },
  ],
  switch: null,
};
const ONE: ScannerList = { scanner_choice: "single", scanners: [TWO.scanners[0]], switch: null };

const TAGS = { items: [{ image_tag: "1.0", last_scan_at: "2026-11-06T10:00:00Z", open_cves: 2 }] };

const SCANS: TagScan[] = [
  { scanner_uuid: "s1", scanner_name: "Trivy", unlinked: false, state: "ok", note: null, job_id: "j1", updated_at: null },
  { scanner_uuid: "s2", scanner_name: "Grype", unlinked: false, state: "failed", note: "sync.note.scannerFailed", job_id: "j2", updated_at: null },
];

const SCAN = "/api/v1/mappings/m1/tags/1.0/scan";

function stub(list: ScannerList, post?: () => Response, scans: TagScan[] = SCANS) {
  return stubApi((path, init) => {
    if (path === "/api/v1/mappings/m1/scanners") return json(list);
    if (path === "/api/v1/mappings/m1/tags") return json(TAGS);
    if (path === "/api/v1/mappings/m1/tags/1.0/scans") return json({ items: scans });
    if (path === SCAN && init?.method === "POST") return post?.() ?? json({ job_id: "j9", scanner_uuid: "s1", queued: true }, 202);
    return undefined;
  });
}

const routes = [
  { path: "/mappings/m1", element: <ScansCard mapping={mapping} /> },
  { path: "/sync-jobs", element: <output>jobs</output> },
];

class NoopResizeObserver {
  observe() {}
  unobserve() {}
  disconnect() {}
}

beforeEach(() => {
  vi.stubGlobal("ResizeObserver", NoopResizeObserver);
  // jsdom lacks the pointer-capture and scroll methods Radix Select calls.
  Element.prototype.hasPointerCapture = () => false;
  Element.prototype.releasePointerCapture = () => undefined;
  Element.prototype.setPointerCapture = () => undefined;
  Element.prototype.scrollIntoView = () => undefined;
});
afterEach(() => {
  vi.unstubAllGlobals();
});

const scanButton = () => screen.findByRole("button", { name: t("mapping.scan.button") });

describe("ScansCard", () => {
  it("lists the tag with each scanner's state and the fixed failure reason", async () => {
    stub(TWO);
    renderWithRoutes(routes, "/mappings/m1");
    expect(await screen.findByText("1.0")).toBeInTheDocument();
    expect(await screen.findByText("Trivy")).toBeInTheDocument();
    expect(screen.getByText(t("mapping.scan.state.ok"))).toBeInTheDocument();
    expect(screen.getByText(t("mapping.scan.state.failed"))).toBeInTheDocument();
    expect(screen.getByText(t("sync.note.scannerFailed"))).toBeInTheDocument();
  });

  it("shows the report's scanner name marked as not linked for an unknown registration (#277)", async () => {
    const scans: TagScan[] = [
      { scanner_uuid: "s1", scanner_name: "Trivy", unlinked: false, state: "ok", note: null, job_id: null, updated_at: null },
      { scanner_uuid: "unknown", scanner_name: "Grype", unlinked: true, state: "ok", note: null, job_id: null, updated_at: null },
    ];
    stub(TWO, undefined, scans);
    renderWithRoutes(routes, "/mappings/m1");
    const grype = await screen.findByText("Grype");
    expect(grype.parentElement).toHaveTextContent(`Grype${t("mapping.scan.notLinked")}`);
    expect(screen.getAllByText(t("mapping.scan.notLinked"))).toHaveLength(1);
    expect(screen.getByText("Trivy").parentElement).not.toHaveTextContent(t("mapping.scan.notLinked"));
  });

  it("shows Unknown scanner with no suffix when the report has no name", async () => {
    const scans: TagScan[] = [
      { scanner_uuid: "unknown", scanner_name: "Unknown scanner", unlinked: false, state: "ok", note: null, job_id: null, updated_at: null },
    ];
    stub(TWO, undefined, scans);
    renderWithRoutes(routes, "/mappings/m1");
    expect(await screen.findByText("Unknown scanner")).toBeInTheDocument();
    expect(screen.queryByText(t("mapping.scan.notLinked"))).toBeNull();
  });

  it("takes its rows from the mapping tag route, in its order, and not from sync jobs", async () => {
    const fetchMock = stubApi((path) => {
      if (path === "/api/v1/mappings/m1/scanners") return json(ONE);
      if (path === "/api/v1/mappings/m1/tags") {
        return json({
          items: [
            { image_tag: "2.0", last_scan_at: "2026-11-06T10:00:00Z", open_cves: 1 },
            { image_tag: "1.5", last_scan_at: "2026-11-01T10:00:00Z", open_cves: 0 },
          ],
        });
      }
      if (path.endsWith("/scans")) return json({ items: [] });
      return undefined;
    });
    renderWithRoutes(routes, "/mappings/m1");
    expect(await screen.findByText("2.0")).toBeInTheDocument();
    expect(await screen.findByText("1.5")).toBeInTheDocument();
    const shown = screen.getAllByRole("row").slice(1).map((row) => row.querySelector("td")?.textContent);
    expect(shown).toEqual(["2.0", "1.5"]);
    const paths = fetchMock.mock.calls.map(([input]) => String(input));
    expect(paths).toContain("/api/v1/mappings/m1/tags");
    expect(paths.some((path) => path.includes("/sync-jobs"))).toBe(false);
  });

  it("shows the empty note when the tag route returns no tags", async () => {
    stubApi((path) => {
      if (path === "/api/v1/mappings/m1/scanners") return json(ONE);
      if (path === "/api/v1/mappings/m1/tags") return json({ items: [] });
      return undefined;
    });
    renderWithRoutes(routes, "/mappings/m1");
    expect(await screen.findByText(t("mapping.scan.noTags"))).toBeInTheDocument();
  });

  it("shows Not scanned for a tag without reports", async () => {
    stub(ONE, undefined, []);
    renderWithRoutes(routes, "/mappings/m1");
    expect(await screen.findByText(t("mapping.scan.notScanned"))).toBeInTheDocument();
  });

  it("shows the picker only with several scanners, and Start stays disabled until one is chosen", async () => {
    const fetchMock = stub(TWO);
    renderWithRoutes(routes, "/mappings/m1");
    await userEvent.click(await scanButton());
    expect(screen.getByText(t("mapping.scan.chooseScanner"))).toBeInTheDocument();
    expect(screen.getByRole("button", { name: t("mapping.scan.start") })).toBeDisabled();
    expect(fetchMock.mock.calls.some(([, init]) => (init as RequestInit | undefined)?.method === "POST")).toBe(false);

    await userEvent.click(screen.getByRole("combobox"));
    await userEvent.click(await screen.findByRole("option", { name: "Grype" }));
    await userEvent.click(screen.getByRole("button", { name: t("mapping.scan.start") }));
    expect(await screen.findByText(t("mapping.scan.queued"))).toBeInTheDocument();
    const post = fetchMock.mock.calls.find(([url]) => String(url) === SCAN);
    expect(post?.[1]?.body).toBe(JSON.stringify({ scanner_uuid: "s2" }));
  });

  it("starts at once with no picker for a single scanner", async () => {
    const fetchMock = stub(ONE);
    renderWithRoutes(routes, "/mappings/m1");
    await userEvent.click(await scanButton());
    expect(await screen.findByText(t("mapping.scan.queued"))).toBeInTheDocument();
    expect(screen.queryByRole("combobox")).not.toBeInTheDocument();
    const post = fetchMock.mock.calls.find(([url]) => String(url) === SCAN);
    expect(post?.[1]?.method).toBe("POST");
    expect(post?.[1]?.body).toBeUndefined();
  });

  it("shows the no-access note and still starts a scan when the list is unavailable", async () => {
    stub({ scanner_choice: "unavailable", scanners: [], switch: null });
    renderWithRoutes(routes, "/mappings/m1");
    expect(await screen.findByText(t("mapping.scan.noScannerAccess"))).toBeInTheDocument();
    await userEvent.click(await scanButton());
    expect(await screen.findByText(t("mapping.scan.queued"))).toBeInTheDocument();
  });

  it("shows the catalog text for a 409 already running, not the server text", async () => {
    stub(ONE, () =>
      json({ error: { code: "conflict", message: "A scan with this scanner is already in progress." } }, 409),
    );
    renderWithRoutes(routes, "/mappings/m1");
    await userEvent.click(await scanButton());
    expect(await screen.findByRole("alert")).toHaveTextContent(t("mapping.scan.alreadyRunning"));
  });

  it("shows the restore-waiting text for the other 409", async () => {
    stub(ONE, () => json({ error: { code: "conflict", message: t("mapping.scan.restoreWaiting") } }, 409));
    renderWithRoutes(routes, "/mappings/m1");
    await userEvent.click(await scanButton());
    expect(await screen.findByRole("alert")).toHaveTextContent(t("mapping.scan.restoreWaiting"));
  });

  it("shows the cooldown text for 429 and the generic text for another failure", async () => {
    stub(ONE, () => json({ error: { code: "rate_limited", message: "x" } }, 429));
    const first = renderWithRoutes(routes, "/mappings/m1");
    await userEvent.click(await scanButton());
    expect(await screen.findByRole("alert")).toHaveTextContent(t("mapping.scan.cooldown"));
    first.unmount();

    stub(ONE, () => json({ error: { code: "internal_error", message: "x" } }, 500));
    renderWithRoutes(routes, "/mappings/m1");
    await userEvent.click(await scanButton());
    expect(await screen.findByRole("alert")).toHaveTextContent(t("errors.generic"));
  });

  it("shows the switch banner while the project scanner is switched", async () => {
    stub({ ...ONE, switch: { scanner_name: "Grype", state: "switched" } });
    renderWithRoutes(routes, "/mappings/m1");
    expect(await screen.findByText(t("mapping.scan.switchActive", { scanner: "Grype" }))).toBeInTheDocument();
  });

  it("shows the restore failed banner with a Sync jobs link", async () => {
    const failed: TagScan[] = [
      { scanner_uuid: "s1", scanner_name: "Trivy", unlinked: false, state: "failed", note: "sync.note.restoreFailed", job_id: "j1", updated_at: null },
    ];
    stub({ ...ONE, switch: { scanner_name: "Grype", state: "restore_pending" } }, undefined, failed);
    renderWithRoutes(routes, "/mappings/m1");
    expect(await screen.findByText(t("mapping.scan.restorePending"))).toBeInTheDocument();
    expect(await screen.findByText(new RegExp(t("mapping.scan.restoreFailed")))).toBeInTheDocument();
    expect(screen.getByRole("link", { name: t("mapping.pull.viewSyncJobs") })).toHaveAttribute("href", "/sync-jobs");
  });
});
