import { screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { t } from "../i18n";
import { json, renderAt, stubApi, user } from "../test/render";
import type { CveSummary } from "../types/api";
import CvesPage from "./CvesPage";

const medium: CveSummary = {
  id: "m1:CVE-2026-0002",
  mapping_id: "m1",
  cve_id: "CVE-2026-0002",
  severity: "MEDIUM",
  open_severity: "MEDIUM",
  status: "open",
  package: "libfoo",
  first_seen_at: null,
  last_seen_at: null,
  github_issue_url: null,
  accepted: false,
  fixed_in_version: null,
  open_tags: 2,
  tracked_tags: 10,
  github_issue_number: null,
  github_issue_status: null,
};

const mapping = { id: "m1", user_id: "u1", harbor_project: "platform", harbor_repository: "api" };

function row(over: Partial<CveSummary>): CveSummary {
  return { ...medium, ...over };
}

function stub(items: CveSummary[] = [medium], onIssue?: (path: string) => void) {
  return stubApi((path, init) => {
    if (path === "/api/v1/account/me") return json({ user: user("user") });
    if (path.endsWith("/issue") && init?.method === "POST") {
      onIssue?.(path);
      return json({ github_issue_url: "https://github.com/o/r/issues/1", github_issue_number: 1 }, 201);
    }
    if (path.startsWith("/api/v1/cves")) return json({ items, page: 1, page_size: 50, total: items.length });
    if (path.startsWith("/api/v1/mappings")) return json({ items: [mapping], page: 1, page_size: 200, total: 1 });
    return undefined;
  });
}

function cvesCalls(fetchMock: ReturnType<typeof stub>): string[] {
  return fetchMock.mock.calls.map(([path]) => String(path)).filter((path) => path.startsWith("/api/v1/cves?"));
}

describe("CvesPage", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("sends every severity by default and Open as status=open&accepted=false", async () => {
    const fetchMock = stub();
    renderAt(<CvesPage />);
    await screen.findByText("CVE-2026-0002");
    const query = new URLSearchParams(cvesCalls(fetchMock)[0].split("?")[1]);
    expect(query.get("severity")).toBeNull();
    expect(query.get("status")).toBe("open");
    expect(query.get("accepted")).toBe("false");
  });

  it("turns the filter controls into a comma-separated query string", async () => {
    const fetchMock = stub();
    renderAt(<CvesPage />);
    await screen.findByText("CVE-2026-0002");
    const severity = screen.getByRole("group", { name: t("cves.filter.severity") });
    await userEvent.click(within(severity).getByRole("button", { name: "LOW" }));
    await userEvent.click(within(severity).getByRole("button", { name: "UNKNOWN" }));
    const status = screen.getByRole("group", { name: t("cves.filter.status") });
    await userEvent.click(within(status).getByRole("button", { name: t("cves.status.fixed") }));
    await userEvent.type(screen.getByLabelText(t("cves.filter.package")), "openssl");
    await vi.waitFor(() => {
      const query = new URLSearchParams(cvesCalls(fetchMock).at(-1)?.split("?")[1]);
      expect(query.get("severity")).toBe("CRITICAL,HIGH,MEDIUM");
      expect(query.get("status")).toBe("open,fixed");
      expect(query.get("package")).toBe("openssl");
      expect(query.get("accepted")).toBeNull();
    });
  });

  it("shows active-filter chips and Clear all restores the default view", async () => {
    stub();
    renderAt(<CvesPage />, "/cves?severity=HIGH&tag=1.42.0");
    await screen.findByText("CVE-2026-0002");
    expect(screen.getByText(t("cves.filter.active", { n: 2 }))).toBeInTheDocument();
    expect(screen.getByText(t("cves.filter.chip.tag", { value: "1.42.0" }))).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: t("cves.filter.clearAll") }));
    expect(screen.queryByText(t("cves.filter.clearAll"))).not.toBeInTheDocument();
    expect(within(screen.getByRole("group", { name: t("cves.filter.severity") })).getByRole("button", { name: "LOW" })).toHaveAttribute(
      "aria-pressed",
      "true",
    );
  });

  it("renders all five severity pills with text labels", async () => {
    const items = (["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"] as const).map((severity, i) =>
      row({ id: `m1:CVE-${i}`, cve_id: `CVE-${i}`, severity, open_severity: severity }),
    );
    stub(items);
    renderAt(<CvesPage />);
    await screen.findByText("CVE-0");
    for (const key of ["pill.critical", "pill.high", "pill.medium", "pill.low", "pill.unknown"] as const) {
      const cell = screen.getAllByText(t(key)).find((el) => el.closest("tbody") !== null);
      expect(cell).toBeDefined();
    }
  });

  it("creates a MEDIUM issue in one click", async () => {
    const onIssue = vi.fn();
    stub([medium], onIssue);
    renderAt(<CvesPage />);
    await userEvent.click(await screen.findByRole("button", { name: t("cves.action.createIssue") }));
    await vi.waitFor(() => expect(onIssue).toHaveBeenCalledWith("/api/v1/cves/m1%3ACVE-2026-0002/issue"));
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it.each(["LOW", "UNKNOWN"] as const)("asks for confirmation before a %s issue", async (severity) => {
    const onIssue = vi.fn();
    stub([row({ severity, open_severity: severity })], onIssue);
    renderAt(<CvesPage />);
    await userEvent.click(await screen.findByRole("button", { name: t("cves.action.createIssue") }));
    const dialog = await screen.findByRole("dialog");
    expect(onIssue).not.toHaveBeenCalled();
    await userEvent.click(within(dialog).getByRole("button", { name: t("mappings.cancel") }));
    expect(onIssue).not.toHaveBeenCalled();
    await userEvent.click(screen.getByRole("button", { name: t("cves.action.createIssue") }));
    await userEvent.click(within(await screen.findByRole("dialog")).getByRole("button", { name: t("cves.confirm.create") }));
    await vi.waitFor(() => expect(onIssue).toHaveBeenCalledTimes(1));
  });

  it("offers no Create issue for a CVE fixed on every tag", async () => {
    stub([row({ severity: "CRITICAL", open_severity: null, status: "fixed" })]);
    renderAt(<CvesPage />);
    const cell = (await screen.findByText("CVE-2026-0002")).closest("tr") as HTMLElement;
    expect(within(cell).queryByRole("button", { name: t("cves.action.createIssue") })).not.toBeInTheDocument();
    expect(within(cell).getByText(t("cves.issue.notEligible"))).toBeInTheDocument();
  });
});
