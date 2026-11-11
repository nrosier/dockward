import { act, screen, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { t } from "../../i18n";
import { json, renderAt, stubApi } from "../../test/render";
import type { JobLog, JobLogStep } from "../../types/api";
import { JobLogDialog } from "./JobLogDialog";

const step: JobLogStep = {
  seq: 1,
  command: "trivy image --download-db-only",
  started_at: "2026-11-11T10:00:00Z",
  finished_at: "2026-11-11T10:00:12Z",
  timeout_secs: 600,
  outcome: "ok",
  exit_code: 0,
  truncated: false,
};

function log(over: Partial<JobLog> = {}): JobLog {
  return {
    job_id: "j1",
    kind: "db_update",
    scanner: "trivy",
    status: "done",
    attempt: 1,
    steps: [step],
    lines: [{ id: 1, seq: 1, at: "2026-11-11T10:00:01Z", stream: "stderr", text: "<b>downloading</b>" }],
    next_after: 1,
    ...over,
  };
}

function open(body: () => Response) {
  const fetchMock = stubApi((path) => (path.startsWith("/api/v1/jobs/j1/log") ? body() : undefined));
  renderAt(<JobLogDialog jobId="j1" onClose={() => {}} />);
  return fetchMock;
}

describe("JobLogDialog", () => {
  beforeEach(() => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
  });
  afterEach(() => {
    vi.useRealTimers();
    vi.unstubAllGlobals();
  });

  it("queued shows the waiting note", async () => {
    open(() => json(log({ status: "queued", steps: [], lines: [], next_after: null, attempt: 0 })));
    expect(await screen.findByText(t("jobs.log.queued"))).toBeInTheDocument();
  });

  it("running polls every 5 seconds, then stops when the job is done", async () => {
    let status: "running" | "done" = "running";
    const fetchMock = open(() => json(log({ status })));
    expect(await screen.findByText(t("jobs.log.running"))).toBeInTheDocument();
    expect(fetchMock).toHaveBeenCalledTimes(1);
    status = "done";
    await act(async () => {
      await vi.advanceTimersByTimeAsync(5000);
    });
    expect(await screen.findByText(t("jobs.log.done"))).toBeInTheDocument();
    const calls = fetchMock.mock.calls.length;
    expect(calls).toBe(2);
    await act(async () => {
      await vi.advanceTimersByTimeAsync(20000);
    });
    expect(fetchMock.mock.calls.length).toBe(calls);
  });

  it("done shows the step, its outcome, exit code and duration, and the lines as plain text", async () => {
    open(() => json(log()));
    expect(await screen.findByText(t("jobs.log.done"))).toBeInTheDocument();
    expect(screen.getByText("trivy image --download-db-only")).toBeInTheDocument();
    expect(screen.getByText(t("jobs.log.step.exit", { code: 0 }))).toBeInTheDocument();
    expect(screen.getByText(t("jobs.log.step.duration", { n: "12.0" }))).toBeInTheDocument();
    expect(screen.getByText("<b>downloading</b>")).toBeInTheDocument();
    expect(screen.getByText("stderr")).toBeInTheDocument();
    expect(document.querySelector("b")).toBeNull();
  });

  it("failed highlights the failing step with its exit code", async () => {
    open(() =>
      json(
        log({
          status: "failed",
          steps: [step, { ...step, seq: 2, command: "grype db update", outcome: "failed", exit_code: 2 }],
          lines: [],
        }),
      ),
    );
    expect(await screen.findByText(t("jobs.log.failed"))).toBeInTheDocument();
    const failing = screen.getByText("grype db update").closest("[data-failing]");
    expect(failing).not.toBeNull();
    expect(within(failing as HTMLElement).getByText(t("jobs.log.step.exit", { code: 2 }))).toBeInTheDocument();
    expect(screen.getByText("trivy image --download-db-only").closest("[data-failing]")).toBeNull();
  });

  it("a timed out step shows its timeout", async () => {
    open(() =>
      json(log({ status: "failed", steps: [{ ...step, outcome: "timed_out", exit_code: null, timeout_secs: 600 }], lines: [] })),
    );
    expect(await screen.findByText(t("jobs.log.step.timedOut", { n: 600 }))).toBeInTheDocument();
  });

  it("empty shows that no steps are logged", async () => {
    open(() => json(log({ steps: [], lines: [], next_after: null, attempt: 0 })));
    expect(await screen.findByText(t("jobs.log.empty"))).toBeInTheDocument();
  });

  it("a truncated step shows the notice", async () => {
    open(() => json(log({ steps: [{ ...step, truncated: true }] })));
    expect(await screen.findByText(t("jobs.log.truncated"))).toBeInTheDocument();
  });

  it("a load error (404) shows the catalog message", async () => {
    stubApi(() => undefined);
    renderAt(<JobLogDialog jobId="j1" onClose={() => {}} />);
    expect(await screen.findByText(t("jobs.log.loadFailed"))).toBeInTheDocument();
  });

  it("sends no attempt parameter", async () => {
    const fetchMock = open(() => json(log()));
    await screen.findByText(t("jobs.log.done"));
    expect(String(fetchMock.mock.calls[0][0])).not.toContain("attempt");
  });
});
