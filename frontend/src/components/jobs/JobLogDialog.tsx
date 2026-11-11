import { useQuery } from "@tanstack/react-query";
import { useEffect, useRef } from "react";
import { t, type MessageKey } from "../../i18n";
import { api } from "../../lib/api";
import type { JobLog, JobLogStep } from "../../types/api";
import { Dialog } from "../ui/Dialog";
import { LoadingMessage } from "../ui/StatusMessage";
import { formatClock } from "./dates";

const POLL_MS = 5000;
// The backend returns at most this many lines per request (services/job_log.rs, PAGE_LINES).
const PAGE_LINES = 500;
const NEAR_BOTTOM_PX = 24;

// Reads the latest attempt in full. A short first page is the whole log, so a poll is one
// request; a longer log is read page by page with the `after` cursor.
async function fetchLog(jobId: string): Promise<JobLog> {
  const base = `/jobs/${encodeURIComponent(jobId)}/log`;
  let result = await api<JobLog>("GET", base);
  while (result.lines.length > 0 && result.lines.length % PAGE_LINES === 0 && result.next_after !== null) {
    const next = await api<JobLog>("GET", `${base}?after=${result.next_after}`);
    if (next.lines.length === 0) {
      break;
    }
    result = { ...next, lines: [...result.lines, ...next.lines] };
  }
  return result;
}

function isLive(status: string | undefined): boolean {
  return status === "queued" || status === "running";
}

function isFailing(step: JobLogStep): boolean {
  return step.outcome !== "ok" && step.outcome !== "running";
}

function seconds(step: JobLogStep): string | null {
  if (step.finished_at === null) {
    return null;
  }
  const n = (Date.parse(step.finished_at) - Date.parse(step.started_at)) / 1000;
  return Number.isFinite(n) ? n.toFixed(1) : null;
}

function outcomeText(step: JobLogStep): string {
  switch (step.outcome) {
    case "ok":
      return t("pill.done");
    case "running":
      return t("pill.running");
    case "failed":
      return t("pill.failed");
    case "timed_out":
      return t("jobs.log.step.timedOut", { n: step.timeout_secs });
    case "output_too_large":
      return t("jobs.log.step.outputTooLarge");
    case "spawn_failed":
      return t("jobs.log.step.spawnFailed");
  }
}

const STATUS_NOTE: Record<string, MessageKey> = {
  queued: "jobs.log.queued",
  running: "jobs.log.running",
  done: "jobs.log.done",
  failed: "jobs.log.failed",
};

function Step({ step, log }: { step: JobLogStep; log: JobLog }) {
  const lines = log.lines.filter((line) => line.seq === step.seq);
  const duration = seconds(step);
  const failing = isFailing(step);
  return (
    <li
      {...(failing ? { "data-failing": "true" } : {})}
      className={`rounded-lg border p-3 ${failing ? "border-crit/40 bg-crit/5" : "border-border bg-surface-2"}`}
    >
      <code className="block text-[13px] break-all">{step.command}</code>
      <div className={`mt-1 flex flex-wrap gap-x-3 text-[12.5px] ${failing ? "text-crit-ink" : "text-muted"}`}>
        <span>{outcomeText(step)}</span>
        {step.exit_code === null ? null : <span>{t("jobs.log.step.exit", { code: step.exit_code })}</span>}
        {duration === null ? null : <span>{t("jobs.log.step.duration", { n: duration })}</span>}
      </div>
      {step.truncated ? (
        <p role="note" className="mt-1 text-[12.5px] text-med-ink">
          {t("jobs.log.truncated")}
        </p>
      ) : null}
      {lines.length === 0 ? null : (
        <ol className="mt-2 font-mono text-[12.5px]">
          {lines.map((line) => (
            <li key={line.id} className="flex gap-2">
              <time dateTime={line.at} className="shrink-0 text-muted">
                {formatClock(line.at)}
              </time>
              <span className={`shrink-0 ${line.stream === "stderr" ? "text-crit-ink" : "text-muted"}`}>{line.stream}</span>
              <span className="min-w-0 break-words whitespace-pre-wrap">{line.text}</span>
            </li>
          ))}
        </ol>
      )}
    </li>
  );
}

function Body({ log }: { log: JobLog }) {
  const scroller = useRef<HTMLDivElement>(null);
  const atBottom = useRef(true);
  const lineCount = log.lines.length;
  // Follow new output only while the reader is at the bottom.
  useEffect(() => {
    const el = scroller.current;
    if (el !== null && lineCount >= 0 && atBottom.current && log.status === "running") {
      el.scrollTop = el.scrollHeight;
    }
  }, [lineCount, log.status]);
  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-wrap items-center gap-x-3 text-[13px]">
        <p>{t(STATUS_NOTE[log.status] ?? "jobs.log.empty")}</p>
        {log.status === "running" ? <p className="text-muted">{t("jobs.log.live")}</p> : null}
        {log.attempt > 0 ? <p className="text-muted">{t("jobs.log.attempt", { n: log.attempt })}</p> : null}
      </div>
      {log.steps.length === 0 ? (
        log.status === "queued" ? null : <p className="text-muted">{t("jobs.log.empty")}</p>
      ) : (
        <div
          ref={scroller}
          onScroll={(event) => {
            const el = event.currentTarget;
            atBottom.current = el.scrollHeight - el.scrollTop - el.clientHeight <= NEAR_BOTTOM_PX;
          }}
          className="max-h-[60vh] overflow-y-auto"
        >
          <h3 className="sr-only">{t("jobs.log.steps")}</h3>
          <ol className="flex flex-col gap-2">
            {log.steps.map((step) => (
              <Step key={step.seq} step={step} log={log} />
            ))}
          </ol>
        </div>
      )}
    </div>
  );
}

// The log of one job's latest attempt, in a wide dialog. It polls while the job is queued or running.
export function JobLogDialog({ jobId, onClose }: { jobId: string; onClose: () => void }) {
  const query = useQuery({
    queryKey: ["job-log", jobId],
    queryFn: () => fetchLog(jobId),
    refetchInterval: (q) => (isLive(q.state.data?.status) ? POLL_MS : false),
  });
  return (
    <Dialog open onOpenChange={(open) => (open ? undefined : onClose())} title={t("jobs.log.title")} size="wide">
      {query.isPending ? <LoadingMessage /> : null}
      {query.isError ? (
        <p role="alert" className="text-crit-ink">
          {t("jobs.log.loadFailed")}
        </p>
      ) : null}
      {query.data ? <Body log={query.data} /> : null}
    </Dialog>
  );
}
