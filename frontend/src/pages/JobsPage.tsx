import { useQuery } from "@tanstack/react-query";
import { Fragment, useState } from "react";
import { useSearchParams } from "react-router";
import { MappingFilter } from "../components/mappings/MappingFilter";
import { PageHeader } from "../components/mappings/PageHeader";
import { Segmented } from "../components/mappings/Segmented";
import { TABLE, TD, TH } from "../components/mappings/styles";
import { TableScroll } from "../components/mappings/TableScroll";
import { mappingName, useMappingLookup, useScopeAll } from "../components/mappings/useMappings";
import { ImageCell } from "../components/jobs/ImageCell";
import { JobStatusPill } from "../components/jobs/jobPill";
import { newVulnsText, noteText, triggerLabel } from "../components/jobs/labels";
import { PurgeFailed } from "../components/jobs/PurgeFailed";
import { RetryButton } from "../components/jobs/RetryButton";
import { formatDateTime } from "../components/jobs/dates";
import { Time } from "../components/jobs/Time";
import { Card } from "../components/ui/Card";
import { currentPage, Pagination } from "../components/ui/Pagination";
import { ScopeToggle } from "../components/ui/ScopeToggle";
import { ErrorMessage, LoadingMessage } from "../components/ui/StatusMessage";
import { t } from "../i18n";
import { api } from "../lib/api";
import { useMe } from "../lib/session";
import type { Page, Job } from "../types/api";

const PAGE_SIZE = 50;
const MAX_ATTEMPTS = 8;
const STATUSES = ["queued", "running", "done", "failed"] as const;
const COLUMNS = 7;
// The API read cuts last_error to MAX_TEXT_CHARS (500 characters, backend/src/db/jobs.rs).
// The page shows at most 300 of them, so a long message does not push the table wide.
const ERROR_DISPLAY_MAX = 300;

// A job that has run and is queued again is retrying. A job that has never run is plain Queued.
function isRetrying(job: Job): boolean {
  return job.status === "queued" && job.attempts > 0;
}

function capText(text: string, max: number): string {
  const chars = Array.from(text);
  return chars.length <= max ? text : `${chars.slice(0, max).join("")}…`;
}

// The error row shows for a failed job with an error, and for a retrying job with an error or a next attempt time.
function showErrorRow(job: Job): boolean {
  if (job.status === "failed") {
    return job.last_error !== null;
  }
  return isRetrying(job) && (job.last_error !== null || job.next_attempt_at !== null);
}

export default function JobsPage() {
  const scopeAll = useScopeAll();
  const me = useMe();
  const [params, setParams] = useSearchParams();
  const page = currentPage(params);
  const rawStatus = params.get("status") ?? "";
  const status = (STATUSES as readonly string[]).includes(rawStatus) ? rawStatus : "";
  const mappingId = params.get("mapping_id") ?? "";
  const mappings = useMappingLookup(scopeAll);
  const [purged, setPurged] = useState<number | null>(null);

  const list = useQuery({
    queryKey: ["jobs", scopeAll, page, status, mappingId],
    queryFn: () => {
      const query = new URLSearchParams({ page: String(page), page_size: String(PAGE_SIZE), sort: "created_at", order: "desc" });
      if (status !== "") {
        query.set("status", status);
      }
      if (mappingId !== "") {
        query.set("mapping_id", mappingId);
      }
      if (scopeAll) {
        query.set("scope", "all");
      }
      return api<Page<Job>>("GET", `/jobs?${query.toString()}`);
    },
  });

  function setParam(name: string, value: string) {
    const updated = new URLSearchParams(params);
    if (value === "") {
      updated.delete(name);
    } else {
      updated.set(name, value);
    }
    updated.delete("page");
    setParams(updated);
  }

  const header = (
    <PageHeader title={t("page.jobs")} subtitle={t("jobs.subtitle")}>
      <PurgeFailed scopeAll={scopeAll} onPurged={setPurged} />
      <ScopeToggle />
    </PageHeader>
  );

  const filters = (
    <div className="flex flex-wrap items-center gap-2.5">
      <Segmented
        label={t("jobs.filter.status")}
        value={status}
        onChange={(value) => setParam("status", value)}
        options={[
          { value: "", label: t("jobs.filter.all") },
          { value: "queued", label: t("pill.queued") },
          { value: "running", label: t("pill.running") },
          { value: "done", label: t("pill.done") },
          { value: "failed", label: t("pill.failed") },
        ]}
      />
      <MappingFilter
        id="sync-mapping"
        value={mappingId}
        mappings={Array.from(mappings.values())}
        onChange={(value) => setParam("mapping_id", value)}
      />
    </div>
  );

  if (list.isPending) {
    return (
      <>
        {header}
        {filters}
        <LoadingMessage />
      </>
    );
  }
  if (list.isError) {
    return (
      <>
        {header}
        {filters}
        <ErrorMessage />
      </>
    );
  }

  const canRetry = (job: Job) =>
    job.status === "failed" &&
    (me.data?.role === "admin" || mappings.get(job.mapping_id)?.user_id === me.data?.id);

  return (
    <>
      {header}
      {filters}
      {purged === null ? null : (
        <output className="block text-[13px] text-muted">
          {purged === 1 ? t("jobs.purge.successOne") : t("jobs.purge.success", { count: purged })}
        </output>
      )}
      <Card>
        {list.data.items.length === 0 ? (
          <p className="p-5 text-muted">{t("jobs.empty")}</p>
        ) : (
          <TableScroll label={t("page.jobs")}>
            <table className={TABLE}>
              <thead>
                <tr>
                  <th className={TH}>{t("jobs.col.image")}</th>
                  <th className={TH}>{t("jobs.col.trigger")}</th>
                  <th className={TH}>{t("jobs.col.status")}</th>
                  <th className={TH}>{t("jobs.col.attempts")}</th>
                  <th className={TH}>{t("jobs.col.created")}</th>
                  <th className={TH}>{t("jobs.col.updated")}</th>
                  <th className={TH}>
                    <span className="sr-only">{t("jobs.col.actions")}</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {list.data.items.map((job) => {
                  const mapping = mappings.get(job.mapping_id);
                  const newVulns = newVulnsText(job);
                  return (
                    <Fragment key={job.id}>
                      <tr>
                        <td className={TD}>
                          <ImageCell job={job} />
                          {newVulns === null ? null : <div className="mt-1 text-[12.5px]">{newVulns}</div>}
                          {mapping === undefined ? null : (
                            <div className="mt-1 text-[12.5px] text-muted">{mappingName(mapping)}</div>
                          )}
                        </td>
                        <td className={`${TD} text-muted`}>
                          {triggerLabel(job.trigger)}
                        </td>
                        <td className={TD}>
                          <JobStatusPill
                            status={job.status}
                            label={isRetrying(job) ? t("jobs.retrying", { attempts: job.attempts, max: MAX_ATTEMPTS }) : undefined}
                          />
                        </td>
                        <td className={`${TD} text-muted`}>
                          {t("jobs.attempts", { attempts: job.attempts, max: MAX_ATTEMPTS })}
                        </td>
                        <td className={`${TD} text-muted`}>
                          <Time iso={job.created_at} />
                        </td>
                        <td className={`${TD} text-muted`}>
                          <Time iso={job.updated_at} />
                        </td>
                        <td className={`${TD} text-right`}>{canRetry(job) ? <RetryButton job={job} /> : null}</td>
                      </tr>
                      {showErrorRow(job) ? (
                        <tr>
                          <td colSpan={COLUMNS} className="border-b border-border/60 px-3.5 pb-3">
                            <div className="rounded-lg border border-crit/30 bg-crit/5 px-3 py-2.5 text-[13px] text-crit-ink">
                              {job.last_error === null ? null : capText(noteText(job.last_error), ERROR_DISPLAY_MAX)}
                              {isRetrying(job) && job.next_attempt_at !== null ? (
                                <time
                                  dateTime={job.next_attempt_at}
                                  title={job.next_attempt_at}
                                  className="mt-1 block text-[12.5px] text-muted"
                                >
                                  {t("jobs.nextAttempt", { time: formatDateTime(job.next_attempt_at) })}
                                </time>
                              ) : null}
                            </div>
                          </td>
                        </tr>
                      ) : null}
                    </Fragment>
                  );
                })}
              </tbody>
            </table>
          </TableScroll>
        )}
        <Pagination total={list.data.total} pageSize={PAGE_SIZE} />
      </Card>
    </>
  );
}
