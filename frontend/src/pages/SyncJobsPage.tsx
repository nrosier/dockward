import { useQuery } from "@tanstack/react-query";
import { Fragment } from "react";
import { useSearchParams } from "react-router";
import { MappingFilter } from "../components/mappings/MappingFilter";
import { PageHeader } from "../components/mappings/PageHeader";
import { Segmented } from "../components/mappings/Segmented";
import { TABLE, TD, TH } from "../components/mappings/styles";
import { TableScroll } from "../components/mappings/TableScroll";
import { mappingName, useMappingLookup, useScopeAll } from "../components/mappings/useMappings";
import { ImageCell } from "../components/syncjobs/ImageCell";
import { JobStatusPill } from "../components/syncjobs/jobPill";
import { RetryButton } from "../components/syncjobs/RetryButton";
import { Time } from "../components/syncjobs/Time";
import { Card } from "../components/ui/Card";
import { currentPage, Pagination } from "../components/ui/Pagination";
import { ScopeToggle } from "../components/ui/ScopeToggle";
import { ErrorMessage, LoadingMessage } from "../components/ui/StatusMessage";
import { t } from "../i18n";
import { api } from "../lib/api";
import { useMe } from "../lib/session";
import type { Page, SyncJob } from "../types/api";

const PAGE_SIZE = 50;
const MAX_ATTEMPTS = 8;
const STATUSES = ["queued", "running", "done", "failed"] as const;
const COLUMNS = 7;

export default function SyncJobsPage() {
  const scopeAll = useScopeAll();
  const me = useMe();
  const [params, setParams] = useSearchParams();
  const page = currentPage(params);
  const rawStatus = params.get("status") ?? "";
  const status = (STATUSES as readonly string[]).includes(rawStatus) ? rawStatus : "";
  const mappingId = params.get("mapping_id") ?? "";
  const mappings = useMappingLookup(scopeAll);

  const list = useQuery({
    queryKey: ["sync-jobs", scopeAll, page, status, mappingId],
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
      return api<Page<SyncJob>>("GET", `/sync-jobs?${query.toString()}`);
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
    <PageHeader title={t("page.syncJobs")} subtitle={t("syncJobs.subtitle")}>
      <ScopeToggle />
    </PageHeader>
  );

  const filters = (
    <div className="flex flex-wrap items-center gap-2.5">
      <Segmented
        label={t("syncJobs.filter.status")}
        value={status}
        onChange={(value) => setParam("status", value)}
        options={[
          { value: "", label: t("syncJobs.filter.all") },
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

  const canRetry = (job: SyncJob) =>
    job.status === "failed" &&
    (me.data?.role === "admin" || mappings.get(job.mapping_id)?.user_id === me.data?.id);

  return (
    <>
      {header}
      {filters}
      <Card>
        {list.data.items.length === 0 ? (
          <p className="p-5 text-muted">{t("syncJobs.empty")}</p>
        ) : (
          <TableScroll label={t("page.syncJobs")}>
            <table className={TABLE}>
              <thead>
                <tr>
                  <th className={TH}>{t("syncJobs.col.image")}</th>
                  <th className={TH}>{t("syncJobs.col.trigger")}</th>
                  <th className={TH}>{t("syncJobs.col.status")}</th>
                  <th className={TH}>{t("syncJobs.col.attempts")}</th>
                  <th className={TH}>{t("syncJobs.col.created")}</th>
                  <th className={TH}>{t("syncJobs.col.updated")}</th>
                  <th className={TH}>
                    <span className="sr-only">{t("syncJobs.col.actions")}</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {list.data.items.map((job) => {
                  const mapping = mappings.get(job.mapping_id);
                  return (
                    <Fragment key={job.id}>
                      <tr>
                        <td className={TD}>
                          <ImageCell job={job} />
                          {mapping === undefined ? null : (
                            <div className="mt-1 text-[12.5px] text-muted">{mappingName(mapping)}</div>
                          )}
                        </td>
                        <td className={`${TD} text-muted`}>
                          {t(job.trigger === "poll" ? "syncJobs.trigger.poll" : "syncJobs.trigger.webhook")}
                        </td>
                        <td className={TD}>
                          <JobStatusPill status={job.status} />
                        </td>
                        <td className={`${TD} text-muted`}>
                          {t("syncJobs.attempts", { attempts: job.attempts, max: MAX_ATTEMPTS })}
                        </td>
                        <td className={`${TD} text-muted`}>
                          <Time iso={job.created_at} />
                        </td>
                        <td className={`${TD} text-muted`}>
                          <Time iso={job.updated_at} />
                        </td>
                        <td className={`${TD} text-right`}>{canRetry(job) ? <RetryButton job={job} /> : null}</td>
                      </tr>
                      {job.status === "failed" && job.last_error !== null ? (
                        <tr>
                          <td colSpan={COLUMNS} className="border-b border-border/60 px-3.5 pb-3">
                            <div className="rounded-lg border border-crit/30 bg-crit/5 px-3 py-2.5 text-[13px] text-crit-ink">
                              {job.last_error}
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
