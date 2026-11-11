import { useQuery } from "@tanstack/react-query";
import { useSearchParams } from "react-router";
import { Badge, ROW, Segmented, Tag, TD, TH } from "../components/admin/parts";
import { formatDateTime } from "../components/jobs/dates";
import { Card } from "../components/ui/Card";
import { ErrorMessage, LoadingMessage } from "../components/ui/StatusMessage";
import { t } from "../i18n";
import { api } from "../lib/api";
import type { HousekeepingRun, Page } from "../types/api";

const KINDS = ["poll", "cleanup", "retention"];

function duration(run: HousekeepingRun): string {
  if (run.finished_at === null) {
    return "";
  }
  const seconds = (Date.parse(run.finished_at) - Date.parse(run.started_at)) / 1000;
  return Number.isFinite(seconds) ? t("admin.jobs.seconds", { n: seconds.toFixed(1) }) : "";
}

export default function AdminJobsPage() {
  const [params, setParams] = useSearchParams();
  const raw = params.get("kind");
  const kind = raw !== null && KINDS.includes(raw) ? raw : "";
  const runs = useQuery({
    queryKey: ["admin", "jobs", kind],
    queryFn: () => api<Page<HousekeepingRun>>("GET", `/admin/jobs?page_size=50${kind ? `&kind=${kind}` : ""}`),
  });

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <p className="text-muted">{t("admin.jobs.intro")}</p>
        <span id="jobs-kind" className="sr-only">
          {t("admin.jobs.kind")}
        </span>
        <Segmented
          labelId="jobs-kind"
          value={kind}
          onChange={(value) => setParams(value === "" ? {} : { kind: value })}
          options={[
            { value: "", label: t("admin.jobs.all") },
            { value: "poll", label: t("admin.jobs.poll") },
            { value: "cleanup", label: t("admin.jobs.cleanup") },
            { value: "retention", label: t("admin.jobs.retention") },
          ]}
        />
      </div>
      {runs.isPending ? <LoadingMessage /> : null}
      {runs.isError ? <ErrorMessage /> : null}
      {runs.data ? (
        <Card className="overflow-x-auto" aria-label={t("admin.jobs.table")}>
          <table className="w-full border-collapse">
            <thead>
              <tr>
                <th className={TH}>{t("admin.jobs.col.kind")}</th>
                <th className={TH}>{t("admin.jobs.col.status")}</th>
                <th className={TH}>{t("admin.jobs.col.started")}</th>
                <th className={TH}>{t("admin.jobs.col.duration")}</th>
                <th className={TH}>{t("admin.jobs.col.result")}</th>
              </tr>
            </thead>
            <tbody>
              {runs.data.items.map((run) => (
                <tr key={run.id} className={ROW}>
                  <td className={TD}>
                    <Tag>{run.job_kind}</Tag>
                  </td>
                  <td className={TD}>
                    <Badge tone={run.status === "done" ? "ok" : "crit"}>
                      {run.status === "done" ? t("pill.done") : t("pill.failed")}
                    </Badge>
                  </td>
                  <td className={`${TD} text-muted`}>{formatDateTime(run.started_at)}</td>
                  <td className={`${TD} text-muted`}>{duration(run)}</td>
                  <td className={TD}>
                    {run.status === "failed" && run.error_summary ? (
                      <span className="text-crit-ink">{run.error_summary}</span>
                    ) : (
                      t("admin.jobs.processed", { n: run.processed_count })
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
      ) : null}
    </div>
  );
}
