import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router";
import { PageHeader } from "../components/mappings/PageHeader";
import { LINK, TABLE, TD, TH } from "../components/mappings/styles";
import { TableScroll } from "../components/mappings/TableScroll";
import { useMappingLookup, useScopeAll } from "../components/mappings/useMappings";
import { ImageCell } from "../components/jobs/ImageCell";
import { JobStatusPill } from "../components/jobs/jobPill";
import { triggerLabel } from "../components/jobs/labels";
import { RetryButton } from "../components/jobs/RetryButton";
import { Time } from "../components/jobs/Time";
import { Card } from "../components/ui/Card";
import { Panel } from "../components/mappings/Panel";
import { Pill, type PillKind } from "../components/ui/Pill";
import { ScopeToggle } from "../components/ui/ScopeToggle";
import { ErrorMessage, LoadingMessage } from "../components/ui/StatusMessage";
import { t } from "../i18n";
import { api } from "../lib/api";
import type { DashboardSummary } from "../types/api";

interface CountCardProps {
  kind: PillKind;
  count: number;
  label: string;
  to?: string;
  alert?: boolean;
}

function CountCard({ kind, count, label, to, alert = false }: CountCardProps) {
  const border = alert && count > 0 ? " border-crit/45" : "";
  const body = (
    <>
      <Pill kind={kind} />
      <span className="text-[32px] leading-none font-semibold">{count}</span>
      <span className="text-[12.5px] text-muted">{label}</span>
    </>
  );
  const className = `flex flex-col items-start gap-2.5 px-[18px] py-4 text-text no-underline${border}`;
  if (to === undefined) {
    return <Card className={className}>{body}</Card>;
  }
  return (
    <Card className={`p-0${border}`}>
      <Link
        to={to}
        className="flex flex-col items-start gap-2.5 rounded-[10px] px-[18px] py-4 text-text no-underline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent"
      >
        {body}
      </Link>
    </Card>
  );
}

export default function DashboardPage() {
  const scopeAll = useScopeAll();
  const summary = useQuery({
    queryKey: ["dashboard", "summary", scopeAll],
    queryFn: () => api<DashboardSummary>("GET", `/dashboard/summary${scopeAll ? "?scope=all" : ""}`),
  });
  const mappings = useMappingLookup(scopeAll);

  const header = (
    <PageHeader title={t("page.dashboard")} subtitle={t("dashboard.subtitle")}>
      <ScopeToggle />
    </PageHeader>
  );

  if (summary.isPending) {
    return (
      <>
        {header}
        <LoadingMessage />
      </>
    );
  }
  if (summary.isError) {
    return (
      <>
        {header}
        <ErrorMessage />
      </>
    );
  }
  const data = summary.data;
  const scopeQuery = scopeAll ? "&scope=all" : "";

  return (
    <>
      {header}

      <div className="grid grid-cols-[repeat(auto-fit,minmax(170px,1fr))] gap-3.5">
        <CountCard
          kind="critical"
          count={data.open_cves.critical}
          label={t("dashboard.openCves")}
          to={`/cves?severity=CRITICAL&status=open`}
        />
        <CountCard
          kind="high"
          count={data.open_cves.high}
          label={t("dashboard.openCves")}
          to={`/cves?severity=HIGH&status=open`}
        />
        <CountCard
          kind="medium"
          count={data.open_cves.medium}
          label={t("dashboard.openCves")}
          to={`/cves?severity=MEDIUM&status=open`}
        />
        <CountCard
          kind="low"
          count={data.open_cves.low}
          label={t("dashboard.openCves")}
          to={`/cves?severity=LOW&status=open`}
        />
        <CountCard
          kind="unknown"
          count={data.open_cves.unknown}
          label={t("dashboard.openCves")}
          to={`/cves?severity=UNKNOWN&status=open`}
        />
        <CountCard
          kind="open"
          count={data.open_cves.total}
          label={t("dashboard.openCvesTotal")}
          to={`/cves?status=open`}
        />
        <CountCard
          kind="fixed"
          count={data.fixed_cves}
          label={t("dashboard.fixedCves")}
          to={`/cves?status=fixed`}
        />
        <CountCard kind="accepted" count={data.accepted_cves} label={t("dashboard.acceptedCves")} to="/cves?accepted=true" />
        <Card className="p-0">
          <Link
            to="/cves?has_issue=true"
            className="flex flex-col items-start gap-2.5 rounded-[10px] px-[18px] py-4 text-text no-underline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent"
          >
            <span className="inline-flex h-[22px] items-center rounded-full border border-border bg-text/5 px-[9px] text-[11px] leading-none font-semibold tracking-[0.05em] uppercase">
              {t("dashboard.issues")}
            </span>
            <span className="text-[32px] leading-none font-semibold">{data.open_issues}</span>
            <span className="text-[12.5px] text-muted">{t("dashboard.openIssues")}</span>
          </Link>
        </Card>
        <CountCard
          kind="failed"
          count={data.failed_syncs}
          label={t("dashboard.failedSyncs")}
          to={`/jobs?status=failed${scopeQuery}`}
          alert
        />
      </div>

      <Panel aria-labelledby="recent">
        <div className="flex items-center justify-between px-[18px] pt-4 pb-2">
          <h2 id="recent" className="text-[15px] font-semibold">
            {t("dashboard.recentSyncs")}
          </h2>
          <Link to="/jobs" className={`text-[13px] ${LINK}`}>
            {t("dashboard.allJobs")}
          </Link>
        </div>
        {data.recent_syncs.length === 0 ? (
          <p className="px-[18px] pt-2 pb-5 text-muted">{t("dashboard.noSyncs")}</p>
        ) : (
          <TableScroll label={t("dashboard.recentSyncs")}>
            <table className={TABLE}>
              <thead>
                <tr>
                  <th className={TH}>{t("jobs.col.image")}</th>
                  <th className={TH}>{t("dashboard.col.target")}</th>
                  <th className={TH}>{t("jobs.col.trigger")}</th>
                  <th className={TH}>{t("jobs.col.status")}</th>
                  <th className={TH}>{t("dashboard.col.when")}</th>
                  <th className={TH}>
                    <span className="sr-only">{t("jobs.col.actions")}</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {data.recent_syncs.map((job) => {
                  const mapping = mappings.get(job.mapping_id);
                  return (
                    <tr key={job.id}>
                      <td className={TD}>
                        <ImageCell job={job} showError />
                      </td>
                      <td className={`${TD} font-mono text-[12.5px]`}>
                        {mapping === undefined ? null : `${mapping.github_owner}/${mapping.github_repo}`}
                      </td>
                      <td className={`${TD} text-muted`}>{triggerLabel(job.trigger)}</td>
                      <td className={TD}>
                        <JobStatusPill status={job.status} />
                      </td>
                      <td className={`${TD} text-muted`}>
                        <Time iso={job.updated_at} />
                      </td>
                      <td className={`${TD} text-right`}>{job.status === "failed" ? <RetryButton job={job} /> : null}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </TableScroll>
        )}
      </Panel>
    </>
  );
}
