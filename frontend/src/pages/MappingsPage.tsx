import { useQuery } from "@tanstack/react-query";
import { Plus } from "lucide-react";
import { Link, useSearchParams } from "react-router";
import { PageHeader } from "../components/mappings/PageHeader";
import { TABLE, TD, TH } from "../components/mappings/styles";
import { TableScroll } from "../components/mappings/TableScroll";
import { useScopeAll } from "../components/mappings/useMappings";
import { JobStatusPill } from "../components/syncjobs/jobPill";
import { Time } from "../components/syncjobs/Time";
import { buttonClass } from "../components/ui/Button";
import { Card } from "../components/ui/Card";
import { currentPage, Pagination } from "../components/ui/Pagination";
import { ScopeToggle } from "../components/ui/ScopeToggle";
import { ErrorMessage, LoadingMessage } from "../components/ui/StatusMessage";
import { t } from "../i18n";
import { api } from "../lib/api";
import { useMe } from "../lib/session";
import type { MappingListItem, OpenCves, Page } from "../types/api";

const PAGE_SIZE = 50;

function hostOf(url: string): string {
  try {
    return new URL(url).host;
  } catch {
    return url;
  }
}

function IssuesCell({ mapping }: { mapping: MappingListItem }) {
  if (!mapping.auto_create_issues) {
    return (
      <>
        <div>{t("mappings.issues.off")}</div>
        <div className="text-[12.5px] text-muted">{t("mappings.issues.offDetail")}</div>
      </>
    );
  }
  return (
    <>
      <div>{t("mappings.issues.auto")}</div>
      <div className="text-[12.5px] text-muted">
        {t(mapping.min_issue_severity === "CRITICAL" ? "mappings.issues.criticalOnly" : "mappings.issues.highAndAbove")}
      </div>
    </>
  );
}

function OpenCounts({ counts }: { counts: OpenCves }) {
  return (
    <div className="flex gap-2.5">
      <span className="inline-flex items-center gap-1.5" title={t("pill.critical")}>
        <span aria-hidden="true" className="size-2 rounded-full bg-crit" />
        {t("mappings.count.critical", { n: counts.critical })}
      </span>
      <span className="inline-flex items-center gap-1.5" title={t("pill.high")}>
        <span aria-hidden="true" className="size-2 rounded-full bg-high" />
        {t("mappings.count.high", { n: counts.high })}
      </span>
    </div>
  );
}

export default function MappingsPage() {
  const scopeAll = useScopeAll();
  const me = useMe();
  const [params] = useSearchParams();
  const page = currentPage(params);
  const list = useQuery({
    queryKey: ["mappings", "list", scopeAll, page],
    queryFn: () =>
      api<Page<MappingListItem>>("GET", `/mappings?page=${page}&page_size=${PAGE_SIZE}${scopeAll ? "&scope=all" : ""}`),
  });

  const header = (
    <PageHeader title={t("page.mappings")} subtitle={t("mappings.subtitle")}>
      <ScopeToggle />
      <Link to="/mappings/new" className={buttonClass("primary")}>
        <Plus aria-hidden="true" size={16} />
        {t("dashboard.newMapping")}
      </Link>
    </PageHeader>
  );

  if (list.isPending) {
    return (
      <>
        {header}
        <LoadingMessage />
      </>
    );
  }
  if (list.isError) {
    return (
      <>
        {header}
        <ErrorMessage />
      </>
    );
  }

  return (
    <>
      {header}
      <Card>
        {list.data.items.length === 0 ? (
          <p className="p-5 text-muted">{t("mappings.empty")}</p>
        ) : (
          <TableScroll label={t("page.mappings")}>
            <table className={TABLE}>
              <thead>
                <tr>
                  <th className={TH}>{t("mappings.col.harbor")}</th>
                  <th className={TH}>{t("mappings.col.github")}</th>
                  <th className={TH}>{t("mappings.col.issues")}</th>
                  <th className={TH}>{t("mappings.col.openCves")}</th>
                  <th className={TH}>{t("mappings.col.lastSync")}</th>
                  <th className={TH}>
                    <span className="sr-only">{t("syncJobs.col.actions")}</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {list.data.items.map((mapping) => (
                  <tr key={mapping.id}>
                    <td className={TD}>
                      <div className="font-medium">
                        {mapping.harbor_project}/{mapping.harbor_repository}
                      </div>
                      <div className="text-[12.5px] text-muted">{hostOf(mapping.harbor_base_url)}</div>
                    </td>
                    <td className={TD}>
                      <div className="font-mono text-[12.5px]">
                        {mapping.github_owner}/{mapping.github_repo}
                      </div>
                      <div className="text-[12.5px] text-muted">
                        {t("mappings.branch", { branch: mapping.default_branch })}
                      </div>
                    </td>
                    <td className={TD}>
                      <IssuesCell mapping={mapping} />
                    </td>
                    <td className={TD}>
                      <OpenCounts counts={mapping.open_cves} />
                    </td>
                    <td className={TD}>
                      {mapping.last_sync === null ? (
                        <>
                          <span className="text-muted">{t("mappings.never")}</span>
                          <div className="mt-1 text-[12.5px] text-muted">{t("mappings.neverReason")}</div>
                        </>
                      ) : (
                        <>
                          <JobStatusPill status={mapping.last_sync.status} />
                          <div className="mt-1 text-[12.5px] text-muted">
                            <Time iso={mapping.last_sync.updated_at} />
                          </div>
                        </>
                      )}
                    </td>
                    <td className={`${TD} text-right`}>
                      {me.data?.id === mapping.user_id ? (
                        <Link
                          to={`/mappings/${encodeURIComponent(mapping.id)}`}
                          className={buttonClass("small")}
                          aria-label={t("mappings.editNamed", {
                            name: `${mapping.harbor_project}/${mapping.harbor_repository}`,
                          })}
                        >
                          {t("mappings.edit")}
                        </Link>
                      ) : null}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </TableScroll>
        )}
        <Pagination total={list.data.total} pageSize={PAGE_SIZE} />
      </Card>
    </>
  );
}
