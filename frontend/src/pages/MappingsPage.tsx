import { useQuery } from "@tanstack/react-query";
import { ArrowDown, ArrowUp, Plus } from "lucide-react";
import { Link, useNavigate, useSearchParams } from "react-router";
import { PageHeader } from "../components/mappings/PageHeader";
import { LINK, TABLE, TD, TH } from "../components/mappings/styles";
import { TableScroll } from "../components/mappings/TableScroll";
import { useScopeAll } from "../components/mappings/useMappings";
import { JobStatusPill } from "../components/syncjobs/jobPill";
import { Time } from "../components/syncjobs/Time";
import { buttonClass } from "../components/ui/Button";
import { Card } from "../components/ui/Card";
import { currentPage, Pagination } from "../components/ui/Pagination";
import { ScopeToggle } from "../components/ui/ScopeToggle";
import { ErrorMessage, LoadingMessage } from "../components/ui/StatusMessage";
import { t, type MessageKey } from "../i18n";
import { api } from "../lib/api";
import { useMe } from "../lib/session";
import type { MappingListItem, OpenCves, Page } from "../types/api";

const PAGE_SIZE = 50;
const INTERACTIVE = "a, button, input, select, textarea, label, [role='button'], [role='link']";
const ROW_OPEN =
  "cursor-pointer hover:bg-border/30 focus-visible:outline-2 focus-visible:-outline-offset-2 focus-visible:outline-accent";

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

const OPEN_COUNTS = [
  { key: "critical", dot: "bg-crit", label: "pill.critical", text: "mappings.count.critical" },
  { key: "high", dot: "bg-high", label: "pill.high", text: "mappings.count.high" },
  { key: "medium", dot: "bg-med", label: "pill.medium", text: "mappings.count.medium" },
  { key: "low", dot: "bg-low", label: "pill.low", text: "mappings.count.low" },
  { key: "unknown", dot: "bg-muted", label: "pill.unknown", text: "mappings.count.unknown" },
] as const;

function OpenCounts({ counts }: { counts: OpenCves }) {
  return (
    <div className="flex flex-wrap gap-x-2.5 gap-y-1">
      {OPEN_COUNTS.map((item) => (
        <span key={item.key} className="inline-flex items-center gap-1.5" title={t(item.label)}>
          <span aria-hidden="true" className={`size-2 rounded-full ${item.dot}`} />
          {t(item.text, { n: counts[item.key] })}
        </span>
      ))}
      <span className="font-semibold">{t("mappings.count.total", { n: counts.total })}</span>
    </div>
  );
}

type SortKey = "harbor_project" | "github_owner" | "open_issues" | "last_sync_at";
type SortOrder = "asc" | "desc";

// First direction when a column becomes the sort. Text columns start
// ascending (A to Z). Open issues and last sync start descending, since the
// most severe and the newest rows are the useful ones to see first.
const SORT_COLUMNS: { key: SortKey; label: MessageKey; first: SortOrder }[] = [
  { key: "harbor_project", label: "mappings.sort.harborSource", first: "asc" },
  { key: "github_owner", label: "mappings.sort.githubTarget", first: "asc" },
  { key: "open_issues", label: "mappings.sort.openIssues", first: "desc" },
  { key: "last_sync_at", label: "mappings.sort.lastSync", first: "desc" },
];

function SortHeader({
  column,
  active,
  order,
  onSort,
}: {
  column: (typeof SORT_COLUMNS)[number];
  active: boolean;
  order: SortOrder;
  onSort: (column: (typeof SORT_COLUMNS)[number]) => void;
}) {
  const Arrow = order === "asc" ? ArrowUp : ArrowDown;
  return (
    <th className={TH} aria-sort={active ? (order === "asc" ? "ascending" : "descending") : undefined}>
      <button
        type="button"
        onClick={() => onSort(column)}
        className="inline-flex cursor-pointer items-center gap-1 uppercase focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent"
      >
        {t(column.label)}
        {active ? (
          <>
            <Arrow aria-hidden="true" size={12} />
            <span className="sr-only">{t(order === "asc" ? "mappings.sort.ascending" : "mappings.sort.descending")}</span>
          </>
        ) : null}
      </button>
    </th>
  );
}

export default function MappingsPage() {
  const scopeAll = useScopeAll();
  const me = useMe();
  const navigate = useNavigate();
  const [params, setParams] = useSearchParams();
  const page = currentPage(params);
  const sortParam = params.get("sort");
  const sort = SORT_COLUMNS.find((column) => column.key === sortParam)?.key ?? null;
  const order: SortOrder = params.get("order") === "desc" ? "desc" : "asc";
  // No URL params: send none and keep the server default.
  const sortQuery = sort === null ? "" : `&sort=${sort}&order=${order}`;
  const list = useQuery({
    queryKey: ["mappings", "list", scopeAll, page, sort, order],
    queryFn: () =>
      api<Page<MappingListItem>>(
        "GET",
        `/mappings?page=${page}&page_size=${PAGE_SIZE}${scopeAll ? "&scope=all" : ""}${sortQuery}`,
      ),
  });

  function onSort(column: (typeof SORT_COLUMNS)[number]) {
    const updated = new URLSearchParams(params);
    updated.set("sort", column.key);
    updated.set("order", sort === column.key ? (order === "asc" ? "desc" : "asc") : column.first);
    updated.delete("page");
    setParams(updated);
  }
  const sortHeader = (key: SortKey) => {
    const column = SORT_COLUMNS.find((c) => c.key === key) ?? SORT_COLUMNS[0];
    return <SortHeader column={column} active={sort === key} order={order} onSort={onSort} />;
  };

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
                  {sortHeader("harbor_project")}
                  {sortHeader("github_owner")}
                  <th className={TH}>{t("mappings.col.issues")}</th>
                  {sortHeader("open_issues")}
                  {sortHeader("last_sync_at")}
                </tr>
              </thead>
              <tbody>
                {list.data.items.map((mapping) => {
                  const editable = me.data?.id === mapping.user_id;
                  const href = `/mappings/${encodeURIComponent(mapping.id)}`;
                  const name = `${mapping.harbor_project}/${mapping.harbor_repository}`;
                  return (
                    <tr
                      key={mapping.id}
                      tabIndex={editable ? 0 : undefined}
                      className={editable ? ROW_OPEN : undefined}
                      onClick={
                        editable
                          ? (event) => {
                              // Inner controls keep their own action.
                              if ((event.target as Element).closest(INTERACTIVE)) return;
                              void navigate(href);
                            }
                          : undefined
                      }
                      onKeyDown={
                        editable
                          ? (event) => {
                              if (event.key === "Enter" && event.target === event.currentTarget) {
                                void navigate(href);
                              }
                            }
                          : undefined
                      }
                    >
                      <td className={TD}>
                        <div className="font-medium">
                          {editable ? (
                            <Link to={href} className={LINK}>
                              {name}
                            </Link>
                          ) : (
                            name
                          )}
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
                    </tr>
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
