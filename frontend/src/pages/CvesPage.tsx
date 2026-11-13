import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Link, useSearchParams } from "react-router";
import { CveFilterBar } from "../components/cves/CveFilterBar";
import { CreateIssueDialog } from "../components/cves/CreateIssueDialog";
import { CveStatusPill, SeverityPill, issueEligible, scannerLabel } from "../components/cves/CvePills";
import { safeHttpsUrl } from "../components/cves/safeUrl";
import { PageHeader } from "../components/mappings/PageHeader";
import { LINK, TABLE, TD, TH } from "../components/mappings/styles";
import { TableScroll } from "../components/mappings/TableScroll";
import { Button, buttonClass } from "../components/ui/Button";
import { Card } from "../components/ui/Card";
import { currentPage, Pagination } from "../components/ui/Pagination";
import { ErrorMessage, LoadingMessage } from "../components/ui/StatusMessage";
import { t } from "../i18n";
import { ApiError, api } from "../lib/api";
import { parseFilters, toApiQuery, toUrlParams } from "../lib/cveFilters";
import { useMe } from "../lib/session";
import type { CveSummary, MappingTag, Page } from "../types/api";
import type { Source } from "../types/sources";

const PAGE_SIZE = 50;

function IssueCell({ cve }: { cve: CveSummary }) {
  const url = safeHttpsUrl(cve.github_issue_url);
  if (cve.github_issue_number === null || url === null) {
    return (
      <span className="text-muted">{issueEligible(cve) ? t("cves.issue.none") : t("cves.issue.notEligible")}</span>
    );
  }
  return (
    <span className="inline-flex items-center gap-2">
      <a href={url} target="_blank" rel="noopener noreferrer" className={LINK}>
        #{cve.github_issue_number}
      </a>
      {cve.github_issue_status === "closed" ? <span className="text-[12.5px] text-muted">{t("cves.issue.closed")}</span> : null}
    </span>
  );
}

// The Action column does not change with the filters. A CVE with an issue, open or closed,
// shows View issue and never Create issue (#257, decisions 10 and 12). One without an issue
// shows Create issue to the mapping's owner while a tag still reports it open; it is
// disabled while an active acceptance exists.
function ActionCell({
  cve,
  canCreate,
  pending,
  onCreate,
}: {
  cve: CveSummary;
  canCreate: boolean;
  pending: boolean;
  onCreate: () => void;
}) {
  if (cve.github_issue_number !== null) {
    const url = safeHttpsUrl(cve.github_issue_url);
    return url === null ? null : (
      <a href={url} target="_blank" rel="noopener noreferrer" className={buttonClass("small")}>
        {t("cves.action.viewIssue")}
      </a>
    );
  }
  if (!canCreate || !issueEligible(cve)) {
    return null;
  }
  return (
    <Button variant="small" disabled={cve.accepted || pending} onClick={onCreate}>
      {t("cves.action.createIssue")}
    </Button>
  );
}

function githubRepository(source: { github_owner: string; github_repo: string } | undefined): string {
  return source === undefined ? "" : `${source.github_owner}/${source.github_repo}`;
}

// The detail link carries the list's query as `from`, so Back returns to the same list.
function detailPath(id: string, params: URLSearchParams): string {
  const path = `/cves/${encodeURIComponent(id)}`;
  const from = params.toString();
  return from === "" ? path : `${path}?${new URLSearchParams({ from }).toString()}`;
}

export default function CvesPage() {
  const me = useMe();
  // The Mapping combobox is the only scope control (#257, decision 2), so there is no
  // toggle: an admin reads every tenant's mappings, anyone else reads their own.
  const scopeAll = me.data?.role === "admin";
  const queryClient = useQueryClient();
  const [params, setParams] = useSearchParams();
  const page = currentPage(params);
  const filters = parseFilters(params);
  const order = params.get("order") === "asc" ? "asc" : "desc";
  // Each row's repository comes from its source_id (#323); the row has no repository field.
  const sourceList = useQuery({
    queryKey: ["image-sources", "list", scopeAll],
    queryFn: () => api<Page<Source>>("GET", `/image-sources?page_size=200${scopeAll ? "&scope=all" : ""}`),
  });
  const sourceItems = sourceList.data?.items ?? [];
  const sources = new Map(sourceItems.map((item) => [item.id, item]));
  const [issueError, setIssueError] = useState<string | null>(null);
  const [creating, setCreating] = useState<CveSummary | null>(null);
  const tags = useQuery({
    queryKey: ["image-sources", filters.mapping, "tags"],
    queryFn: () => api<{ items: MappingTag[] }>("GET", `/image-sources/${encodeURIComponent(filters.mapping)}/tags`),
    enabled: filters.mapping !== "",
  });

  // Sets the parameters in the patch; an empty value removes one. Any change goes back to
  // page 1. Filters read from an older link are rewritten to the current names.
  function setParamsPatch(patch: Record<string, string>) {
    setParams(
      (current) => {
        const updated = new URLSearchParams(current);
        for (const legacy of ["accepted", "mapping_id"]) {
          updated.delete(legacy);
        }
        for (const [name, value] of Object.entries(toUrlParams(filters))) {
          updated.set(name, value);
        }
        for (const [name, value] of Object.entries(patch)) {
          if (value === "") {
            updated.delete(name);
          } else {
            updated.set(name, value);
          }
        }
        updated.delete("page");
        return updated;
      },
      { replace: "q" in patch && Object.keys(patch).length === 1 },
    );
  }

  const apiQuery = toApiQuery(filters);
  const queryString = new URLSearchParams(apiQuery).toString();
  const list = useQuery({
    queryKey: ["cves", scopeAll, page, queryString, order],
    queryFn: () => {
      const query = new URLSearchParams({
        page: String(page),
        page_size: String(PAGE_SIZE),
        sort: "severity",
        order,
        ...apiQuery,
      });
      if (scopeAll) {
        query.set("scope", "all");
      }
      return api<Page<CveSummary>>("GET", `/cves?${query.toString()}`);
    },
  });

  const createIssue = useMutation({
    mutationFn: (id: string) => api("POST", `/cves/${encodeURIComponent(id)}/issue`),
    onMutate: () => setIssueError(null),
    onSuccess: () => {
      setCreating(null);
      return queryClient.invalidateQueries({ queryKey: ["cves"] });
    },
    onError: (error) => {
      setCreating(null);
      setIssueError(error instanceof ApiError ? error.message : t("cves.issue.failed"));
    },
  });

  const header = <PageHeader title={t("page.cves")} subtitle={t("cves.subtitle")} />;

  const filterBar = <CveFilterBar state={filters} sources={sourceItems} tags={tags.data?.items ?? []} onChange={setParamsPatch} />;

  if (list.isPending) {
    return (
      <>
        {header}
        {filterBar}
        <LoadingMessage />
      </>
    );
  }
  if (list.isError) {
    return (
      <>
        {header}
        {filterBar}
        <ErrorMessage />
      </>
    );
  }

  return (
    <>
      {header}
      {filterBar}
      {issueError === null ? null : (
        <p role="alert" className="text-[13px] text-crit-ink">
          {issueError}
        </p>
      )}
      <Card>
        {list.data.items.length === 0 ? (
          <p className="p-5 text-muted">{t("cves.empty")}</p>
        ) : (
          <TableScroll label={t("page.cves")}>
            <table className={TABLE}>
              <thead>
                <tr>
                  <th className={TH}>{t("cves.col.cve")}</th>
                  <th className={TH} aria-sort={order === "desc" ? "descending" : "ascending"}>
                    <button
                      type="button"
                      onClick={() => setParamsPatch({ order: order === "desc" ? "asc" : "desc" })}
                      className="cursor-pointer uppercase focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent"
                    >
                      {t("cves.col.severity")} {order === "desc" ? "↓" : "↑"}
                    </button>
                  </th>
                  <th className={TH}>{t("cves.col.status")}</th>
                  <th className={TH}>{t("cves.col.package")}</th>
                  <th className={TH}>{t("cves.col.fixedIn")}</th>
                  <th className={TH}>{t("cves.col.scanners")}</th>
                  <th className={TH}>{t("cves.col.mapping")}</th>
                  <th className={TH}>{t("cves.col.tags")}</th>
                  <th className={TH}>{t("cves.col.issue")}</th>
                  <th className={TH}>{t("cves.col.action")}</th>
                </tr>
              </thead>
              <tbody>
                {list.data.items.map((cve) => {
                  const source = sources.get(cve.source_id);
                  // One row per source (#337): the display name, else the repository, tells rows apart.
                  const sourceLabel = source === undefined ? "" : (source.name ?? source.repository);
                  return (
                    <tr key={cve.id}>
                      <td className={`${TD} whitespace-nowrap`}>
                        <Link to={detailPath(cve.id, params)} className={`font-mono text-[13px] ${LINK}`}>
                          {cve.cve_id}
                          {sourceLabel === "" ? null : (
                            <>
                              {" "}
                              <span className="sr-only">{t("cves.row.inSource", { source: sourceLabel })}</span>
                            </>
                          )}
                        </Link>
                        {cve.id_reason === null ? null : (
                          <span data-testid="cve-id-reason" className="ml-2 text-[12px] text-muted">
                            {t("cves.idReason")}
                          </span>
                        )}
                      </td>
                      <td className={TD}>
                        <SeverityPill severity={cve.severity} />
                      </td>
                      <td className={TD}>
                        <CveStatusPill cve={cve} />
                      </td>
                      <td className={TD}>{cve.package}</td>
                      <td className={`${TD} font-mono text-[12.5px]`}>{cve.fixed_in_version ?? t("cves.unknown")}</td>
                      <td className={`${TD} whitespace-nowrap`}>{scannerLabel(cve.scanners)}</td>
                      <td className={TD}>{sourceLabel}</td>
                      <td className={`${TD} whitespace-nowrap text-muted`}>
                        {t("cves.tags", { open: cve.open_tags, tracked: cve.tracked_tags })}
                      </td>
                      <td className={`${TD} whitespace-nowrap`}>
                        <IssueCell cve={cve} />
                      </td>
                      <td className={`${TD} whitespace-nowrap`}>
                        <ActionCell
                          cve={cve}
                          canCreate={source !== undefined && me.data?.id === source.user_id}
                          pending={createIssue.isPending && createIssue.variables === cve.id}
                          onCreate={() => setCreating(cve)}
                        />
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
      <CreateIssueDialog
        cve={creating}
        repository={creating === null ? "" : githubRepository(sources.get(creating.source_id))}
        pending={createIssue.isPending}
        onCancel={() => setCreating(null)}
        onConfirm={(cve) => createIssue.mutate(cve.id)}
      />
    </>
  );
}
