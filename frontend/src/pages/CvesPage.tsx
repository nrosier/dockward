import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Link, useSearchParams } from "react-router";
import { CveStatusPill, SeverityPill, issueEligible } from "../components/cves/CvePills";
import { CveFilterBar } from "../components/cves/CveFilterBar";
import { IssueAction } from "../components/cves/IssueAction";
import { safeHttpsUrl } from "../components/cves/safeUrl";
import { PageHeader } from "../components/mappings/PageHeader";
import { LINK, TABLE, TD, TH } from "../components/mappings/styles";
import { TableScroll } from "../components/mappings/TableScroll";
import { mappingName, useMappingLookup, useScopeAll } from "../components/mappings/useMappings";
import { Card } from "../components/ui/Card";
import { currentPage, Pagination } from "../components/ui/Pagination";
import { ScopeToggle } from "../components/ui/ScopeToggle";
import { ErrorMessage, LoadingMessage } from "../components/ui/StatusMessage";
import { t } from "../i18n";
import { ApiError, api } from "../lib/api";
import { FILTER_KEYS, parseFilters, toApiQuery } from "../lib/cveFilters";
import { useMe } from "../lib/session";
import type { CveSummary, Page } from "../types/api";

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

export default function CvesPage() {
  const scopeAll = useScopeAll();
  const me = useMe();
  const queryClient = useQueryClient();
  const [params, setParams] = useSearchParams();
  const page = currentPage(params);
  const q = params.get("q") ?? "";
  const filters = parseFilters(params);
  const order = params.get("order") === "asc" ? "asc" : "desc";
  const mappings = useMappingLookup(scopeAll);
  const [issueError, setIssueError] = useState<string | null>(null);

  // Sets the parameters in the patch; an empty value removes one. Any change
  // goes back to page 1.
  function setParamsPatch(patch: Record<string, string>) {
    setParams(
      (current) => {
        const updated = new URLSearchParams(current);
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
      { replace: "q" in patch },
    );
  }

  function clearAll() {
    setParams((current) => {
      const updated = new URLSearchParams(current);
      for (const name of [...FILTER_KEYS, "q", "page"]) {
        updated.delete(name);
      }
      return updated;
    });
  }

  const apiQuery = toApiQuery(filters);
  const queryString = new URLSearchParams(apiQuery).toString();
  const list = useQuery({
    queryKey: ["cves", scopeAll, page, q, queryString, order],
    queryFn: () => {
      const query = new URLSearchParams({
        page: String(page),
        page_size: String(PAGE_SIZE),
        sort: "severity",
        order,
        ...apiQuery,
      });
      if (q !== "") {
        query.set("q", q);
      }
      if (scopeAll) {
        query.set("scope", "all");
      }
      return api<Page<CveSummary>>("GET", `/cves?${query.toString()}`);
    },
  });

  const createIssue = useMutation({
    mutationFn: (id: string) => api("POST", `/cves/${encodeURIComponent(id)}/issue`),
    onMutate: () => setIssueError(null),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["cves"] }),
    onError: (error) => setIssueError(error instanceof ApiError ? error.message : t("cves.issue.failed")),
  });

  const header = (
    <PageHeader title={t("page.cves")} subtitle={t("cves.subtitle")}>
      <ScopeToggle />
    </PageHeader>
  );

  const filterBar = (
    <CveFilterBar
      state={filters}
      q={q}
      mappings={Array.from(mappings.values())}
      onChange={setParamsPatch}
      onClearAll={clearAll}
    />
  );

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
                  <th className={TH}>{t("cves.col.mapping")}</th>
                  <th className={TH}>{t("cves.col.tags")}</th>
                  <th className={TH}>{t("cves.col.issue")}</th>
                  <th className={TH}>{t("cves.col.action")}</th>
                </tr>
              </thead>
              <tbody>
                {list.data.items.map((cve) => {
                  const mapping = mappings.get(cve.mapping_id);
                  return (
                    <tr key={cve.id}>
                      <td className={TD}>
                        <Link to={`/cves/${encodeURIComponent(cve.id)}`} className={`font-mono text-[13px] ${LINK}`}>
                          {cve.cve_id}
                        </Link>
                      </td>
                      <td className={TD}>
                        <SeverityPill severity={cve.severity} />
                      </td>
                      <td className={TD}>
                        <CveStatusPill cve={cve} />
                      </td>
                      <td className={TD}>{cve.package}</td>
                      <td className={`${TD} font-mono text-[12.5px]`}>{cve.fixed_in_version ?? t("cves.unknown")}</td>
                      <td className={TD}>{mapping === undefined ? null : mappingName(mapping)}</td>
                      <td className={`${TD} text-muted`}>
                        {t("cves.tags", { open: cve.open_tags, tracked: cve.tracked_tags })}
                      </td>
                      <td className={TD}>
                        <IssueCell cve={cve} />
                      </td>
                      <td className={TD}>
                        {mapping !== undefined && me.data?.id === mapping.user_id && issueEligible(cve) ? (
                          <IssueAction
                            cve={cve}
                            label={t("cves.action.createIssue")}
                            variant="small"
                            disabled={cve.accepted || cve.github_issue_status === "open"}
                            pending={createIssue.isPending && createIssue.variables === cve.id}
                            onCreate={() => createIssue.mutate(cve.id)}
                          />
                        ) : null}
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
