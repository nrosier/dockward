import { useQuery } from "@tanstack/react-query";
import { Search } from "lucide-react";
import { useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router";
import { CveStatusPill, SeverityPill, issueEligible } from "../components/cves/CvePills";
import { safeHttpsUrl } from "../components/cves/safeUrl";
import { MappingFilter } from "../components/mappings/MappingFilter";
import { PageHeader } from "../components/mappings/PageHeader";
import { INPUT, LINK, TABLE, TD, TH } from "../components/mappings/styles";
import { TableScroll } from "../components/mappings/TableScroll";
import { mappingName, useMappingLookup, useScopeAll } from "../components/mappings/useMappings";
import { Card } from "../components/ui/Card";
import { currentPage, Pagination } from "../components/ui/Pagination";
import { ScopeToggle } from "../components/ui/ScopeToggle";
import { ErrorMessage, LoadingMessage } from "../components/ui/StatusMessage";
import { t } from "../i18n";
import { api } from "../lib/api";
import type { CveSummary, Page } from "../types/api";

const PAGE_SIZE = 50;
const DEBOUNCE_MS = 300;
const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"] as const;
const STATUSES = ["open", "fixed", "accepted", "all"] as const;
type StatusFilter = (typeof STATUSES)[number];

// Open sends status=open&accepted=false; Fixed sends status=fixed; Accepted
// sends accepted=true; All sends nothing.
export function statusQuery(status: StatusFilter): Record<string, string> {
  switch (status) {
    case "open":
      return { status: "open", accepted: "false" };
    case "fixed":
      return { status: "fixed" };
    case "accepted":
      return { accepted: "true" };
    default:
      return {};
  }
}

function IssueCell({ cve }: { cve: CveSummary }) {
  const url = safeHttpsUrl(cve.github_issue_url);
  if (cve.github_issue_number === null || url === null) {
    return (
      <span className="text-muted">{issueEligible(cve.severity) ? t("cves.issue.none") : t("cves.issue.notEligible")}</span>
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
  const [params, setParams] = useSearchParams();
  const page = currentPage(params);
  const q = params.get("q") ?? "";
  const rawSeverity = params.get("severity") ?? "";
  const severity = (SEVERITIES as readonly string[]).includes(rawSeverity) ? rawSeverity : "";
  const rawStatus = params.get("status") ?? "open";
  const status: StatusFilter = (STATUSES as readonly string[]).includes(rawStatus) ? (rawStatus as StatusFilter) : "open";
  const mappingId = params.get("mapping_id") ?? "";
  const order = params.get("order") === "asc" ? "asc" : "desc";
  const mappings = useMappingLookup(scopeAll);

  const [search, setSearch] = useState(q);
  useEffect(() => {
    setSearch(q);
  }, [q]);

  function setParam(name: string, value: string) {
    setParams(
      (current) => {
        const updated = new URLSearchParams(current);
        if (value === "") {
          updated.delete(name);
        } else {
          updated.set(name, value);
        }
        updated.delete("page");
        return updated;
      },
      { replace: name === "q" },
    );
  }

  // The search box is debounced: the URL, and so the query, changes 300 ms
  // after the last keystroke.
  useEffect(() => {
    if (search === q) {
      return;
    }
    const timer = setTimeout(() => setParam("q", search), DEBOUNCE_MS);
    return () => clearTimeout(timer);
    // oxlint-disable-next-line react-hooks/exhaustive-deps -- setParam is recreated each render and only reads current params
  }, [search, q]);

  const list = useQuery({
    queryKey: ["cves", scopeAll, page, q, severity, status, mappingId, order],
    queryFn: () => {
      const query = new URLSearchParams({
        page: String(page),
        page_size: String(PAGE_SIZE),
        sort: "severity",
        order,
        ...statusQuery(status),
      });
      if (q !== "") {
        query.set("q", q);
      }
      if (severity !== "") {
        query.set("severity", severity);
      }
      if (mappingId !== "") {
        query.set("mapping_id", mappingId);
      }
      if (scopeAll) {
        query.set("scope", "all");
      }
      return api<Page<CveSummary>>("GET", `/cves?${query.toString()}`);
    },
  });

  const header = (
    <PageHeader title={t("page.cves")} subtitle={t("cves.subtitle")}>
      <ScopeToggle />
    </PageHeader>
  );

  const filters = (
    <search className="flex flex-wrap items-center gap-2.5">
      <label htmlFor="cve-q" className="sr-only">
        {t("cves.filter.search")}
      </label>
      <div className="relative min-w-60 flex-[1_1_240px]">
        <Search aria-hidden="true" size={16} className="absolute top-1/2 left-3 -translate-y-1/2 text-muted" />
        <input
          id="cve-q"
          type="search"
          value={search}
          onChange={(event) => setSearch(event.target.value)}
          placeholder={t("cves.filter.searchPlaceholder")}
          className={`${INPUT} pl-9`}
        />
      </div>
      <label htmlFor="cve-severity" className="sr-only">
        {t("cves.filter.severity")}
      </label>
      <select
        id="cve-severity"
        value={severity}
        onChange={(event) => setParam("severity", event.target.value)}
        className={`${INPUT} w-auto!`}
      >
        <option value="">{t("cves.filter.allSeverities")}</option>
        {SEVERITIES.map((value) => (
          <option key={value} value={value}>
            {value}
          </option>
        ))}
      </select>
      <label htmlFor="cve-status" className="sr-only">
        {t("cves.filter.status")}
      </label>
      <select
        id="cve-status"
        value={status}
        onChange={(event) => setParam("status", event.target.value)}
        className={`${INPUT} w-auto!`}
      >
        <option value="open">{t("pill.open")}</option>
        <option value="fixed">{t("pill.fixed")}</option>
        <option value="accepted">{t("pill.accepted")}</option>
        <option value="all">{t("cves.filter.allStatuses")}</option>
      </select>
      <MappingFilter
        id="cve-mapping"
        value={mappingId}
        mappings={Array.from(mappings.values())}
        onChange={(value) => setParam("mapping_id", value)}
      />
    </search>
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

  return (
    <>
      {header}
      {filters}
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
                      onClick={() => setParam("order", order === "desc" ? "asc" : "desc")}
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
