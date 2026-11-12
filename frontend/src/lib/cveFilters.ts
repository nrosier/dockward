// CVE list control bar state, kept in the URL query string, and its mapping to the
// GET /cves query (#257). Severity and status are comma-separated lists (OR inside a
// group, AND across groups); the combobox filters take one value each.

export const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"] as const;
export const STATUSES = ["open", "fixed", "accepted"] as const;
export type SeverityValue = (typeof SEVERITIES)[number];
export type StatusValue = (typeof STATUSES)[number];
export const FIXES = ["available", "none"] as const;
export type FixValue = (typeof FIXES)[number];
export type HasIssue = "" | "true" | "false";

export interface CveFilterState {
  q: string;
  // Empty means every severity.
  severities: SeverityValue[];
  // Never empty: the default is Open.
  statuses: StatusValue[];
  hasIssue: HasIssue;
  // Empty or both means no fix filter (#265).
  fixes: FixValue[];
  // The first path segment of the repository (decision 38).
  namespace: string;
  repository: string;
  tag: string;
  mapping: string;
}

const DEFAULT_STATUSES: StatusValue[] = ["open"];

// Keeps the values the server accepts, once each, in canonical order.
function pick<T extends string>(raw: string | null, allowed: readonly T[]): T[] {
  const wanted = new Set((raw ?? "").split(","));
  return allowed.filter((value) => wanted.has(value));
}

// The status pills from the URL. Old links keep working: without `status`,
// accepted=true selects Accepted and accepted=false selects Open and Fixed (the
// CVEs that are not accepted); status=all is every status.
function parseStatuses(params: URLSearchParams): StatusValue[] {
  const raw = params.get("status");
  if (raw === "all") {
    return [...STATUSES];
  }
  const picked = pick(raw, STATUSES);
  if (picked.length > 0) {
    return picked;
  }
  if (raw === null) {
    const accepted = params.get("accepted");
    if (accepted === "true") {
      return ["accepted"];
    }
    if (accepted === "false") {
      return ["open", "fixed"];
    }
  }
  return [...DEFAULT_STATUSES];
}

// The new name wins when both it and the old one are in the URL (#257, decision 9).
function renamed(params: URLSearchParams, name: string, legacy: string): string {
  const value = params.get(name);
  return value !== null && value !== "" ? value : (params.get(legacy) ?? "");
}

export function parseFilters(params: URLSearchParams): CveFilterState {
  const hasIssue = params.get("has_issue");
  return {
    q: params.get("q") ?? "",
    severities: pick(params.get("severity"), SEVERITIES),
    statuses: parseStatuses(params),
    hasIssue: hasIssue === "true" || hasIssue === "false" ? hasIssue : "",
    fixes: pick(params.get("fix"), FIXES),
    namespace: params.get("namespace") ?? "",
    repository: params.get("repository") ?? "",
    tag: params.get("tag") ?? "",
    mapping: renamed(params, "mapping", "mapping_id"),
  };
}

// The values to put in the page URL: the defaults are left out.
export function toUrlParams(state: CveFilterState): Record<string, string> {
  const out: Record<string, string> = {};
  if (state.q !== "") {
    out.q = state.q;
  }
  if (state.severities.length > 0) {
    out.severity = state.severities.join(",");
  }
  if (state.statuses.join(",") !== DEFAULT_STATUSES.join(",")) {
    out.status = state.statuses.join(",");
  }
  if (state.hasIssue !== "") {
    out.has_issue = state.hasIssue;
  }
  if (state.fixes.length > 0) {
    out.fix = state.fixes.join(",");
  }
  for (const name of ["namespace", "repository", "tag", "mapping"] as const) {
    if (state[name] !== "") {
      out[name] = state[name];
    }
  }
  return out;
}

// The GET /cves filter parameters. Status is always sent, so the server never
// applies its own default. The Mapping filter is a source, sent as `source_id`
// (#323): the server does not read a `mapping` key, so the URL name is not sent.
export function toApiQuery(state: CveFilterState): Record<string, string> {
  const { mapping, ...rest } = toUrlParams(state);
  const query: Record<string, string> = { ...rest, status: state.statuses.join(",") };
  if (mapping !== undefined) {
    query.source_id = mapping;
  }
  return query;
}

// Every URL parameter the filters own, including the names older links used.
export const FILTER_KEYS = [
  "q",
  "severity",
  "status",
  "has_issue",
  "fix",
  "namespace",
  "repository",
  "tag",
  "mapping",
  "accepted",
  "mapping_id",
] as const;

// The namespace of a repository path: its first segment (decision 33).
export function namespaceOf(repository: string): string {
  const slash = repository.indexOf("/");
  return slash < 0 ? repository : repository.slice(0, slash);
}
