// CVE list filter state, kept in the URL query string, and its mapping to the
// GET /cves query (#129). Severity and status are comma-separated lists; the
// text filters are exact match on the server.

export const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"] as const;
export const STATUSES = ["open", "fixed", "accepted"] as const;
export type SeverityValue = (typeof SEVERITIES)[number];
export type StatusValue = (typeof STATUSES)[number];

export const TEXT_FILTERS = ["package", "tag", "harbor_project", "harbor_repository"] as const;
export type TextFilter = (typeof TEXT_FILTERS)[number];

export interface CveFilterState {
  severities: SeverityValue[];
  statuses: StatusValue[];
  text: Record<TextFilter, string>;
  mappingId: string;
}

// Keeps the values the server accepts, once each, in canonical order.
function pick<T extends string>(raw: string | null, allowed: readonly T[]): T[] {
  const wanted = new Set((raw ?? "").split(","));
  return allowed.filter((value) => wanted.has(value));
}

// Default view: every severity, open CVEs only. A legacy status=all link means every status.
export function parseFilters(params: URLSearchParams): CveFilterState {
  const severities = pick(params.get("severity"), SEVERITIES);
  const statuses = params.get("status") === "all" ? [...STATUSES] : pick(params.get("status"), STATUSES);
  return {
    severities: severities.length === 0 ? [...SEVERITIES] : severities,
    statuses: statuses.length === 0 ? ["open"] : statuses,
    text: {
      package: params.get("package") ?? "",
      tag: params.get("tag") ?? "",
      harbor_project: params.get("harbor_project") ?? "",
      harbor_repository: params.get("harbor_repository") ?? "",
    },
    mappingId: params.get("mapping_id") ?? "",
  };
}

// The values to put in the page URL: the defaults are left out.
export function toUrlParams(state: CveFilterState): Record<string, string> {
  const out: Record<string, string> = {};
  if (state.severities.length < SEVERITIES.length) {
    out.severity = state.severities.join(",");
  }
  if (state.statuses.join(",") !== "open") {
    out.status = state.statuses.join(",");
  }
  for (const name of TEXT_FILTERS) {
    if (state.text[name] !== "") {
      out[name] = state.text[name];
    }
  }
  if (state.mappingId !== "") {
    out.mapping_id = state.mappingId;
  }
  return out;
}

// The GET /cves filter parameters. Open alone also sends accepted=false, so an
// accepted CVE is reached through the Accepted status.
export function toApiQuery(state: CveFilterState): Record<string, string> {
  const out = toUrlParams(state);
  out.status = state.statuses.join(",");
  if (out.status === "open") {
    out.accepted = "false";
  }
  return out;
}

// How many filters differ from the default view.
export function activeFilters(state: CveFilterState): Array<{ key: string; value: string }> {
  return Object.entries(toUrlParams(state)).map(([key, value]) => ({ key, value }));
}

export const FILTER_KEYS = ["severity", "status", ...TEXT_FILTERS, "mapping_id"] as const;
