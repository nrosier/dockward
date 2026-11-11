import { useQuery } from "@tanstack/react-query";
import { useSearchParams } from "react-router";
import { api } from "../../lib/api";
import { useMe } from "../../lib/session";
import type { MappingListItem, Page } from "../../types/api";

// True when an admin has "All mappings" on. Only admins can send `scope=all`.
export function useScopeAll(): boolean {
  const me = useMe();
  const [params] = useSearchParams();
  return me.data?.role === "admin" && params.get("scope") === "all";
}

export function mappingName(mapping: { harbor_project: string; harbor_repository: string }): string {
  return `${mapping.harbor_project}/${mapping.harbor_repository}`;
}

// Every mapping in scope (up to 200), loaded once so CVE and job rows can
// look up the name by `mapping_id`.
export function useAllMappings(scopeAll: boolean) {
  return useQuery({
    queryKey: ["mappings", "lookup", scopeAll],
    queryFn: () => api<Page<MappingListItem>>("GET", `/mappings?page_size=200${scopeAll ? "&scope=all" : ""}`),
  });
}

export function useMappingLookup(scopeAll: boolean): Map<string, MappingListItem> {
  const query = useAllMappings(scopeAll);
  return new Map((query.data?.items ?? []).map((mapping) => [mapping.id, mapping]));
}
