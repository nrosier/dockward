import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { api } from "../../lib/api";
import type { PickerList } from "../../types/api";

interface Options {
  // Null keeps the query off (nothing picked yet).
  path: string | null;
  q: string;
  page: number;
  pageSize: number;
  sort: "name" | "full_name";
}

// One picker list page. No retry, no refetch on error, focus or reconnect:
// the user retries by acting (#126, errors).
export function usePickerList<T>({ path, q, page, pageSize, sort }: Options) {
  const params = new URLSearchParams({ page: String(page), page_size: String(pageSize), sort });
  if (q.trim() !== "") {
    params.set("q", q.trim());
  }
  return useQuery({
    queryKey: ["picker", path, q.trim(), page, pageSize],
    queryFn: () => api<PickerList<T>>("GET", `${path ?? ""}?${params.toString()}`),
    enabled: path !== null,
    retry: false,
    retryOnMount: false,
    refetchOnWindowFocus: false,
    refetchOnReconnect: false,
    staleTime: 30_000,
    placeholderData: keepPreviousData,
  });
}
