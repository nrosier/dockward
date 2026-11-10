import { useQuery } from "@tanstack/react-query";
import { api } from "../../lib/api";
import type { Page } from "../../types/api";
import type { Hub, Source } from "../../types/sources";

export const SOURCES_KEY = ["sources"] as const;

export function useSources() {
  return useQuery({
    queryKey: SOURCES_KEY,
    queryFn: () => api<Page<Source>>("GET", "/image-sources?page_size=200"),
  });
}

export function useHubs() {
  return useQuery({
    queryKey: ["hubs"],
    queryFn: async () => {
      const result = await api<Page<Hub> | Hub[]>("GET", "/hubs");
      return Array.isArray(result) ? result : result.items;
    },
  });
}
