import { useQuery } from "@tanstack/react-query";
import { api } from "../../lib/api";
import type { Credential, Page } from "../../types/api";

// The user's credentials of one type. Shares the cache key of the form's selects.
export function useCredentials(type: "harbor" | "github") {
  return useQuery({
    queryKey: ["credentials", type],
    queryFn: () => api<Page<Credential>>("GET", `/credentials?service_type=${type}&page_size=200`),
  });
}
