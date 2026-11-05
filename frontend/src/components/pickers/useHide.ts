import { useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "../../lib/api";
import type { HiddenItem, HideRequest } from "../../types/api";

// Hide one list item for this user. A repeat hide is a 200 from the server, not
// an error. The lists and the Hidden tab refetch afterwards.
export function useHide() {
  const queryClient = useQueryClient();
  const mutation = useMutation({
    mutationFn: (body: HideRequest) => api<HiddenItem>("POST", "/pickers/hidden", body),
    onSuccess: async () => {
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ["picker"] }),
        queryClient.invalidateQueries({ queryKey: ["hidden"] }),
      ]);
    },
  });
  return {
    hide: mutation.mutate,
    pending: mutation.isPending,
    failed: mutation.isError,
    error: mutation.error,
  };
}
