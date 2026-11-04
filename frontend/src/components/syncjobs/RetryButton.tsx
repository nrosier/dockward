import { useMutation, useQueryClient } from "@tanstack/react-query";
import { RotateCcw } from "lucide-react";
import { t } from "../../i18n";
import { api } from "../../lib/api";
import { Button } from "../ui/Button";
import type { SyncJob } from "../../types/api";

// Retry sends `POST /sync-jobs/:id/retry`, then refreshes the dashboard
// summary and the sync job lists.
export function RetryButton({ job }: { job: SyncJob }) {
  const queryClient = useQueryClient();
  const retry = useMutation({
    mutationFn: () => api<SyncJob>("POST", `/sync-jobs/${encodeURIComponent(job.id)}/retry`),
    onSuccess: async () => {
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ["dashboard"] }),
        queryClient.invalidateQueries({ queryKey: ["sync-jobs"] }),
      ]);
    },
  });
  return (
    <div className="flex flex-col items-end gap-1">
      <Button variant="small" disabled={retry.isPending} onClick={() => retry.mutate()}>
        <RotateCcw aria-hidden="true" size={14} />
        {t("syncJobs.retry")}
      </Button>
      {retry.isError ? (
        <span role="alert" className="text-[12.5px] text-crit-ink">
          {t("syncJobs.retryFailed")}
        </span>
      ) : null}
    </div>
  );
}
