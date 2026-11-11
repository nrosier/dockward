import { useMutation, useQueryClient } from "@tanstack/react-query";
import { RotateCcw } from "lucide-react";
import { t } from "../../i18n";
import { api } from "../../lib/api";
import { Button } from "../ui/Button";
import type { Job } from "../../types/api";

// Retry sends `POST /jobs/:id/retry`, then refreshes the dashboard
// summary and the job lists.
export function RetryButton({ job }: { job: Job }) {
  const queryClient = useQueryClient();
  const retry = useMutation({
    mutationFn: () => api<Job>("POST", `/jobs/${encodeURIComponent(job.id)}/retry`),
    onSuccess: async () => {
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ["dashboard"] }),
        queryClient.invalidateQueries({ queryKey: ["jobs"] }),
      ]);
    },
  });
  return (
    <div className="flex flex-col items-end gap-1">
      <Button variant="small" disabled={retry.isPending} onClick={() => retry.mutate()}>
        <RotateCcw aria-hidden="true" size={14} />
        {t("jobs.retry")}
      </Button>
      {retry.isError ? (
        <span role="alert" className="text-[12.5px] text-crit-ink">
          {t("jobs.retryFailed")}
        </span>
      ) : null}
    </div>
  );
}
