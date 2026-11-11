import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { t } from "../../i18n";
import { api } from "../../lib/api";
import { Button } from "../ui/Button";
import { Dialog } from "../ui/Dialog";

interface PurgeFailedProps {
  scopeAll: boolean;
  onPurged: (deleted: number) => void;
}

// "Purge failed jobs" button and its confirmation dialog (#243). The count comes
// from `GET /jobs/failed-count`; the purge is `POST /jobs/purge-failed`.
export function PurgeFailed({ scopeAll, onPurged }: PurgeFailedProps) {
  const queryClient = useQueryClient();
  const query = scopeAll ? "?scope=all" : "";
  const count = useQuery({
    queryKey: ["jobs", "failed-count", scopeAll],
    queryFn: () => api<{ count: number }>("GET", `/jobs/failed-count${query}`),
  });
  // The count is read when the dialog opens.
  const [shown, setShown] = useState<number | null>(null);
  const purge = useMutation({
    mutationFn: () => api<{ deleted: number }>("POST", `/jobs/purge-failed${query}`),
    onSuccess: async (result) => {
      setShown(null);
      onPurged(result.deleted);
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ["dashboard"] }),
        queryClient.invalidateQueries({ queryKey: ["jobs"] }),
      ]);
    },
  });

  const available = count.data?.count ?? 0;
  const n = shown ?? 0;

  function onOpenChange(next: boolean) {
    if (!next && !purge.isPending) {
      setShown(null);
    }
  }

  return (
    <>
      <Button
        className="text-crit-ink"
        disabled={count.data === undefined || available === 0}
        onClick={() => {
          purge.reset();
          setShown(available);
        }}
      >
        {t("jobs.purge.button")}
      </Button>
      {count.isError ? (
        <span role="alert" className="text-[12.5px] text-crit-ink">
          {t("jobs.purge.countFailed")}
        </span>
      ) : null}
      <Dialog
        open={shown !== null}
        onOpenChange={onOpenChange}
        title={t("jobs.purge.title")}
        description={n === 1 ? t("jobs.purge.bodyOne") : t("jobs.purge.body", { count: n })}
      >
        {purge.isError ? (
          <p role="alert" className="text-[13px] text-crit-ink">
            {t("jobs.purge.failed")}
          </p>
        ) : null}
        <div className="flex flex-wrap justify-end gap-2.5">
          {/* oxlint-disable-next-line jsx-a11y/no-autofocus -- spec: Cancel is focused by default in the destructive dialog */}
          <Button autoFocus disabled={purge.isPending} onClick={() => onOpenChange(false)}>
            {t("jobs.purge.cancel")}
          </Button>
          <Button variant="danger" disabled={purge.isPending} onClick={() => purge.mutate()}>
            {n === 1 ? t("jobs.purge.confirmOne") : t("jobs.purge.confirm", { count: n })}
          </Button>
        </div>
      </Dialog>
    </>
  );
}
