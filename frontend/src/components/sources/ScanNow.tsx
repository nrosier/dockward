import { useMutation, useQueryClient } from "@tanstack/react-query";
import { t } from "../../i18n";
import { api, ApiError } from "../../lib/api";
import type { ScanQueued } from "../../types/sources";
import { Button } from "../ui/Button";

// Runs discovery for the source now (POST /image-sources/:id/scan). The result is
// the queued count, or one fixed message; the server's text is not shown.
export function ScanNow({ sourceId }: { sourceId: string }) {
  const queryClient = useQueryClient();
  const scan = useMutation({
    mutationFn: () => api<ScanQueued>("POST", `/image-sources/${sourceId}/scan`),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["sources", sourceId, "images"] }),
  });
  return (
    <div className="flex flex-wrap items-center gap-3">
      <Button disabled={scan.isPending} onClick={() => scan.mutate()}>
        {scan.isPending ? t("sources.scan.running") : t("sources.scan.button")}
      </Button>
      {scan.isSuccess ? (
        <output className="text-[13px] text-muted">{scan.data.queued === 1 ? t("sources.scan.queuedOne") : t("sources.scan.queued", { count: scan.data.queued })}</output>
      ) : null}
      {scan.isError ? (
        <p role="alert" className="text-[13px] text-crit-ink">
          {scan.error instanceof ApiError && scan.error.status === 429
            ? t("sources.scan.rateLimited")
            : t("sources.scan.failed")}
        </p>
      ) : null}
    </div>
  );
}
