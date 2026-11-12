import { useMutation, useQueryClient } from "@tanstack/react-query";
import { t } from "../../i18n";
import { api, ApiError } from "../../lib/api";
import type { ScanQueued } from "../../types/sources";
import { Button } from "../ui/Button";

type Action = "pull" | "scan";

function clock(seconds: number): string {
  return `${Math.floor(seconds / 60)}:${String(seconds % 60).padStart(2, "0")}`;
}

function failure(error: unknown): string {
  if (error instanceof ApiError && error.status === 409) {
    return t("sources.tagActions.busy");
  }
  if (error instanceof ApiError && error.status === 429) {
    return error.retryAfter === undefined
      ? t("sources.tagActions.rateLimited")
      : t("sources.tagActions.rateLimitedWait", { time: clock(error.retryAfter) });
  }
  return t("sources.tagActions.failed");
}

// Pull and Scan for one tag (POST /image-sources/:id/tags/:tag/pull|scan). One click
// sends one request. The result stays until the next refresh; the table does not poll.
// The buttons use aria-disabled while a request runs so keyboard focus is kept.
export function TagActions({ sourceId, tag }: { sourceId: string; tag: string }) {
  const queryClient = useQueryClient();
  const run = useMutation({
    mutationFn: (action: Action) =>
      api<ScanQueued>("POST", `/image-sources/${sourceId}/tags/${encodeURIComponent(tag)}/${action}`),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["sources", sourceId, "images"] }),
  });
  const click = (action: Action) => {
    if (!run.isPending) {
      run.mutate(action);
    }
  };
  return (
    <div className="flex flex-col items-start gap-1.5">
      <div className="flex items-center gap-2">
        <Button variant="small" aria-label={t("sources.tagActions.pull", { tag })} aria-disabled={run.isPending} onClick={() => click("pull")}>
          {t("sources.tagActions.pullLabel")}
        </Button>
        <Button variant="small" aria-label={t("sources.tagActions.scan", { tag })} aria-disabled={run.isPending} onClick={() => click("scan")}>
          {t("sources.tagActions.scanLabel")}
        </Button>
      </div>
      {run.isPending ? <output className="text-[12.5px] text-muted">{t("sources.tagActions.working")}</output> : null}
      {run.isSuccess ? <output className="text-[12.5px] text-muted">{t("sources.tagActions.queued")}</output> : null}
      {run.isError ? (
        <p role="alert" className="text-[12.5px] text-crit-ink">
          {failure(run.error)}
        </p>
      ) : null}
    </div>
  );
}
