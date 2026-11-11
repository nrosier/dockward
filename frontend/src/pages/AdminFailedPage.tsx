import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { FormError, formatDateTime, messageOf } from "../components/admin/parts";
import { Button } from "../components/ui/Button";
import { Card } from "../components/ui/Card";
import { ErrorMessage, LoadingMessage } from "../components/ui/StatusMessage";
import { ShaBadge } from "../components/ui/ShaBadge";
import { t } from "../i18n";
import { api } from "../lib/api";
import type { Mapping, Page, Job } from "../types/api";
import type { User } from "../lib/session";

const MAX_ATTEMPTS = 8;
const FAILED_KEY = ["admin", "failed"] as const;

export default function AdminFailedPage() {
  const queryClient = useQueryClient();
  const jobs = useQuery({
    queryKey: FAILED_KEY,
    queryFn: () => api<Page<Job>>("GET", "/jobs?status=failed&scope=all"),
  });
  const mappings = useQuery({
    queryKey: ["admin", "failed", "mappings"],
    queryFn: () => api<Page<Mapping>>("GET", "/mappings?scope=all&page_size=200"),
  });
  const users = useQuery({
    queryKey: ["admin", "users", "all"],
    queryFn: () => api<User[]>("GET", "/admin/users"),
  });
  const retry = useMutation({
    mutationFn: (id: string) => api<unknown>("POST", `/jobs/${id}/retry`),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: FAILED_KEY });
      void queryClient.invalidateQueries({ queryKey: ["jobs"] });
    },
  });

  if (jobs.isPending) {
    return <LoadingMessage />;
  }
  if (jobs.isError) {
    return <ErrorMessage />;
  }

  const mappingById = new Map((mappings.data?.items ?? []).map((m) => [m.id, m]));
  const nameById = new Map((users.data ?? []).map((u) => [u.id, u.username]));

  return (
    <div className="flex flex-col gap-4">
      <p className="text-muted">{t("admin.failed.intro")}</p>
      <FormError message={retry.isError ? messageOf(retry.error) : null} />
      {jobs.data.items.length === 0 ? <p className="text-muted">{t("admin.failed.empty")}</p> : null}
      {jobs.data.items.map((job) => {
        const mapping = mappingById.get(job.mapping_id);
        const owner = mapping === undefined ? undefined : nameById.get(mapping.user_id);
        return (
          <Card key={job.id} className="flex flex-col gap-3 p-5">
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div className="flex flex-col gap-1.5">
                <div>
                  {job.image.repo_full_name ?? ""}
                  <span className="text-muted">{job.image.tag ? `:${job.image.tag}` : ""}</span>
                  {mapping ? (
                    <>
                      {" → "}
                      <span className="font-mono text-[13px]">{`${mapping.github_owner}/${mapping.github_repo}`}</span>
                    </>
                  ) : null}
                </div>
                <div className="flex flex-wrap items-center gap-3 text-[12.5px] text-muted">
                  {job.image.digest ? <ShaBadge digest={job.image.digest} /> : null}
                  {owner ? <span>{t("admin.failed.owner", { name: owner })}</span> : null}
                  <span>
                    {t("admin.failed.failedAt", {
                      time: formatDateTime(job.updated_at),
                      attempts: job.attempts,
                      max: MAX_ATTEMPTS,
                    })}
                  </span>
                </div>
              </div>
              <Button disabled={retry.isPending} onClick={() => retry.mutate(job.id)}>
                {t("admin.failed.retry")}
              </Button>
            </div>
            {job.last_error ? (
              <pre className="m-0 overflow-x-auto rounded-lg border border-border bg-bg p-3 font-mono text-[12.5px] whitespace-pre-wrap text-crit-ink">
                {job.last_error}
              </pre>
            ) : null}
          </Card>
        );
      })}
    </div>
  );
}
