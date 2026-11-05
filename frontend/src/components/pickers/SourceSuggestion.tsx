import { useQuery } from "@tanstack/react-query";
import { t } from "../../i18n";
import { api } from "../../lib/api";
import type { SourceSuggestionResponse } from "../../types/api";
import { Button } from "../ui/Button";
import { Pill } from "../ui/Pill";
import { Note, PANEL } from "./PickerControls";
import { PickerError } from "./PickerError";

interface Props {
  harborCredId: string;
  githubCredId: string;
  project: string;
  repository: string;
  onConfirm: (owner: string, repo: string) => void;
  onDismiss: () => void;
}

// A suggestion from the image's source label. Suggest-only: Confirm fills the
// form fields and saves nothing. The raw label is never shown, only the URL
// built from the parsed owner and repository.
export function SourceSuggestion({ harborCredId, githubCredId, project, repository, onConfirm, onDismiss }: Props) {
  const params = new URLSearchParams({ project, repository });
  if (githubCredId !== "") {
    params.set("github_cred_id", githubCredId);
  }
  const query = useQuery({
    queryKey: ["picker", "suggestion", harborCredId, githubCredId, project, repository],
    queryFn: () => api<SourceSuggestionResponse>("GET", `/credentials/${encodeURIComponent(harborCredId)}/source-suggestion?${params.toString()}`),
    retry: false,
    retryOnMount: false,
    refetchOnWindowFocus: false,
    refetchOnReconnect: false,
    staleTime: 30_000,
  });
  if (query.isError) {
    return <PickerError error={query.error} stamp={query.errorUpdatedAt} onRetry={() => void query.refetch()} />;
  }
  const suggestion = query.data?.suggestion;
  if (suggestion === undefined || suggestion === null) {
    return null;
  }
  const name = `${suggestion.github_owner}/${suggestion.github_repo}`;
  const outside = suggestion.github_listed === false;
  return (
    <section aria-label={t("mapping.suggest.title")} className={`${PANEL} gap-3`}>
      <h3 className="text-[15px] font-semibold">{t("mapping.suggest.title")}</h3>
      <p className="text-[12.5px] text-muted">{t("mapping.suggest.fromLabel", { tag: suggestion.image_tag })}</p>
      <div className="flex flex-col gap-1.5 rounded-[10px] border border-border bg-surface-2 p-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <span className="font-mono">{name}</span>
          {suggestion.github_listed === null ? null : (
            <Pill kind={outside ? "medium" : "done"} label={outside ? t("mapping.suggest.notListed") : t("mapping.suggest.listed")} />
          )}
        </div>
        <p className="text-xs text-muted">{t("mapping.suggest.source", { url: `https://github.com/${name}` })}</p>
      </div>
      {outside ? <Note>{t("mapping.suggest.notListedNote")}</Note> : null}
      <div className="flex gap-2">
        <Button variant="primary" onClick={() => onConfirm(suggestion.github_owner, suggestion.github_repo)}>
          {t("mapping.suggest.confirm")}
        </Button>
        <Button onClick={onDismiss}>{t("mapping.suggest.dismiss")}</Button>
      </div>
    </section>
  );
}
