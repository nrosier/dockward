import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState, type FormEvent } from "react";
import { CardHeading, FormError, INPUT, statusOf } from "../components/admin/parts";
import { Button } from "../components/ui/Button";
import { Card } from "../components/ui/Card";
import { Field } from "../components/ui/Field";
import { ErrorMessage, LoadingMessage } from "../components/ui/StatusMessage";
import { t } from "../i18n";
import { api } from "../lib/api";
import type { GithubUrlSettings } from "../types/api";

export const GITHUB_URL_KEY = ["admin", "github-url"] as const;

export default function AdminGithubPage() {
  const settings = useQuery({
    queryKey: GITHUB_URL_KEY,
    queryFn: () => api<GithubUrlSettings>("GET", "/admin/github-url"),
  });
  if (settings.isPending) {
    return <LoadingMessage />;
  }
  if (settings.isError || !settings.data) {
    return <ErrorMessage />;
  }
  return <GithubForm data={settings.data} />;
}

function GithubForm({ data }: { data: GithubUrlSettings }) {
  const queryClient = useQueryClient();
  const [apiBase, setApiBase] = useState(data.api_base_url);
  const [webUrl, setWebUrl] = useState(data.web_url);
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);

  const save = useMutation({
    mutationFn: () =>
      api<GithubUrlSettings>("PUT", "/admin/github-url", { api_base_url: apiBase.trim(), web_url: webUrl.trim() }),
    onSuccess: (next) => {
      setApiBase(next.api_base_url);
      setWebUrl(next.web_url);
      setError(null);
      setSaved(true);
      queryClient.setQueryData(GITHUB_URL_KEY, next);
    },
    onError: (failure) => {
      setSaved(false);
      // The server answers 422 with the catalog key as its fixed message; the text comes from the catalog.
      setError(statusOf(failure) === 422 ? t("settings.github_url_invalid") : t("errors.generic"));
    },
  });

  function submit(event: FormEvent) {
    event.preventDefault();
    setSaved(false);
    setError(null);
    save.mutate();
  }

  return (
    <form onSubmit={submit} className="flex flex-col gap-5">
      <Card className="flex flex-col gap-4 p-5" aria-labelledby="github-url">
        <CardHeading id="github-url" title={t("admin.github.title")} help={t("admin.github.help")} />
        <Field id="github-api" label={t("admin.github.api")} help={t("admin.github.apiHelp")}>
          <input
            id="github-api"
            className={INPUT}
            inputMode="url"
            autoComplete="off"
            value={apiBase}
            onChange={(e) => setApiBase(e.target.value)}
          />
        </Field>
        <Field id="github-web" label={t("admin.github.web")} help={t("admin.github.webHelp")}>
          <input
            id="github-web"
            className={INPUT}
            inputMode="url"
            autoComplete="off"
            value={webUrl}
            onChange={(e) => setWebUrl(e.target.value)}
          />
        </Field>
      </Card>
      <FormError message={error} />
      {saved ? <output className="text-[13px] text-ok-ink">{t("admin.github.saved")}</output> : null}
      <div className="flex flex-wrap justify-end gap-2.5">
        <Button
          onClick={() => {
            setApiBase(data.api_base_url);
            setWebUrl(data.web_url);
            setError(null);
            setSaved(false);
          }}
        >
          {t("admin.github.discard")}
        </Button>
        <Button type="submit" variant="primary" disabled={save.isPending}>
          {t("admin.github.save")}
        </Button>
      </div>
    </form>
  );
}
