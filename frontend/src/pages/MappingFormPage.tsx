import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { Link, useNavigate, useParams } from "react-router";
import { MappingForm } from "../components/mappings/MappingForm";
import { ShownOnce } from "../components/mappings/ShownOnce";
import { LINK } from "../components/mappings/styles";
import { mappingName } from "../components/mappings/useMappings";
import { WebhookCard, type Rotated } from "../components/mappings/WebhookCard";
import { PageTitle } from "../components/ui/PageTitle";
import { ErrorMessage, LoadingMessage, NotFoundMessage } from "../components/ui/StatusMessage";
import { t } from "../i18n";
import { ApiError, api } from "../lib/api";
import { useMe } from "../lib/session";
import type { Mapping, MappingCreated } from "../types/api";

// What the shown-once panel displays. It lives in component state only: never
// in the query cache, the URL, localStorage, or the console.
interface Shown {
  kind: "created" | "rotated";
  mapping: Mapping;
  webhookUrl?: string;
  authSecret?: string;
}

export default function MappingFormPage() {
  const { id } = useParams();
  const navigate = useNavigate();
  const me = useMe();
  const [shown, setShown] = useState<Shown | null>(null);

  const existing = useQuery({
    queryKey: ["mappings", "one", id],
    queryFn: () => api<Mapping>("GET", `/mappings/${encodeURIComponent(id ?? "")}`),
    enabled: id !== undefined,
  });

  if (shown !== null) {
    return (
      <ShownOnce
        kind={shown.kind}
        harborProject={shown.mapping.harbor_project}
        harborName={mappingName(shown.mapping)}
        githubTarget={`${shown.mapping.github_owner}/${shown.mapping.github_repo}`}
        webhookUrl={shown.webhookUrl}
        authSecret={shown.authSecret}
        onDone={() => void navigate("/mappings")}
      />
    );
  }

  const back = (
    <Link to="/mappings" className={`text-[13px] ${LINK}`}>
      {t("mappings.back")}
    </Link>
  );

  if (id === undefined) {
    return (
      <>
        <div className="flex flex-col gap-1.5">
          {back}
          <PageTitle title={t("page.mappingNew")} />
          <p className="text-muted">{t("mappings.form.newSubtitle")}</p>
        </div>
        <MappingForm
          onCreated={(created: MappingCreated) =>
            setShown({
              kind: "created",
              mapping: created.mapping,
              webhookUrl: created.webhook_url,
              authSecret: created.auth_secret,
            })
          }
        />
      </>
    );
  }

  if (existing.isPending) {
    return <LoadingMessage />;
  }
  if (existing.isError) {
    return existing.error instanceof ApiError && existing.error.status === 404 ? <NotFoundMessage /> : <ErrorMessage />;
  }
  const mapping = existing.data;
  const owned = me.data?.id === mapping.user_id;

  const onRotated = (rotated: Rotated) => setShown({ kind: "rotated", mapping, ...rotated });

  return (
    <>
      <div className="flex flex-col gap-1.5">
        {back}
        <PageTitle title={t("page.mappingEdit")} />
        <p className="text-muted">{mappingName(mapping)}</p>
      </div>
      <MappingForm key={mapping.id} mapping={mapping} readOnly={!owned} onCreated={() => undefined} />
      {owned ? (
        <WebhookCard mapping={mapping} onRotated={onRotated} onDeleted={() => void navigate("/mappings")} />
      ) : null}
    </>
  );
}
