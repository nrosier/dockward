import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { Link, useNavigate, useParams } from "react-router";
import { MappingForm } from "../components/mappings/MappingForm";
import { ShownOnce } from "../components/mappings/ShownOnce";
import { LINK } from "../components/mappings/styles";
import { mappingName } from "../components/mappings/useMappings";
import { PullScans } from "../components/mappings/PullScans";
import { ProjectWebhookProposal } from "../components/mappings/ProjectWebhookProposal";
import { WebhookCard, type Rotated } from "../components/mappings/WebhookCard";
import { PageTitle } from "../components/ui/PageTitle";
import { ErrorMessage, LoadingMessage, NotFoundMessage } from "../components/ui/StatusMessage";
import { t } from "../i18n";
import { ApiError, api } from "../lib/api";
import { useMe } from "../lib/session";
import type { Mapping, MappingCreated, MappingSaved } from "../types/api";

// What the shown-once panel displays. It lives in component state only: never
// in the query cache, the URL, localStorage, or the console.
interface Shown {
  kind: "created" | "rotated";
  mapping: Mapping;
  webhookUrl?: string;
  authSecret?: string;
  projectWebhookExists?: boolean;
}

export default function MappingFormPage() {
  const { id } = useParams();
  const navigate = useNavigate();
  const me = useMe();
  const [shown, setShown] = useState<Shown | null>(null);
  // After an edit save whose Harbor project has no project webhook (#179). Not stored:
  // the next save proposes again.
  const [proposal, setProposal] = useState<{ mappingId: string; harborProject: string } | null>(null);

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
        project={
          shown.kind === "created" && shown.projectWebhookExists !== undefined
            ? { mappingId: shown.mapping.id, webhookExists: shown.projectWebhookExists }
            : undefined
        }
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
              projectWebhookExists: created.project_webhook_exists,
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
  const canPull = owned || me.data?.role === "admin";

  const onRotated = (rotated: Rotated) => setShown({ kind: "rotated", mapping, ...rotated });
  // A project with a project webhook goes back to the list as before. Without one, the
  // page stays and shows the proposal banner, which does not block the form.
  const onUpdated = (saved: MappingSaved) => {
    if (saved.project_webhook_exists) {
      void navigate("/mappings");
    } else {
      setProposal({ mappingId: saved.id, harborProject: saved.harbor_project });
    }
  };

  return (
    <>
      <div className="flex flex-col gap-1.5">
        {back}
        <PageTitle title={t("page.mappingEdit")} />
        <p className="text-muted">{mappingName(mapping)}</p>
      </div>
      {canPull ? <PullScans key={`pull-${mapping.id}`} mapping={mapping} /> : null}
      <MappingForm key={mapping.id} mapping={mapping} readOnly={!owned} onCreated={() => undefined} onUpdated={onUpdated} />
      {/* Below the form actions, where Save was clicked. */}
      {proposal === null ? null : (
        <div className="flex flex-col gap-2">
          <output className="text-[13px] text-ok-ink">{t("mapping.projectWebhook.saved")}</output>
          <ProjectWebhookProposal
            key={`${proposal.mappingId}-${proposal.harborProject}`}
            mappingId={proposal.mappingId}
            harborProject={proposal.harborProject}
            onDismiss={() => setProposal(null)}
          />
        </div>
      )}
      {owned ? (
        <WebhookCard mapping={mapping} onRotated={onRotated} onDeleted={() => void navigate("/mappings")} />
      ) : null}
    </>
  );
}
