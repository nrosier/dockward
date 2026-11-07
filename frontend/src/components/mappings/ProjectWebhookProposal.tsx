import { useMutation } from "@tanstack/react-query";
import { useState } from "react";
import { t } from "../../i18n";
import { ApiError, api } from "../../lib/api";
import type { ProjectWebhookCreated } from "../../types/api";
import { Button } from "../ui/Button";
import { CopyField } from "../ui/CopyField";

interface ProjectWebhookProposalProps {
  // The saved mapping. Its id is sent to create the webhook; only the project is shown.
  mappingId: string;
  harborProject: string;
  onDismiss: () => void;
}

interface Values {
  webhookUrl: string;
  authSecret: string;
}

// The project webhook proposal after a save (#179). Shown only when the save response
// says the Harbor project has no project webhook. An inline banner, not a modal: it
// does not block the page and can be dismissed. A dismissal is not stored. It names the
// Harbor project and no repository. The created values are shown once and live in this
// component's state only, never in the query cache.
export function ProjectWebhookProposal({ mappingId, harborProject, onDismiss }: ProjectWebhookProposalProps) {
  const [values, setValues] = useState<Values | null>(null);
  const [conflict, setConflict] = useState(false);

  const create = useMutation({
    mutationFn: async (): Promise<void> => {
      const body = await api<ProjectWebhookCreated>("POST", "/project-webhooks", { mapping_id: mappingId });
      setValues({ webhookUrl: body.webhook_url, authSecret: body.auth_secret });
    },
    onError: (failure) => {
      // Another user created it first: show the setup note instead.
      if (failure instanceof ApiError && failure.status === 409) setConflict(true);
    },
  });

  let body;
  if (values !== null) {
    body = (
      <>
        <p className="text-[13px] font-semibold text-high-ink">
          {t("mapping.projectWebhook.created", { project: harborProject })}
        </p>
        <div className="flex flex-col gap-1.5">
          <label htmlFor="proposal-webhook-url" className="text-[13px] font-semibold">
            {t("projectWebhook.shownOnce.webhookUrl")}
          </label>
          <CopyField id="proposal-webhook-url" value={values.webhookUrl} label={t("projectWebhook.shownOnce.webhookUrl")} />
        </div>
        <div className="flex flex-col gap-1.5">
          <label htmlFor="proposal-auth-secret" className="text-[13px] font-semibold">
            {t("projectWebhook.shownOnce.authSecret")}
          </label>
          <CopyField id="proposal-auth-secret" value={values.authSecret} label={t("projectWebhook.shownOnce.authSecret")} />
        </div>
      </>
    );
  } else if (conflict) {
    body = <p className="text-[13px]">{t("mapping.projectWebhook.exists", { project: harborProject })}</p>;
  } else {
    body = (
      <>
        <p className="text-[13px]">{t("mapping.projectWebhook.propose", { project: harborProject })}</p>
        {create.isError ? (
          <p role="alert" className="text-[13px] text-crit-ink">
            {t("errors.generic")}
          </p>
        ) : null}
        <div className="flex flex-wrap gap-2">
          <Button variant="primary" disabled={create.isPending} onClick={() => create.mutate()}>
            {create.isPending ? t("mapping.projectWebhook.creating") : t("mapping.projectWebhook.create")}
          </Button>
        </div>
      </>
    );
  }

  return (
    <section
      aria-label={t("mapping.projectWebhook.label")}
      className="flex flex-col gap-3 rounded-[10px] border border-accent/40 bg-accent/10 px-4 py-3.5"
    >
      {body}
      {values === null ? (
        <div className="flex">
          <Button variant="small" onClick={onDismiss}>
            {t("mapping.projectWebhook.dismiss")}
          </Button>
        </div>
      ) : (
        <div className="flex">
          <Button variant="small" onClick={onDismiss}>
            {t("projectWebhook.shownOnce.done")}
          </Button>
        </div>
      )}
    </section>
  );
}
