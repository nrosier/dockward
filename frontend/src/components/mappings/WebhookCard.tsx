import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { t } from "../../i18n";
import { api } from "../../lib/api";
import type { Mapping } from "../../types/api";
import { Button } from "../ui/Button";
import { Panel } from "./Panel";
import { ConfirmDialog } from "./ConfirmDialog";
import { mappingName } from "./useMappings";

export interface Rotated {
  webhookUrl?: string;
  authSecret?: string;
}

interface WebhookCardProps {
  mapping: Mapping;
  // Receives the new value. The page holds it in component state only.
  onRotated: (rotated: Rotated) => void;
  // Called after `204`; the page navigates to /mappings.
  onDeleted: () => void;
}

type Which = "webhook" | "secret";

// "Webhook" card and the "Delete mapping" button of the edit screen.
export function WebhookCard({ mapping, onRotated, onDeleted }: WebhookCardProps) {
  const queryClient = useQueryClient();
  const [confirm, setConfirm] = useState<Which | null>(null);
  const [deleting, setDeleting] = useState(false);

  // The mutation returns nothing: the secret goes to `onRotated` and is never
  // held by the mutation cache.
  const rotate = useMutation({
    mutationFn: async (which: Which): Promise<void> => {
      const base = `/mappings/${encodeURIComponent(mapping.id)}`;
      if (which === "webhook") {
        const body = await api<{ webhook_url: string }>("POST", `${base}/rotate-webhook-token`);
        onRotated({ webhookUrl: body.webhook_url });
      } else {
        const body = await api<{ auth_secret: string }>("POST", `${base}/rotate-auth-secret`);
        onRotated({ authSecret: body.auth_secret });
      }
    },
    onSuccess: () => setConfirm(null),
  });

  const remove = useMutation({
    mutationFn: () => api<void>("DELETE", `/mappings/${encodeURIComponent(mapping.id)}`),
    onSuccess: async () => {
      setDeleting(false);
      await queryClient.invalidateQueries({ queryKey: ["mappings"] });
      await queryClient.invalidateQueries({ queryKey: ["dashboard"] });
      await queryClient.invalidateQueries({ queryKey: ["cves"] });
      await queryClient.invalidateQueries({ queryKey: ["sync-jobs"] });
      onDeleted();
    },
  });

  const name = mappingName(mapping);
  return (
    <>
      <Panel className="flex flex-col gap-3 px-[22px] py-5" aria-labelledby="webhook-card">
        <h2 id="webhook-card" className="text-[15px] font-semibold">
          {t("mappings.webhook.title")}
        </h2>
        <p className="text-[13px] text-muted">{t("mappings.webhook.help")}</p>
        <div className="flex flex-wrap gap-2.5">
          <Button onClick={() => setConfirm("webhook")}>{t("mappings.webhook.rotateUrl")}</Button>
          <Button onClick={() => setConfirm("secret")}>{t("mappings.webhook.rotateSecret")}</Button>
        </div>
      </Panel>

      <div>
        <Button variant="danger" onClick={() => setDeleting(true)}>
          {t("mappings.delete.button")}
        </Button>
      </div>

      <ConfirmDialog
        open={confirm !== null}
        onOpenChange={(open) => {
          if (!open) setConfirm(null);
        }}
        title={t(confirm === "secret" ? "mappings.webhook.rotateSecret" : "mappings.webhook.rotateUrl")}
        description={t("mappings.webhook.confirm")}
        confirmLabel={t(confirm === "secret" ? "mappings.webhook.rotateSecret" : "mappings.webhook.rotateUrl")}
        pending={rotate.isPending}
        error={rotate.isError ? t("errors.generic") : null}
        onConfirm={() => {
          if (confirm !== null) rotate.mutate(confirm);
        }}
      />

      <ConfirmDialog
        open={deleting}
        onOpenChange={setDeleting}
        title={t("mappings.delete.title")}
        description={t("mappings.delete.body", { name })}
        confirmLabel={t("mappings.delete.confirm")}
        danger
        pending={remove.isPending}
        error={remove.isError ? t("errors.generic") : null}
        onConfirm={() => remove.mutate()}
      />
    </>
  );
}
