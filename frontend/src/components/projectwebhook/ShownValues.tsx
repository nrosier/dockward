import { TriangleAlert } from "lucide-react";
import { t } from "../../i18n";
import { Panel } from "../mappings/Panel";
import { Button } from "../ui/Button";
import { CopyField } from "../ui/CopyField";

interface ShownValuesProps {
  webhookUrl: string | undefined;
  authSecret: string | undefined;
  onDone: () => void;
}

// The rotated values, shown once. They come in as props from the page's component
// state and are never cached, put in the URL, stored, or logged.
export function ShownValues({ webhookUrl, authSecret, onDone }: ShownValuesProps) {
  return (
    <>
      <div role="alert" className="flex gap-3 rounded-[10px] border border-high/50 bg-high/10 px-4 py-3.5">
        <TriangleAlert aria-hidden="true" size={18} className="mt-0.5 shrink-0 text-high-ink" />
        <span className="font-semibold text-high-ink">{t("projectWebhook.shownOnce.warning")}</span>
      </div>
      <Panel className="flex flex-col gap-4 px-[22px] py-5" aria-label={t("projectWebhook.shownOnce.values")}>
        {webhookUrl === undefined ? null : (
          <div className="flex flex-col gap-1.5">
            <label htmlFor="pw-webhook-url" className="text-[13px] font-semibold">
              {t("projectWebhook.shownOnce.webhookUrl")}
            </label>
            <CopyField id="pw-webhook-url" value={webhookUrl} label={t("projectWebhook.shownOnce.webhookUrl")} />
          </div>
        )}
        {authSecret === undefined ? null : (
          <div className="flex flex-col gap-1.5">
            <label htmlFor="pw-auth-secret" className="text-[13px] font-semibold">
              {t("projectWebhook.shownOnce.authSecret")}
            </label>
            <CopyField id="pw-auth-secret" value={authSecret} label={t("projectWebhook.shownOnce.authSecret")} />
          </div>
        )}
      </Panel>
      <div className="flex justify-end">
        <Button variant="primary" onClick={onDone}>
          {t("projectWebhook.shownOnce.done")}
        </Button>
      </div>
    </>
  );
}
