import { TriangleAlert } from "lucide-react";
import { t } from "../../i18n";
import { buttonClass } from "../ui/Button";
import { Panel } from "./Panel";
import { CopyField } from "../ui/CopyField";

interface ShownOnceProps {
  // `created` after a create, `rotated` after a rotation.
  kind: "created" | "rotated";
  harborProject: string;
  harborName: string;
  githubTarget: string;
  webhookUrl?: string;
  authSecret?: string;
  onDone: () => void;
}

// The webhook URL and auth secret, shown once. The values come in as props from
// the page's component state. They are never written to the query cache, the
// URL, localStorage, or the console.
export function ShownOnce({ kind, harborProject, harborName, githubTarget, webhookUrl, authSecret, onDone }: ShownOnceProps) {
  const both = webhookUrl !== undefined && authSecret !== undefined;
  return (
    <>
      <div className="flex flex-col gap-1.5">
        <h1 className="text-2xl font-semibold tracking-tight">
          {t(kind === "created" ? "mappings.created.title" : "mappings.rotated.title")}
        </h1>
        <p className="text-muted">
          {harborName} → <span className="font-mono text-[13px]">{githubTarget}</span>
        </p>
      </div>

      <div role="alert" className="flex gap-3 rounded-[10px] border border-high/50 bg-high/10 px-4 py-3.5">
        <TriangleAlert aria-hidden="true" size={18} className="mt-0.5 shrink-0 text-high-ink" />
        <div className="flex flex-col gap-0.5">
          <span className="font-semibold text-high-ink">
            {t(both ? "mappings.shownOnce.warningBoth" : "mappings.shownOnce.warningOne")}
          </span>
          <span className="text-[13px] text-text/80">{t("mappings.shownOnce.hash")}</span>
        </div>
      </div>

      <Panel className="flex flex-col gap-4 px-[22px] py-5" aria-label={t("mappings.shownOnce.values")}>
        {webhookUrl === undefined ? null : (
          <div className="flex flex-col gap-1.5">
            <label htmlFor="shown-webhook-url" className="text-[13px] font-semibold">
              {t("mappings.shownOnce.webhookUrl")}
            </label>
            <CopyField id="shown-webhook-url" value={webhookUrl} label={t("mappings.shownOnce.webhookUrl")} />
          </div>
        )}
        {authSecret === undefined ? null : (
          <div className="flex flex-col gap-1.5">
            <label htmlFor="shown-auth-secret" className="text-[13px] font-semibold">
              {t("mappings.shownOnce.authSecret")}
            </label>
            <CopyField id="shown-auth-secret" value={authSecret} label={t("mappings.shownOnce.authSecret")} />
          </div>
        )}
      </Panel>

      <Panel className="flex flex-col gap-3 px-[22px] py-5" aria-labelledby="harbor-steps">
        <h2 id="harbor-steps" className="text-[15px] font-semibold">
          {t("mappings.shownOnce.stepsTitle")}
        </h2>
        <ol className="m-0 flex list-decimal flex-col gap-2 pl-5">
          <li>
            {t("mappings.shownOnce.step1a")} <span className="font-mono text-[13px]">{harborProject}</span>
            {t("mappings.shownOnce.step1b")}
          </li>
          <li>{t("mappings.shownOnce.step2")}</li>
          <li>{t("mappings.shownOnce.step3")}</li>
        </ol>
        <p className="text-[12.5px] text-muted">{t("mappings.shownOnce.polling")}</p>
      </Panel>

      <div className="flex justify-end">
        <button type="button" className={buttonClass("primary")} onClick={onDone}>
          {t("mappings.shownOnce.done")}
        </button>
      </div>
    </>
  );
}
