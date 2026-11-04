import { t } from "../../i18n";

export function LoadingMessage() {
  return <output className="block p-8 text-muted">{t("common.loading")}</output>;
}

export function ErrorMessage() {
  return (
    <p role="alert" className="p-8 text-crit-ink">
      {t("errors.generic")}
    </p>
  );
}

export function NotFoundMessage() {
  return (
    <div className="flex flex-col gap-1 py-8">
      <h1 className="text-2xl font-semibold tracking-tight">{t("errors.notFound.title")}</h1>
      <p className="text-muted">{t("errors.notFound.body")}</p>
    </div>
  );
}
