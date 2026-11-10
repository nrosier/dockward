import { useMutation } from "@tanstack/react-query";
import { useState } from "react";
import { CardHeading, FormError, statusOf, messageOf } from "../components/admin/parts";
import { Button } from "../components/ui/Button";
import { Card } from "../components/ui/Card";
import { t } from "../i18n";
import { api } from "../lib/api";

interface BackupResult {
  file: string;
  path: string;
}

export default function AdminBackupPage() {
  const [last, setLast] = useState<string | null>(null);
  const create = useMutation({
    mutationFn: () => api<BackupResult>("POST", "/admin/backup"),
    onSuccess: (body) => setLast(`${body.path.replace(/\/+$/, "")}/${body.file}`),
  });
  const error = create.isError
    ? statusOf(create.error) === 500
      ? t("admin.backup.failed")
      : messageOf(create.error)
    : null;

  return (
    <div className="flex flex-col gap-5">
      <Card className="flex flex-col gap-4 p-5" aria-labelledby="backup-create">
        <CardHeading
          id="backup-create"
          title={t("admin.backup.title")}
          help={t("admin.backup.help")}
          action={
            <Button variant="primary" disabled={create.isPending} onClick={() => create.mutate()}>
              {t("admin.backup.create")}
            </Button>
          }
        />
        {last === null ? null : (
          <output className="flex flex-col gap-1 rounded-lg border border-ok/45 bg-ok/12 p-3">
            <span className="text-[13px] font-semibold text-ok-ink">{t("admin.backup.written")}</span>
            <code className="font-mono text-[12.5px] break-all">{last}</code>
          </output>
        )}
        <FormError message={error} />
        <p className="text-[12.5px] text-muted">{t("admin.backup.keyNote")}</p>
      </Card>
      <Card className="flex flex-col gap-3 p-5" aria-labelledby="backup-restore">
        <CardHeading id="backup-restore" title={t("admin.restore.title")} help={t("admin.restore.help")} />
        <ol className="m-0 flex list-decimal flex-col gap-2 pl-5 text-[13px]">
          <li>{t("admin.restore.stop")}</li>
          <li>
            {t("admin.restore.run")}
            <pre className="mt-2 overflow-x-auto rounded-lg border border-border bg-bg p-3 font-mono text-[12.5px]">
              {`dockward restore ${last ?? t("admin.restore.placeholder")}`}
            </pre>
          </li>
          <li>{t("admin.restore.start")}</li>
        </ol>
        <p className="text-[12.5px] text-muted">{t("admin.restore.docs")}</p>
      </Card>
    </div>
  );
}
