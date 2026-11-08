import { t } from "../../i18n";
import type { CveSummary } from "../../types/api";
import { Dialog } from "../ui/Dialog";
import { Button } from "../ui/Button";
import { SeverityPill } from "./CvePills";

interface CreateIssueDialogProps {
  cve: CveSummary | null;
  // The GitHub repository the issue goes to, as owner/repo.
  repository: string;
  pending: boolean;
  onCancel: () => void;
  onConfirm: (cve: CveSummary) => void;
}

// The confirmation before a list row creates a GitHub issue (#257, decision 10). Nothing is
// created until Confirm.
export function CreateIssueDialog({ cve, repository, pending, onCancel, onConfirm }: CreateIssueDialogProps) {
  return (
    <Dialog
      open={cve !== null}
      onOpenChange={(open) => {
        if (!open) {
          onCancel();
        }
      }}
      title={t("cves.createDialog.title", { cve: cve?.cve_id ?? "" })}
      description={t("cves.createDialog.body")}
    >
      {cve === null ? null : (
        <>
          <dl className="m-0 grid grid-cols-[auto_1fr] gap-x-4 gap-y-2 rounded-lg border border-border bg-bg px-3.5 py-3 text-[13px]">
            <dt className="text-muted">{t("cves.createDialog.repo")}</dt>
            <dd className="m-0 font-mono">{repository}</dd>
            <dt className="text-muted">{t("cves.createDialog.cve")}</dt>
            <dd className="m-0 flex flex-wrap items-center gap-2">
              <span className="font-mono">{cve.cve_id}</span>
              <SeverityPill severity={cve.open_severity ?? cve.severity} />
            </dd>
            <dt className="text-muted">{t("cves.createDialog.package")}</dt>
            <dd className="m-0">{cve.package ?? t("cves.unknown")}</dd>
          </dl>
          <div className="flex flex-wrap justify-end gap-2.5">
            <Button onClick={onCancel}>{t("mappings.cancel")}</Button>
            <Button variant="primary" disabled={pending} onClick={() => onConfirm(cve)}>
              {t("cves.createDialog.confirm")}
            </Button>
          </div>
        </>
      )}
    </Dialog>
  );
}
