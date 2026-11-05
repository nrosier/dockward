import { useState } from "react";
import { t } from "../../i18n";
import { ConfirmDialog } from "../mappings/ConfirmDialog";
import { Button, type ButtonVariant } from "../ui/Button";
import type { CveSummary } from "../../types/api";
import { issueNeedsConfirm } from "./CvePills";

interface IssueActionProps {
  cve: Pick<CveSummary, "cve_id" | "open_severity">;
  label: string;
  onCreate: () => void;
  disabled?: boolean;
  pending?: boolean;
  title?: string;
  variant?: ButtonVariant;
}

// The Create issue button. CRITICAL, HIGH and MEDIUM create in one click; LOW
// and UNKNOWN ask for confirmation first (#129).
export function IssueAction({ cve, label, onCreate, disabled = false, pending = false, title, variant }: IssueActionProps) {
  const [confirming, setConfirming] = useState(false);
  const confirm = issueNeedsConfirm(cve.open_severity);
  return (
    <>
      <Button
        variant={variant}
        disabled={disabled || pending}
        title={title}
        onClick={() => (confirm ? setConfirming(true) : onCreate())}
      >
        {label}
      </Button>
      {confirm ? (
        <ConfirmDialog
          open={confirming}
          onOpenChange={setConfirming}
          title={t("cves.confirm.title", { cve: cve.cve_id })}
          description={t("cves.confirm.body", { severity: cve.open_severity ?? "" })}
          confirmLabel={t("cves.confirm.create")}
          pending={pending}
          onConfirm={() => {
            setConfirming(false);
            onCreate();
          }}
        />
      ) : null}
    </>
  );
}
