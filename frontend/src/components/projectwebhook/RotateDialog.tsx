import { t } from "../../i18n";
import { Button } from "../ui/Button";
import { Dialog } from "../ui/Dialog";

interface RotateDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  mappings: string[];
  pending: boolean;
  error: string | null;
  onConfirm: () => void;
}

// Nothing is revoked until Confirm. The list is every mapping that stops receiving events.
export function RotateDialog({ open, onOpenChange, mappings, pending, error, onConfirm }: RotateDialogProps) {
  return (
    <Dialog
      open={open}
      onOpenChange={onOpenChange}
      title={t("projectWebhook.rotate.title")}
      description={t("projectWebhook.rotate.warning")}
    >
      <div className="flex flex-col gap-2">
        {mappings.length === 0 ? (
          <p className="text-[13px] text-muted">{t("projectWebhook.rotate.affectedNone")}</p>
        ) : (
          <>
            <p className="font-mono text-[13px]">{t("projectWebhook.rotate.affectedHeading")}</p>
            <ul className="m-0 list-disc pl-[18px]">
              {mappings.map((name) => (
                <li key={name} className="font-mono text-[13px]">
                  {name}
                </li>
              ))}
            </ul>
          </>
        )}
        <p className="mt-1 text-[13px] text-muted">{t("projectWebhook.rotate.followUp")}</p>
      </div>
      {error === null ? null : (
        <p role="alert" className="text-[13px] text-crit-ink">
          {error}
        </p>
      )}
      <div className="flex flex-wrap justify-end gap-2.5">
        <Button onClick={() => onOpenChange(false)}>{t("common.cancel")}</Button>
        <Button variant="primary" disabled={pending} onClick={onConfirm}>
          {t("projectWebhook.rotate.confirm")}
        </Button>
      </div>
    </Dialog>
  );
}
