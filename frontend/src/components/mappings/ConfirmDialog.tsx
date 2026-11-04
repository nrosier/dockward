import { Dialog } from "../ui/Dialog";
import { Button } from "../ui/Button";
import { t } from "../../i18n";

interface ConfirmDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: string;
  description: string;
  confirmLabel: string;
  onConfirm: () => void;
  pending?: boolean;
  danger?: boolean;
  error?: string | null;
}

export function ConfirmDialog({
  open,
  onOpenChange,
  title,
  description,
  confirmLabel,
  onConfirm,
  pending = false,
  danger = false,
  error = null,
}: ConfirmDialogProps) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange} title={title} description={description}>
      {error === null ? null : (
        <p role="alert" className="text-[13px] text-crit-ink">
          {error}
        </p>
      )}
      <div className="flex flex-wrap justify-end gap-2.5">
        <Button onClick={() => onOpenChange(false)}>{t("mappings.cancel")}</Button>
        <Button variant={danger ? "danger" : "primary"} disabled={pending} onClick={onConfirm}>
          {confirmLabel}
        </Button>
      </div>
    </Dialog>
  );
}
