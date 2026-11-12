import { useState, type FormEvent } from "react";
import { t } from "../../i18n";
import { FormError, INPUT } from "../admin/parts";
import { Button } from "../ui/Button";
import { Dialog } from "../ui/Dialog";
import { Field } from "../ui/Field";
import { digitsOf, isWrongCode, useCodeMutation } from "./totpCodes";

// Needs a current authenticator code (POST /account/totp/disable). Focus starts in
// the code field, not on the destructive button. Cancel and Escape send nothing.
export function TotpDisableDialog({ onDisabled, onClose }: { onDisabled: () => void; onClose: () => void }) {
  const disable = useCodeMutation<void>("/account/totp/disable");
  const [code, setCode] = useState("");
  const wrong = disable.isError && isWrongCode(disable.error);

  function submit(event: FormEvent) {
    event.preventDefault();
    if (code.length !== 6 || disable.isPending) {
      return;
    }
    disable.mutate(code, { onSuccess: onDisabled });
  }

  return (
    <Dialog
      open
      onOpenChange={(open) => (open ? undefined : onClose())}
      title={t("account.totp.disable.title")}
      description={t("account.totp.disable.body")}
    >
      <form onSubmit={submit} className="flex flex-col gap-4">
        <Field
          id="totp-disable-code"
          label={t("account.totp.disable.code")}
          error={wrong ? t("account.totp.disable.wrongCode") : undefined}
        >
          <input
            id="totp-disable-code"
            // oxlint-disable-next-line jsx-a11y/no-autofocus -- the dialog's first control is this field by design
            autoFocus
            className={`${INPUT} font-mono tracking-[0.2em]`}
            inputMode="numeric"
            autoComplete="one-time-code"
            maxLength={6}
            aria-invalid={wrong}
            aria-describedby={wrong ? "totp-disable-code-error" : undefined}
            value={code}
            onChange={(event) => setCode(digitsOf(event.target.value))}
          />
        </Field>
        {disable.isError && !wrong ? <FormError message={t("account.totp.disable.failed")} /> : null}
        <div className="flex justify-end gap-2.5">
          <Button onClick={onClose}>{t("common.cancel")}</Button>
          <Button type="submit" variant="danger" disabled={code.length !== 6 || disable.isPending}>
            {disable.isPending ? t("account.totp.disable.confirming") : t("account.totp.disable.confirm")}
          </Button>
        </div>
      </form>
    </Dialog>
  );
}
