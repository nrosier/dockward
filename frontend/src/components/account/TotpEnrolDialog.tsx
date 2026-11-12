import { useEffect, useRef, useState, type FormEvent } from "react";
import { useMutation } from "@tanstack/react-query";
import { Check, Copy } from "lucide-react";
import { t } from "../../i18n";
import { api } from "../../lib/api";
import { FormError, INPUT } from "../admin/parts";
import { Button } from "../ui/Button";
import { CopyField } from "../ui/CopyField";
import { Dialog } from "../ui/Dialog";
import { Field } from "../ui/Field";
import { useCopy } from "../ui/useCopy";
import { QrCode } from "./QrCode";
import { digitsOf, isWrongCode, useCodeMutation } from "./totpCodes";

interface Enrolment {
  secret: string;
  qr_svg: string;
}

// Two steps in one dialog. The secret and the recovery codes live only in this
// component's state (specs/frontend.md: shown-once values). Unmounting drops them.
export function TotpEnrolDialog({ onEnabled, onClose }: { onEnabled: () => void; onClose: () => void }) {
  const enrol = useMutation({ mutationFn: () => api<Enrolment>("POST", "/account/totp/enrol") });
  const confirm = useCodeMutation<{ recovery_codes: string[] }>("/account/totp/confirm");
  const [code, setCode] = useState("");
  const [codes, setCodes] = useState<string[] | null>(null);
  const [saved, setSaved] = useState(false);
  const started = useRef(false);
  const codeInput = useRef<HTMLInputElement>(null);
  const savedBox = useRef<HTMLInputElement>(null);
  const { copied, copy } = useCopy();

  const { mutate: startEnrol } = enrol;
  useEffect(() => {
    // StrictMode mounts twice in development; enrol once per dialog.
    if (!started.current) {
      started.current = true;
      startEnrol();
    }
  }, [startEnrol]);

  useEffect(() => {
    if (enrol.isSuccess && codes === null) {
      codeInput.current?.focus();
    }
  }, [enrol.isSuccess, codes]);

  useEffect(() => {
    if (codes !== null) {
      savedBox.current?.focus();
    }
  }, [codes]);

  function submit(event: FormEvent) {
    event.preventDefault();
    if (code.length !== 6 || confirm.isPending) {
      return;
    }
    confirm.mutate(code, {
      onSuccess: (body) => {
        setCodes(body.recovery_codes);
        onEnabled();
      },
      onError: () => codeInput.current?.select(),
    });
  }

  if (codes !== null) {
    return (
      <Dialog
        open
        onOpenChange={() => undefined}
        dismissible={false}
        title={t("account.totp.recovery.title")}
        description={t("account.totp.recovery.step2")}
      >
        <ul
          aria-label={t("account.totp.recovery.listLabel")}
          className="m-0 grid list-none grid-cols-2 gap-2 rounded-lg border border-border bg-bg p-3 font-mono text-[13px] select-text"
        >
          {codes.map((item) => (
            <li key={item}>{item}</li>
          ))}
        </ul>
        <div className="flex items-center gap-3">
          <Button onClick={() => void copy(codes.join("\n"))}>
            {copied ? <Check aria-hidden="true" size={14} /> : <Copy aria-hidden="true" size={14} />}
            {t("account.totp.recovery.copyAll")}
          </Button>
          <output className="text-[12.5px] text-ok-ink">{copied ? t("common.copied") : ""}</output>
        </div>
        <label className="flex min-h-11 items-center gap-2.5 text-[13px]">
          <input
            ref={savedBox}
            type="checkbox"
            className="size-4 accent-accent"
            checked={saved}
            onChange={(event) => setSaved(event.target.checked)}
          />
          {t("account.totp.recovery.saved")}
        </label>
        <div className="flex justify-end">
          <Button variant="primary" disabled={!saved} onClick={onClose}>
            {t("account.totp.recovery.done")}
          </Button>
        </div>
      </Dialog>
    );
  }

  const wrong = confirm.isError && isWrongCode(confirm.error);
  const failed = enrol.isError || (confirm.isError && !wrong);

  return (
    <Dialog
      open
      onOpenChange={(open) => (open ? undefined : onClose())}
      title={t("account.totp.setup.title")}
      description={t("account.totp.setup.step1")}
    >
      {failed ? (
        <>
          <FormError message={t("account.totp.setup.failed")} />
          <div className="flex justify-end">
            <Button onClick={onClose}>{t("common.close")}</Button>
          </div>
        </>
      ) : enrol.data === undefined ? (
        <output className="text-[13px] text-muted">{t("common.loading")}</output>
      ) : (
        <form onSubmit={submit} className="flex flex-col gap-4">
          <div className="flex flex-col items-center gap-4 sm:flex-row sm:items-start">
            <QrCode svg={enrol.data.qr_svg} label={t("account.totp.setup.qrLabel")} />
            <div className="flex w-full min-w-0 flex-col gap-1.5">
              <label htmlFor="totp-manual-key" className="text-[13px] font-semibold">
                {t("account.totp.setup.manualKey")}
              </label>
              <CopyField id="totp-manual-key" value={enrol.data.secret} label={t("account.totp.setup.manualKey")} />
              <p className="text-[12.5px] text-muted">{t("account.totp.setup.manualHelp")}</p>
            </div>
          </div>
          <Field
            id="totp-setup-code"
            label={t("account.totp.setup.code")}
            help={t("account.totp.setup.codeHelp")}
            error={wrong ? t("account.totp.setup.wrongCode") : undefined}
          >
            <input
              ref={codeInput}
              id="totp-setup-code"
              className={`${INPUT} font-mono tracking-[0.2em]`}
              inputMode="numeric"
              autoComplete="one-time-code"
              maxLength={6}
              aria-invalid={wrong}
              aria-describedby={wrong ? "totp-setup-code-help totp-setup-code-error" : "totp-setup-code-help"}
              value={code}
              onChange={(event) => setCode(digitsOf(event.target.value))}
            />
          </Field>
          <div className="flex justify-end gap-2.5">
            <Button onClick={onClose}>{t("common.cancel")}</Button>
            <Button type="submit" variant="primary" disabled={code.length !== 6 || confirm.isPending}>
              {confirm.isPending ? t("account.totp.setup.confirming") : t("account.totp.setup.confirm")}
            </Button>
          </div>
        </form>
      )}
    </Dialog>
  );
}
