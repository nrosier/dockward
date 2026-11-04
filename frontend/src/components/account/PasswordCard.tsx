import { useMutation } from "@tanstack/react-query";
import { useState, type FormEvent } from "react";
import { t } from "../../i18n";
import { ApiError, api } from "../../lib/api";
import { CardHeading, FormError, INPUT } from "../admin/parts";
import { Button } from "../ui/Button";
import { Card } from "../ui/Card";
import { Field } from "../ui/Field";

const MIN_LENGTH = 15;
const MAX_LENGTH = 64;

// Local users only. The three fields are cleared as soon as the request is sent.
export function PasswordCard() {
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [message, setMessage] = useState<{ ok: boolean; text: string } | null>(null);

  const change = useMutation({
    mutationFn: (body: { current_password: string; new_password: string }) =>
      api<void>("POST", "/account/password", body),
    onSuccess: () => setMessage({ ok: true, text: t("account.password.changed") }),
    onError: (failure) => {
      if (failure instanceof ApiError && failure.status === 401) {
        setMessage({ ok: false, text: t("account.password.wrong") });
      } else if (failure instanceof ApiError && failure.status === 400 && failure.code === "password_too_short") {
        setMessage({ ok: false, text: t("account.password.tooShort") });
      } else {
        setMessage({ ok: false, text: t("errors.generic") });
      }
    },
  });

  const length = [...next].length;
  const lengthOk = length >= MIN_LENGTH && length <= MAX_LENGTH;
  const canSubmit = current !== "" && lengthOk && next === confirm && !change.isPending;

  function submit(event: FormEvent) {
    event.preventDefault();
    if (!canSubmit) {
      return;
    }
    setMessage(null);
    change.mutate({ current_password: current, new_password: next });
    setCurrent("");
    setNext("");
    setConfirm("");
  }

  return (
    <Card className="flex flex-col gap-4 p-5" aria-labelledby="account-password">
      <CardHeading id="account-password" title={t("account.password.title")} help={t("account.password.help")} />
      <form onSubmit={submit} className="flex flex-col gap-4">
        <Field id="account-current" label={t("account.password.current")}>
          <input
            id="account-current"
            className={INPUT}
            type="password"
            autoComplete="current-password"
            value={current}
            onChange={(event) => setCurrent(event.target.value)}
          />
        </Field>
        <Field id="account-new" label={t("account.password.new")} help={t("account.password.newHelp")}>
          <input
            id="account-new"
            className={INPUT}
            type="password"
            autoComplete="new-password"
            aria-describedby="account-new-help"
            value={next}
            onChange={(event) => setNext(event.target.value)}
          />
        </Field>
        <Field id="account-confirm" label={t("account.password.confirm")}>
          <input
            id="account-confirm"
            className={INPUT}
            type="password"
            autoComplete="new-password"
            value={confirm}
            onChange={(event) => setConfirm(event.target.value)}
          />
        </Field>
        {message === null ? null : message.ok ? (
          <output className="text-[13px] text-ok-ink">{message.text}</output>
        ) : (
          <FormError message={message.text} />
        )}
        <div>
          <Button type="submit" variant="primary" disabled={!canSubmit}>
            {t("account.password.submit")}
          </Button>
        </div>
      </form>
    </Card>
  );
}
