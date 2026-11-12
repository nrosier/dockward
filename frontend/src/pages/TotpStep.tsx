import { useMutation } from "@tanstack/react-query";
import { useCallback, useRef, useState, type FormEvent } from "react";
import { Button } from "../components/ui/Button";
import { t } from "../i18n";
import { ApiError, api } from "../lib/api";
import type { User } from "../lib/session";

const LINK =
  "cursor-pointer self-start rounded-sm text-[13px] text-accent underline-offset-2 hover:underline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent";

// Retry-After seconds as whole minutes, at least 1. 15 minutes when absent.
function minutesOf(error: ApiError): number {
  return error.retryAfter === undefined ? 15 : Math.max(1, Math.ceil(error.retryAfter / 60));
}

interface TotpStepProps {
  input: string;
  onSignedIn: (user: User) => void;
  onBack: () => void;
}

// The code step of sign-in, shown in the login card after a correct password.
// A wrong code and an expired challenge both get the wrong-password text, as the
// server answers the same 401 for each and for a wrong password.
export function TotpStep({ input, onSignedIn, onBack }: TotpStepProps) {
  const [recovery, setRecovery] = useState(false);
  const [code, setCode] = useState("");
  const [error, setError] = useState<string | null>(null);
  const field = useRef<HTMLInputElement>(null);

  // Each mode has its own keyed input, so this runs when the step appears and on
  // every mode switch: focus is always on the field in view.
  const attach = useCallback((node: HTMLInputElement | null) => {
    field.current = node;
    node?.focus();
  }, []);

  const verify = useMutation({
    mutationFn: (value: string) => api<{ user: User }>("POST", "/auth/totp/verify", { code: value }),
    onSuccess: (body) => onSignedIn(body.user),
    onError: (failure) => {
      if (failure instanceof ApiError && failure.status === 429) {
        setError(t("login.totp.locked", { minutes: minutesOf(failure) }));
      } else if (failure instanceof ApiError && failure.status === 401) {
        setError(t("login.error.failed"));
      } else {
        setError(t("errors.generic"));
      }
      setCode("");
      field.current?.focus();
    },
  });

  function submit(event: FormEvent) {
    event.preventDefault();
    const value = code.trim();
    if (value === "" || verify.isPending) {
      return;
    }
    setError(null);
    verify.mutate(value);
  }

  function toggle() {
    setRecovery((on) => !on);
    setCode("");
    setError(null);
  }

  const id = recovery ? "login-totp-recovery" : "login-totp-code";

  return (
    <div className="flex flex-col gap-5" aria-live="polite">
      <div className="flex flex-col gap-1">
        <h1 className="text-xl font-semibold">{t(recovery ? "login.totp.recovery.title" : "login.totp.title")}</h1>
        <p className="text-[13px] text-muted">{t(recovery ? "login.totp.recovery.help" : "login.totp.help")}</p>
      </div>
      {error === null ? null : (
        <p id="login-totp-error" role="alert" className="text-[13px] text-crit-ink">
          {error}
        </p>
      )}
      <form onSubmit={submit} className="flex flex-col gap-4">
        <div className="flex flex-col gap-1.5">
          <label htmlFor={id} className="text-[13px] font-semibold">
            {t(recovery ? "login.totp.recovery.code" : "login.totp.code")}
          </label>
          {recovery ? (
            <input
              key="recovery"
              ref={attach}
              id={id}
              className={`${input} font-mono`}
              autoComplete="one-time-code"
              autoCapitalize="characters"
              spellCheck={false}
              readOnly={verify.isPending}
              aria-describedby={error === null ? undefined : "login-totp-error"}
              value={code}
              onChange={(event) => setCode(event.target.value)}
            />
          ) : (
            <input
              key="app"
              ref={attach}
              id={id}
              className={`${input} font-mono tracking-[0.2em]`}
              inputMode="numeric"
              autoComplete="one-time-code"
              maxLength={6}
              readOnly={verify.isPending}
              aria-describedby={error === null ? undefined : "login-totp-error"}
              value={code}
              onChange={(event) => setCode(event.target.value.replace(/\D/g, "").slice(0, 6))}
            />
          )}
        </div>
        <Button type="submit" variant="primary" className="min-h-11! w-full px-4 text-sm" disabled={verify.isPending}>
          {verify.isPending ? t("login.totp.submitting") : t("login.totp.submit")}
        </Button>
      </form>
      <div className="flex flex-col gap-2">
        <button type="button" className={LINK} onClick={toggle}>
          {t(recovery ? "login.totp.useApp" : "login.totp.useRecovery")}
        </button>
        <button type="button" className={LINK} onClick={onBack}>
          {t("login.totp.back")}
        </button>
      </div>
      <p className="text-[12.5px] text-muted">{t("login.totp.timeout")}</p>
    </div>
  );
}
