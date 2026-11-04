import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useState, type FormEvent } from "react";
import { Link, Navigate, useNavigate } from "react-router";
import { Button } from "../components/ui/Button";
import { LoadingMessage } from "../components/ui/StatusMessage";
import { t } from "../i18n";
import { ApiError, api } from "../lib/api";
import { ME_QUERY_KEY, useSetupStatus, type User } from "../lib/session";

const MIN_LENGTH = 15;
const MAX_LENGTH = 64;
const METER_BARS = 4;
const CHARS_PER_BAR = 7;

// The input border uses the muted token, not the card border: the card border
// is about 1.4:1, and WCAG 1.4.11 asks 3:1 for a control's boundary.
const INPUT = "min-h-11 w-full rounded-lg border border-muted bg-bg px-3 text-sm text-text";

type SetupError = "tooShort" | "done" | "server" | "generic";

// Outside the shell. Shown only while no user exists.
export default function SetupPage() {
  const status = useSetupStatus();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState<{ kind: SetupError; message: string } | null>(null);

  const setup = useMutation({
    mutationFn: () => api<{ user: User }>("POST", "/auth/setup", { username, email, password }),
    onSuccess: (body) => {
      queryClient.setQueryData(ME_QUERY_KEY, body.user);
      void navigate("/");
    },
    onError: (failure) => {
      if (failure instanceof ApiError) {
        if (failure.status === 400 && failure.code === "password_too_short") {
          setError({ kind: "tooShort", message: t("setup.error.tooShort") });
          return;
        }
        if (failure.status === 409) {
          setError({ kind: "done", message: t("setup.error.done") });
          return;
        }
        if (failure.status === 422) {
          setError({ kind: "server", message: failure.message });
          return;
        }
      }
      setError({ kind: "generic", message: t("setup.error.generic") });
    },
  });

  if (status.isPending) {
    return <LoadingMessage />;
  }
  if (status.data?.setup_required === false) {
    return <Navigate to="/login" replace />;
  }

  // Count characters, not UTF-16 units, so an emoji counts as one.
  const length = [...password].length;
  const lengthOk = length >= MIN_LENGTH && length <= MAX_LENGTH;
  const canSubmit = lengthOk && password === confirm && !setup.isPending;
  const filled = Math.min(METER_BARS, Math.ceil(length / CHARS_PER_BAR));
  const tone = lengthOk ? "bg-ok" : "bg-crit";
  const countTone = length === 0 ? "text-muted" : lengthOk ? "text-ok-ink" : "text-crit-ink";

  function submit(event: FormEvent) {
    event.preventDefault();
    if (!canSubmit) {
      return;
    }
    setError(null);
    setup.mutate();
  }

  return (
    <div className="flex min-h-screen flex-col items-center justify-center gap-7 bg-bg px-4 py-12 text-text">
      <div className="flex items-center gap-3">
        <span className="flex size-10 items-center justify-center rounded-[10px] bg-accent text-on-accent">
          <svg
            aria-hidden="true"
            width="22"
            height="22"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2.2"
            strokeLinecap="round"
            strokeLinejoin="round"
          >
            <path d="M4 21V8l8-5 8 5v13" />
            <path d="M9 21v-7h6v7" />
          </svg>
        </span>
        <span className="text-xl font-bold tracking-tight">{t("app.name")}</span>
      </div>

      <main className="flex w-full max-w-[440px] flex-col gap-5 rounded-xl border border-border bg-surface p-7">
        <div className="flex flex-col gap-1.5">
          <span className="text-[11px] leading-none font-semibold tracking-[.08em] text-accent uppercase">
            {t("setup.eyebrow")}
          </span>
          <h1 className="text-xl font-semibold">{t("page.setup")}</h1>
          <p className="text-[13px] text-muted">{t("setup.intro")}</p>
        </div>

        {error === null ? null : (
          <p role="alert" className="text-[13px] text-crit-ink">
            {error.message}
            {error.kind === "done" ? (
              <>
                {" "}
                <Link to="/login" className="text-accent underline">
                  {t("setup.error.doneLink")}
                </Link>
              </>
            ) : null}
          </p>
        )}

        <form onSubmit={submit} className="flex flex-col gap-4">
          <div className="flex flex-col gap-1.5">
            <label htmlFor="setup-username" className="text-[13px] font-semibold">
              {t("setup.username")}
            </label>
            <input
              id="setup-username"
              className={INPUT}
              autoComplete="username"
              required
              value={username}
              onChange={(event) => setUsername(event.target.value)}
            />
          </div>
          <div className="flex flex-col gap-1.5">
            <label htmlFor="setup-email" className="text-[13px] font-semibold">
              {t("setup.email")}
            </label>
            <input
              id="setup-email"
              className={INPUT}
              type="email"
              autoComplete="email"
              required
              value={email}
              onChange={(event) => setEmail(event.target.value)}
            />
          </div>
          <div className="flex flex-col gap-1.5">
            <label htmlFor="setup-password" className="text-[13px] font-semibold">
              {t("setup.password")}
            </label>
            <span id="setup-password-help" className="text-[12.5px] text-muted">
              {t("setup.passwordHelp")}
            </span>
            <input
              id="setup-password"
              className={INPUT}
              type="password"
              autoComplete="new-password"
              aria-describedby="setup-password-help setup-password-count"
              required
              value={password}
              onChange={(event) => setPassword(event.target.value)}
            />
            <div className="flex gap-1" aria-hidden="true">
              {Array.from({ length: METER_BARS }, (_, index) => (
                <span key={index} className={`h-1 flex-1 rounded-sm ${index < filled ? tone : "bg-border"}`} />
              ))}
            </div>
            <span id="setup-password-count" className={`text-[12.5px] ${countTone}`}>
              {t("setup.passwordCount", { n: length })}
            </span>
          </div>
          <div className="flex flex-col gap-1.5">
            <label htmlFor="setup-confirm" className="text-[13px] font-semibold">
              {t("setup.confirm")}
            </label>
            <input
              id="setup-confirm"
              className={INPUT}
              type="password"
              autoComplete="new-password"
              required
              value={confirm}
              onChange={(event) => setConfirm(event.target.value)}
            />
          </div>
          <Button type="submit" variant="primary" className="min-h-11! w-full px-4 text-sm" disabled={!canSubmit}>
            {setup.isPending ? t("setup.submitting") : t("setup.submit")}
          </Button>
        </form>
      </main>
    </div>
  );
}
