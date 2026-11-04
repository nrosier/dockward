import { useMutation, useQueryClient } from "@tanstack/react-query";
import { KeyRound } from "lucide-react";
import { useEffect, useState, type FormEvent } from "react";
import { Navigate, useLocation, useNavigate } from "react-router";
import { Button, buttonClass } from "../components/ui/Button";
import { LoadingMessage } from "../components/ui/StatusMessage";
import { t } from "../i18n";
import { ApiError, api } from "../lib/api";
import { ME_QUERY_KEY, useSetupStatus, type User } from "../lib/session";

// The input border uses the muted token, not the card border: the card border
// is about 1.4:1, and WCAG 1.4.11 asks 3:1 for a control's boundary.
const INPUT = "min-h-11 w-full rounded-lg border border-muted bg-bg px-3 text-sm text-text";

// Outside the shell. Every failed sign-in shows one message, so the page never
// says whether the username exists. The server's code and text are not shown.
export default function LoginPage() {
  const status = useSetupStatus();
  const navigate = useNavigate();
  const location = useLocation();
  const queryClient = useQueryClient();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(() =>
    new URLSearchParams(location.search).has("oidc_error") ? t("login.error.sso") : null,
  );

  // Drop `oidc_error` from the address bar. The message stays on screen.
  useEffect(() => {
    if (new URLSearchParams(location.search).has("oidc_error")) {
      void navigate({ search: "" }, { replace: true });
    }
  }, [location.search, navigate]);

  const login = useMutation({
    mutationFn: () => api<{ user: User }>("POST", "/auth/login", { username, password }),
    onSuccess: (body) => {
      queryClient.setQueryData(ME_QUERY_KEY, body.user);
      void navigate("/");
    },
    onError: (failure) => {
      setError(
        failure instanceof ApiError && failure.status === 429
          ? t("login.error.rateLimited")
          : t("login.error.failed"),
      );
      setPassword("");
    },
  });

  if (status.isPending) {
    return <LoadingMessage />;
  }
  if (status.data?.setup_required) {
    return <Navigate to="/setup" replace />;
  }
  const oidc = status.data?.oidc_enabled === true;

  function submit(event: FormEvent) {
    event.preventDefault();
    setError(null);
    login.mutate();
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

      <main className="flex w-full max-w-[400px] flex-col gap-5 rounded-xl border border-border bg-surface p-7">
        <div className="flex flex-col gap-1">
          <h1 className="text-xl font-semibold">{t("page.login")}</h1>
          <p className="text-[13px] text-muted">{t("login.tagline")}</p>
        </div>

        {error === null ? null : (
          <p role="alert" className="text-[13px] text-crit-ink">
            {error}
          </p>
        )}

        {oidc ? (
          <>
            <a href="/api/v1/auth/oidc/start" className={`${buttonClass("default")} min-h-11! w-full px-4 text-sm`}>
              <KeyRound aria-hidden="true" size={18} />
              {t("login.sso")}
            </a>
            <div className="flex items-center gap-3 text-xs text-muted">
              <span className="h-px flex-1 bg-border" />
              {t("login.divider")}
              <span className="h-px flex-1 bg-border" />
            </div>
          </>
        ) : null}

        <form onSubmit={submit} className="flex flex-col gap-4">
          <div className="flex flex-col gap-1.5">
            <label htmlFor="login-username" className="text-[13px] font-semibold">
              {t("login.username")}
            </label>
            <input
              id="login-username"
              className={INPUT}
              autoComplete="username"
              required
              value={username}
              onChange={(event) => setUsername(event.target.value)}
            />
          </div>
          <div className="flex flex-col gap-1.5">
            <label htmlFor="login-password" className="text-[13px] font-semibold">
              {t("login.password")}
            </label>
            <input
              id="login-password"
              className={INPUT}
              type="password"
              autoComplete="current-password"
              required
              value={password}
              onChange={(event) => setPassword(event.target.value)}
            />
          </div>
          <Button type="submit" variant="primary" className="min-h-11! w-full px-4 text-sm" disabled={login.isPending}>
            {login.isPending ? t("login.submitting") : t("login.submit")}
          </Button>
        </form>
      </main>

      <p className="max-w-[400px] text-center text-[12.5px] text-muted">{t("login.note")}</p>
    </div>
  );
}
