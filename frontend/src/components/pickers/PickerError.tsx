import { useEffect, useState } from "react";
import { t } from "../../i18n";
import { ApiError } from "../../lib/api";
import { Button } from "../ui/Button";

const DETAIL = {
  harbor_identity: "mapping.errors.detail.harborIdentity",
  robot_scope: "mapping.errors.detail.robotScope",
  github_token: "mapping.errors.detail.githubToken",
  wrong_credential_type: "mapping.errors.detail.wrongCredentialType",
} as const;

function clock(seconds: number): string {
  const minutes = Math.floor(seconds / 60);
  return `${minutes}:${String(seconds % 60).padStart(2, "0")}`;
}

// Display-only countdown from Retry-After. It never retries: at zero the
// button becomes available and the user decides.
function RateLimited({ seconds, onRetry }: { seconds: number | undefined; onRetry?: () => void }) {
  const [left, setLeft] = useState(seconds ?? 0);
  useEffect(() => {
    if (left <= 0) {
      return;
    }
    const timer = setTimeout(() => setLeft((current) => current - 1), 1000);
    return () => clearTimeout(timer);
  }, [left]);
  return (
    <>
      <p>{t("mapping.errors.rateLimit.message")}</p>
      <p className="text-[12.5px] text-muted">{t("mapping.errors.rateLimit.note")}</p>
      {onRetry === undefined ? null : (
        <Button variant="small" className="self-start" disabled={left > 0} onClick={onRetry}>
          {left > 0 ? t("mapping.errors.rateLimit.wait", { time: clock(left) }) : t("mapping.errors.tryAgain")}
        </Button>
      )}
    </>
  );
}

function bodyOf(error: unknown, onRetry: (() => void) | undefined, stamp: number | undefined) {
  if (error instanceof ApiError) {
    if (error.status === 429) {
      return <RateLimited key={stamp} seconds={error.retryAfter} onRetry={onRetry} />;
    }
    if (error.status === 502) {
      return (
        <>
          <p>{t("mapping.errors.upstream.message")}</p>
          <p className="text-[12.5px] text-muted">{t("mapping.errors.noAutoRetry")}</p>
          {onRetry === undefined ? null : (
            <Button variant="small" className="self-start" onClick={onRetry}>
              {t("mapping.errors.tryAgain")}
            </Button>
          )}
        </>
      );
    }
    if (error.status === 422 && error.detail !== undefined && error.detail in DETAIL) {
      return <p>{t(DETAIL[error.detail as keyof typeof DETAIL])}</p>;
    }
    if (error.status === 404) {
      return <p>{t("mapping.errors.notFound")}</p>;
    }
  }
  return <p>{t("errors.generic")}</p>;
}

// The error panel for a picker. Only catalog text is shown: the server's
// message is never rendered. A live region, like StatusMessage's ErrorMessage.
export function PickerError({ error, onRetry, stamp }: { error: unknown; onRetry?: () => void; stamp?: number }) {
  return (
    <div role="alert" className="flex flex-col gap-1.5 rounded-lg border border-crit/45 bg-crit/12 px-3 py-2 text-[13px] text-crit-ink">
      {bodyOf(error, onRetry, stamp)}
    </div>
  );
}

// The failure of a hide action. A 422 here is the 1,000-item cap (the name came
// from the list, so it passed the name checks); anything else is generic.
export function HideError({ error }: { error: unknown }) {
  const capped = error instanceof ApiError && error.status === 422;
  return (
    <p role="alert" className="rounded-lg border border-crit/45 bg-crit/12 px-3 py-2 text-[13px] text-crit-ink">
      {capped ? t("mapping.hide.cap") : t("errors.generic")}
    </p>
  );
}
