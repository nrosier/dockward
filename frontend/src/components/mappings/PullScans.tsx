import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { Link } from "react-router";
import { t } from "../../i18n";
import { ApiError, api } from "../../lib/api";
import type { Mapping } from "../../types/api";
import { Button } from "../ui/Button";
import { Panel } from "./Panel";
import { LINK } from "./styles";

// The server allows one pull per mapping per 5 minutes, and counts a pull that
// failed at Harbor too. A 429 carries the exact time left in `Retry-After`.
const COOLDOWN_SECONDS = 300;

type Outcome = { kind: "done"; queued: number } | { kind: "failed" } | null;

function clock(seconds: number): string {
  const minutes = Math.floor(seconds / 60);
  return `${minutes}:${String(seconds % 60).padStart(2, "0")}`;
}

const BANNER = "mt-3 rounded-[10px] border px-4 py-3";

function Result({ outcome }: { outcome: Outcome }) {
  if (outcome === null) {
    return null;
  }
  if (outcome.kind === "failed") {
    return (
      <div role="alert" className={`${BANNER} border-high/50 bg-high/10 text-high-ink`}>
        {t("mapping.pull.failed")}
      </div>
    );
  }
  const zero = outcome.queued === 0;
  const text = zero
    ? t("mapping.pull.zero")
    : outcome.queued === 1
      ? t("mapping.pull.resultOne")
      : t("mapping.pull.result", { n: outcome.queued });
  return (
    <>
      <output
        className={`block ${BANNER} ${zero ? "border-border bg-surface-2 text-text" : "border-ok/45 bg-ok/10 text-ok-ink"}`}
      >
        {text}
      </output>
      <p className="mt-2.5">
        <Link to="/sync-jobs" className={LINK}>
          {t("mapping.pull.viewSyncJobs")}
        </Link>
      </p>
    </>
  );
}

// "Pull scans" panel of the mapping page. Owner and admins only; the caller
// decides who sees it. The browser only sends the request: Harbor is called by
// the server and no Harbor token reaches the browser.
export function PullScans({ mapping }: { mapping: Mapping }) {
  const queryClient = useQueryClient();
  const [outcome, setOutcome] = useState<Outcome>(null);
  const [left, setLeft] = useState(0);

  useEffect(() => {
    if (left <= 0) {
      return;
    }
    const timer = setTimeout(() => setLeft((value) => value - 1), 1000);
    return () => clearTimeout(timer);
  }, [left]);

  const pull = useMutation({
    mutationFn: () => api<{ queued: number }>("POST", `/mappings/${encodeURIComponent(mapping.id)}/pull`),
    onSuccess: async (body) => {
      setOutcome({ kind: "done", queued: body.queued });
      setLeft(COOLDOWN_SECONDS);
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ["sync-jobs"] }),
        queryClient.invalidateQueries({ queryKey: ["dashboard"] }),
        queryClient.invalidateQueries({ queryKey: ["mappings"] }),
      ]);
    },
    onError: (error) => {
      if (error instanceof ApiError && error.status === 429) {
        setLeft(error.retryAfter ?? COOLDOWN_SECONDS);
        return;
      }
      // Any other failure shows the one fixed message; the server text is not shown.
      setOutcome({ kind: "failed" });
      if (error instanceof ApiError && error.status === 502) {
        setLeft(COOLDOWN_SECONDS);
      }
    },
  });

  const cooling = left > 0;
  return (
    <Panel aria-labelledby="pull-scans-heading" className="p-5">
      <h2 id="pull-scans-heading" className="text-[15px] font-semibold">
        {t("mapping.pull.heading")}
      </h2>
      <Result outcome={outcome} />
      <p className="mt-3 text-muted">{t(cooling ? "mapping.pull.cooldownHint" : "mapping.pull.readyHint")}</p>
      <div className="mt-3 flex items-center">
        <Button
          variant={cooling ? "default" : "primary"}
          disabled={cooling || pull.isPending}
          onClick={() => pull.mutate()}
        >
          {pull.isPending ? t("mapping.pull.pulling") : t("mapping.pull.button")}
          {cooling ? (
            <>
              <span aria-hidden="true">·</span>
              <span className="font-mono" aria-label={t("mapping.pull.cooldownTimer", { time: clock(left) })}>
                {clock(left)}
              </span>
            </>
          ) : null}
        </Button>
      </div>
      {cooling ? <p className="mt-2 text-muted">{t("mapping.pull.cooldownNote")}</p> : null}
    </Panel>
  );
}
