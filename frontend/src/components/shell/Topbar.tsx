import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Menu } from "lucide-react";
import { useNavigate } from "react-router";
import { t } from "../../i18n";
import { api } from "../../lib/api";
import { useMe } from "../../lib/session";
import { Button } from "../ui/Button";

// `GET /admin/health` makes outbound calls, so it is fetched at most once every
// 10 minutes (specs/frontend.md, "Screen designs").
export const HEALTH_INTERVAL_MS = 600_000;

interface Check {
  ok: boolean;
  reachable: boolean;
}

export interface AdminHealth {
  github: Check[];
}

export function useAdminHealth(enabled: boolean) {
  return useQuery({
    queryKey: ["admin", "health"],
    queryFn: () => api<AdminHealth>("GET", "/admin/health"),
    enabled,
    staleTime: HEALTH_INTERVAL_MS,
    refetchInterval: HEALTH_INTERVAL_MS,
  });
}

const BADGE = "inline-flex h-6 items-center gap-1.5 rounded-full border px-2.5 text-xs font-medium";
const GOOD = `${BADGE} border-ok/45 bg-ok/12 text-ok-ink`;
const BAD = `${BADGE} border-crit/45 bg-crit/12 text-crit-ink`;

function ReachBadge({ checks, up, down }: { checks: Check[]; up: string; down: string }) {
  if (checks.length === 0) {
    return null;
  }
  const reachable = checks.every((check) => check.reachable);
  return (
    <span className={reachable ? GOOD : BAD}>
      <span aria-hidden="true" className={`size-1.5 rounded-full ${reachable ? "bg-ok" : "bg-crit"}`} />
      {reachable ? up : down}
    </span>
  );
}

function HealthBadges() {
  const health = useAdminHealth(true);
  if (!health.data) {
    return null;
  }
  return <ReachBadge checks={health.data.github} up={t("header.githubReachable")} down={t("header.githubUnreachable")} />;
}

export function Topbar({ onMenu }: { onMenu: () => void }) {
  const me = useMe();
  const isAdmin = me.data?.role === "admin";
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const signOut = useMutation({
    mutationFn: () => api<void>("POST", "/auth/logout"),
    onSettled: () => {
      queryClient.clear();
      void navigate("/login", { replace: true });
    },
  });

  return (
    <header className="sticky top-0 z-10 flex min-h-14 flex-wrap items-center justify-between gap-2.5 border-b border-border bg-bg/92 px-4 py-2.5 backdrop-blur md:px-8">
      <div className="flex flex-wrap items-center gap-2">
        <button
          type="button"
          onClick={onMenu}
          aria-label={t("header.openMenu")}
          className="flex size-9 items-center justify-center rounded-lg text-muted hover:text-text focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent md:hidden"
        >
          <Menu aria-hidden="true" size={20} />
        </button>
        {isAdmin ? (
          <output aria-label={t("header.environmentStatus")} className="flex flex-wrap items-center gap-2">
            <HealthBadges />
          </output>
        ) : null}
      </div>
      <div className="flex items-center gap-3.5">
        <span className="font-mono text-xs text-muted">{t("header.version", { version: APP_VERSION })}</span>
        <Button variant="small" onClick={() => signOut.mutate()} disabled={signOut.isPending}>
          {t("header.signOut")}
        </Button>
      </div>
    </header>
  );
}
