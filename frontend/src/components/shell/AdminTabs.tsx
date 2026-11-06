import { useQuery } from "@tanstack/react-query";
import { NavLink, useLocation } from "react-router";
import { t, type MessageKey } from "../../i18n";
import { api } from "../../lib/api";

interface Tab {
  to: string;
  label: MessageKey;
}

const TABS: Tab[] = [
  { to: "/admin/jobs", label: "admin.tabs.jobs" },
  { to: "/admin/failed", label: "admin.tabs.failed" },
  { to: "/admin/audit", label: "admin.tabs.audit" },
  { to: "/admin/health", label: "admin.tabs.health" },
  { to: "/admin/settings/oidc", label: "admin.tabs.settings" },
  { to: "/admin/log", label: "admin.tabs.log" },
];

const SETTINGS: Tab[] = [
  { to: "/admin/settings/oidc", label: "admin.settings.oidc" },
  { to: "/admin/settings/users", label: "admin.settings.users" },
  { to: "/admin/settings/alerts", label: "admin.settings.alerts" },
  { to: "/admin/settings/github", label: "admin.settings.github" },
  { to: "/admin/settings/backup", label: "admin.settings.backup" },
];

function useFailedCount() {
  return useQuery({
    queryKey: ["sync-jobs", "failed-count"],
    queryFn: () => api<{ total: number }>("GET", "/sync-jobs?status=failed&scope=all&page_size=1"),
    select: (data) => data.total,
  });
}

export function AdminTabs() {
  const location = useLocation();
  const inSettings = location.pathname.startsWith("/admin/settings");
  const failed = useFailedCount();
  const failedTotal = failed.data ?? 0;

  return (
    <div className="flex flex-col gap-3.5">
      <nav aria-label={t("admin.tabs.label")} className="flex flex-wrap gap-1 border-b border-border">
        {TABS.map((tab) => {
          const isSettings = tab.label === "admin.tabs.settings";
          const active = isSettings ? inSettings : location.pathname === tab.to;
          return (
            <NavLink
              key={tab.to}
              to={tab.to}
              aria-current={active ? "page" : undefined}
              className={`-mb-px inline-flex min-h-11 items-center gap-2 border-b-2 px-3.5 text-sm font-medium focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent ${
                active ? "border-accent text-text" : "border-transparent text-muted hover:text-text"
              }`}
            >
              {t(tab.label)}
              {tab.label === "admin.tabs.failed" && failedTotal > 0 ? (
                <>
                  <span
                    aria-hidden="true"
                    className="inline-flex h-5 min-w-5 items-center justify-center rounded-full bg-crit/16 px-1.5 text-[11.5px] font-semibold text-crit-ink"
                  >
                    {failedTotal}
                  </span>
                  <span className="sr-only">{t("admin.tabs.failedCount", { count: failedTotal })}</span>
                </>
              ) : null}
            </NavLink>
          );
        })}
      </nav>
      {inSettings ? (
        <nav aria-label={t("admin.settings.label")} className="flex flex-wrap gap-1.5">
          {SETTINGS.map((link) => (
            <NavLink
              key={link.to}
              to={link.to}
              className={({ isActive }) =>
                `inline-flex min-h-8 items-center rounded-full border px-3 text-[13px] font-medium focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent ${
                  isActive ? "border-accent bg-accent/14 text-text" : "border-border text-muted hover:text-text"
                }`
              }
            >
              {t(link.label)}
            </NavLink>
          ))}
        </nav>
      ) : null}
    </div>
  );
}
