import { Anchor, Boxes, LayoutDashboard, PanelLeftClose, PanelLeftOpen, RefreshCw, ShieldAlert, ShieldCheck, User } from "lucide-react";
import type { ComponentType } from "react";
import { NavLink } from "react-router";
import { t, type MessageKey } from "../../i18n";
import { useMe } from "../../lib/session";

interface Item {
  to: string;
  label: MessageKey;
  icon: ComponentType<{ "aria-hidden": "true"; size: number }>;
  end?: boolean;
}

const TOP: Item[] = [
  { to: "/", label: "nav.dashboard", icon: LayoutDashboard, end: true },
  { to: "/sources", label: "nav.sources", icon: Boxes },
  { to: "/cves", label: "nav.cves", icon: ShieldAlert },
  { to: "/sync-jobs", label: "nav.syncJobs", icon: RefreshCw },
];

const ADMIN: Item = { to: "/admin", label: "nav.admin", icon: ShieldCheck };
const ACCOUNT: Item = { to: "/account", label: "nav.account", icon: User };

interface RailProps {
  collapsed: boolean;
  onToggle: () => void;
  // Called after a link is followed, so the narrow-screen drawer can close.
  onNavigate?: () => void;
  // The drawer always shows labels, and has no collapse button.
  inDrawer?: boolean;
}

function RailLink({ item, collapsed, onNavigate }: { item: Item; collapsed: boolean; onNavigate?: () => void }) {
  const Icon = item.icon;
  const label = t(item.label);
  return (
    <NavLink
      to={item.to}
      end={item.end}
      title={collapsed ? label : undefined}
      onClick={onNavigate}
      className={({ isActive }) =>
        `flex min-h-10 items-center gap-3 rounded-lg px-3 text-sm font-medium focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent ${
          isActive ? "bg-surface-2 text-text" : "text-muted hover:text-text"
        }`
      }
    >
      <Icon aria-hidden="true" size={18} />
      <span className={collapsed ? "sr-only" : ""}>{label}</span>
    </NavLink>
  );
}

export function Rail({ collapsed, onToggle, onNavigate, inDrawer = false }: RailProps) {
  const me = useMe();
  const user = me.data;
  const isCollapsed = collapsed && !inDrawer;
  return (
    <nav aria-label={t("rail.label")} className="flex h-full flex-col gap-1 px-3 pt-4 pb-5">
      <div className="flex items-center justify-between px-1.5 pb-[18px]">
        <NavLink to="/" onClick={onNavigate} className="flex items-center gap-2.5 text-text">
          <span className="flex size-[30px] items-center justify-center rounded-lg bg-accent text-on-accent">
            <Anchor aria-hidden="true" size={18} />
          </span>
          <span className={isCollapsed ? "sr-only" : "text-[15px] font-bold tracking-tight"}>{t("app.name")}</span>
        </NavLink>
        {inDrawer ? null : (
          <button
            type="button"
            onClick={onToggle}
            aria-label={isCollapsed ? t("rail.expand") : t("rail.collapse")}
            aria-expanded={!isCollapsed}
            className="flex size-8 items-center justify-center rounded-lg text-muted hover:text-text focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent"
          >
            {isCollapsed ? <PanelLeftOpen aria-hidden="true" size={18} /> : <PanelLeftClose aria-hidden="true" size={18} />}
          </button>
        )}
      </div>

      {TOP.map((item) => (
        <RailLink key={item.to} item={item} collapsed={isCollapsed} onNavigate={onNavigate} />
      ))}

      <div className="mx-1.5 my-5 h-px bg-border" />

      {user?.role === "admin" ? <RailLink item={ADMIN} collapsed={isCollapsed} onNavigate={onNavigate} /> : null}
      <RailLink item={ACCOUNT} collapsed={isCollapsed} onNavigate={onNavigate} />

      {user === undefined || user === null || isCollapsed ? null : (
        <div className="mt-5 flex flex-col gap-0.5 rounded-lg border border-border p-3 text-xs text-muted">
          <span>
            {t("rail.signedInAs")} <span className="font-semibold text-text">{user.username}</span>
          </span>
          <span>
            {t("rail.accountLine", {
              role: user.role === "admin" ? t("role.admin") : t("role.user"),
              provider: user.auth_provider === "oidc" ? t("rail.providerOidc") : t("rail.providerLocal"),
            })}
          </span>
        </div>
      )}
    </nav>
  );
}
