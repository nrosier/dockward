import { NavLink } from "react-router";
import { t, type MessageKey } from "../../i18n";

const TABS: { to: string; label: MessageKey }[] = [
  { to: "/account/profile", label: "account.tabs.profile" },
  { to: "/account/appearance", label: "account.tabs.appearance" },
  { to: "/account/credentials", label: "account.tabs.credentials" },
  { to: "/account/hidden", label: "account.tabs.hidden" },
];

// The Account tabs. Each tab is its own route, so it can be bookmarked and back works.
export function AccountTabs() {
  return (
    <nav aria-label={t("account.tabs.label")} className="flex flex-wrap gap-1 border-b border-border">
      {TABS.map((tab) => (
        <NavLink
          key={tab.to}
          to={tab.to}
          className={({ isActive }) =>
            `-mb-px inline-flex min-h-11 items-center border-b-2 px-3.5 text-sm font-medium focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent ${
              isActive ? "border-accent text-text" : "border-transparent text-muted hover:text-text"
            }`
          }
        >
          {t(tab.label)}
        </NavLink>
      ))}
    </nav>
  );
}
