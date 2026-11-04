import { Outlet } from "react-router";
import { t } from "../../i18n";
import { AccountTabs } from "./AccountTabs";
import { PageTitle } from "../ui/PageTitle";

// The Account heading, intro and tabs above every account page.
export function AccountLayout() {
  return (
    <div className="flex flex-col gap-5">
      <div className="flex flex-col gap-1">
        <PageTitle title={t("page.account")} />
        <p className="text-muted">{t("account.intro")}</p>
      </div>
      <AccountTabs />
      <Outlet />
    </div>
  );
}
