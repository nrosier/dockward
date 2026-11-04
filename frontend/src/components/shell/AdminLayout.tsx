import { Outlet } from "react-router";
import { t } from "../../i18n";
import { AdminTabs } from "./AdminTabs";

// The Admin heading and tabs above every admin page.
export function AdminLayout() {
  return (
    <>
      <h1 className="text-2xl font-semibold tracking-tight">{t("nav.admin")}</h1>
      <AdminTabs />
      <Outlet />
    </>
  );
}
