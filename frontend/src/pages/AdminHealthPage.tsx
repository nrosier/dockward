import { t } from "../i18n";
import { PageTitle } from "../components/ui/PageTitle";

// Placeholder: the page itself is built in a later issue.
export default function AdminHealthPage() {
  return <PageTitle title={t("admin.tabs.health")} level={2} />;
}
