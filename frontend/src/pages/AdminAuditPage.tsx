import { t } from "../i18n";
import { PageTitle } from "../components/ui/PageTitle";

// Placeholder: the page itself is built in a later issue.
export default function AdminAuditPage() {
  return <PageTitle title={t("admin.tabs.audit")} level={2} />;
}
