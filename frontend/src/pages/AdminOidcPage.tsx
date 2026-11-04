import { t } from "../i18n";
import { PageTitle } from "../components/ui/PageTitle";

// Placeholder: the page itself is built in a later issue.
export default function AdminOidcPage() {
  return <PageTitle title={t("admin.settings.oidc")} level={2} />;
}
