import { t } from "../i18n";
import { PageTitle } from "../components/ui/PageTitle";

// Placeholder, outside the shell: the page itself is built in a later issue.
export default function LoginPage() {
  return (
    <main className="flex min-h-screen items-center justify-center bg-bg p-6 text-text">
      <PageTitle title={t("page.login")} />
    </main>
  );
}
