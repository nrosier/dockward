import { useParams } from "react-router";
import { t } from "../i18n";
import { PageTitle } from "../components/ui/PageTitle";

// Placeholder: the form is built in a later issue. With an `id` it edits.
export default function MappingFormPage() {
  const { id } = useParams();
  return <PageTitle title={id === undefined ? t("page.mappingNew") : t("page.mappingEdit")} />;
}
