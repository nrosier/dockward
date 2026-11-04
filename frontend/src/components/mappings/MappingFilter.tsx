import { t } from "../../i18n";
import type { MappingListItem } from "../../types/api";
import { mappingName } from "./useMappings";
import { INPUT } from "./styles";

interface MappingFilterProps {
  id: string;
  value: string;
  mappings: MappingListItem[];
  onChange: (value: string) => void;
}

// A labelled native select of mappings. The first option clears the filter.
export function MappingFilter({ id, value, mappings, onChange }: MappingFilterProps) {
  return (
    <>
      <label htmlFor={id} className="sr-only">
        {t("mappings.filter.label")}
      </label>
      <select id={id} value={value} onChange={(event) => onChange(event.target.value)} className={`${INPUT} w-auto!`}>
        <option value="">{t("mappings.filter.all")}</option>
        {mappings.map((mapping) => (
          <option key={mapping.id} value={mapping.id}>
            {mappingName(mapping)}
          </option>
        ))}
      </select>
    </>
  );
}
