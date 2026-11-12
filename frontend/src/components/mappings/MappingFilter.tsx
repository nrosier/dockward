import { t } from "../../i18n";
import type { Source } from "../../types/sources";
import { INPUT } from "./styles";

interface MappingFilterProps {
  id: string;
  value: string;
  sources: Source[];
  onChange: (value: string) => void;
}

// A labelled native select of sources, by display name (#323). The first option clears the filter.
export function MappingFilter({ id, value, sources, onChange }: MappingFilterProps) {
  return (
    <>
      <label htmlFor={id} className="sr-only">
        {t("mappings.filter.label")}
      </label>
      <select id={id} value={value} onChange={(event) => onChange(event.target.value)} className={`${INPUT} w-auto!`}>
        <option value="">{t("mappings.filter.all")}</option>
        {sources.map((source) => (
          <option key={source.id} value={source.id}>
            {source.name ?? source.repository}
          </option>
        ))}
      </select>
    </>
  );
}
