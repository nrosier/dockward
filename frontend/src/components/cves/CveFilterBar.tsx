import { X } from "lucide-react";
import { useEffect, useState } from "react";
import { t, type MessageKey } from "../../i18n";
import {
  SEVERITIES,
  STATUSES,
  toUrlParams,
  type CveFilterState,
  type SeverityValue,
  type StatusValue,
  type TextFilter,
} from "../../lib/cveFilters";
import { MappingFilter } from "../mappings/MappingFilter";
import { INPUT } from "../mappings/styles";
import { Button } from "../ui/Button";
import type { MappingListItem } from "../../types/api";
import { mappingName } from "../mappings/useMappings";

const DEBOUNCE_MS = 300;
const TOGGLE =
  "min-h-8 cursor-pointer px-3 text-[12.5px] font-medium focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent";
const LABEL = "mb-1.5 block text-xs text-muted";

// A text box that reports its value 300 ms after the last keystroke.
function DebouncedInput({
  id,
  label,
  placeholder,
  value,
  onCommit,
  type = "text",
}: {
  id: string;
  label: string;
  placeholder: string;
  value: string;
  onCommit: (value: string) => void;
  type?: "text" | "search";
}) {
  const [draft, setDraft] = useState(value);
  useEffect(() => {
    setDraft(value);
  }, [value]);
  useEffect(() => {
    if (draft === value) {
      return;
    }
    const timer = setTimeout(() => onCommit(draft), DEBOUNCE_MS);
    return () => clearTimeout(timer);
    // oxlint-disable-next-line react-hooks/exhaustive-deps -- onCommit is recreated each render and only reads current params
  }, [draft, value]);
  return (
    <div>
      <label htmlFor={id} className={LABEL}>
        {label}
      </label>
      <input
        id={id}
        type={type}
        value={draft}
        placeholder={placeholder}
        onChange={(event) => setDraft(event.target.value)}
        className={INPUT}
      />
    </div>
  );
}

// A multi-select: a group of toggle buttons. The last pressed one stays on.
function Toggles<T extends string>({
  label,
  options,
  selected,
  onChange,
}: {
  label: string;
  options: Array<{ value: T; label: string }>;
  selected: T[];
  onChange: (next: T[]) => void;
}) {
  return (
    <div>
      <p className={LABEL}>{label}</p>
      <fieldset aria-label={label} className="m-0 inline-flex min-w-0 flex-wrap overflow-hidden rounded-lg border border-muted p-0">
        {options.map((option) => {
          const on = selected.includes(option.value);
          return (
            <button
              key={option.value}
              type="button"
              aria-pressed={on}
              onClick={() => {
                const next = on ? selected.filter((value) => value !== option.value) : [...selected, option.value];
                if (next.length > 0) {
                  onChange(options.map((o) => o.value).filter((value) => next.includes(value)));
                }
              }}
              className={`${TOGGLE} ${on ? "bg-surface-2 text-text" : "bg-transparent text-muted"}`}
            >
              {option.label}
            </button>
          );
        })}
      </fieldset>
    </div>
  );
}

interface CveFilterBarProps {
  state: CveFilterState;
  q: string;
  mappings: MappingListItem[];
  // Sets or clears (value "") the URL parameters named in the patch.
  onChange: (patch: Record<string, string>) => void;
  onClearAll: () => void;
}

const TEXT_FIELDS: Array<{ name: TextFilter; label: MessageKey; placeholder: MessageKey }> = [
  { name: "package", label: "cves.filter.package", placeholder: "cves.filter.packagePlaceholder" },
  { name: "tag", label: "cves.filter.tag", placeholder: "cves.filter.tagPlaceholder" },
  { name: "harbor_project", label: "cves.filter.project", placeholder: "cves.filter.projectPlaceholder" },
  { name: "harbor_repository", label: "cves.filter.repository", placeholder: "cves.filter.repositoryPlaceholder" },
];

export function CveFilterBar({ state, q, mappings, onChange, onClearAll }: CveFilterBarProps) {
  const urlValues = toUrlParams(state);
  const chips: Array<{ key: string; text: string; clear: string[] }> = [];
  if (q !== "") {
    chips.push({ key: "q", text: t("cves.filter.chip.q", { value: q }), clear: ["q"] });
  }
  if ("severity" in urlValues) {
    chips.push({ key: "severity", text: t("cves.filter.chip.severity", { value: state.severities.join(", ") }), clear: ["severity"] });
  }
  if ("status" in urlValues) {
    const value = state.statuses.map((status) => t(`cves.status.${status}`)).join(", ");
    chips.push({ key: "status", text: t("cves.filter.chip.status", { value }), clear: ["status"] });
  }
  for (const field of TEXT_FIELDS) {
    if (state.text[field.name] !== "") {
      chips.push({
        key: field.name,
        text: t(`cves.filter.chip.${field.name}`, { value: state.text[field.name] }),
        clear: [field.name],
      });
    }
  }
  if (state.mappingId !== "") {
    const mapping = mappings.find((item) => item.id === state.mappingId);
    chips.push({
      key: "mapping_id",
      text: t("cves.filter.chip.mapping_id", { value: mapping === undefined ? state.mappingId : mappingName(mapping) }),
      clear: ["mapping_id"],
    });
  }

  return (
    <search aria-label={t("cves.filter.group")} className="flex flex-col gap-3 rounded-[10px] border border-border bg-surface p-5">
      <div className="grid grid-cols-[repeat(auto-fit,minmax(10rem,1fr))] gap-4">
        <Toggles<SeverityValue>
          label={t("cves.filter.severity")}
          options={SEVERITIES.map((value) => ({ value, label: value }))}
          selected={state.severities}
          onChange={(next) => onChange({ severity: next.length === SEVERITIES.length ? "" : next.join(",") })}
        />
        <Toggles<StatusValue>
          label={t("cves.filter.status")}
          options={STATUSES.map((value) => ({ value, label: t(`cves.status.${value}`) }))}
          selected={state.statuses}
          onChange={(next) => onChange({ status: next.join(",") === "open" ? "" : next.join(",") })}
        />
        <DebouncedInput
          id="cve-q"
          type="search"
          label={t("cves.filter.search")}
          placeholder={t("cves.filter.searchPlaceholder")}
          value={q}
          onCommit={(value) => onChange({ q: value })}
        />
        {TEXT_FIELDS.map((field) => (
          <DebouncedInput
            key={field.name}
            id={`cve-${field.name}`}
            label={t(field.label)}
            placeholder={t(field.placeholder)}
            value={state.text[field.name]}
            onCommit={(value) => onChange({ [field.name]: value })}
          />
        ))}
        <div>
          <MappingFilterLabeled value={state.mappingId} mappings={mappings} onChange={(value) => onChange({ mapping_id: value })} />
        </div>
      </div>
      {chips.length === 0 ? null : (
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-xs text-muted">{t("cves.filter.active", { n: chips.length })}</span>
          {chips.map((chip) => (
            <span
              key={chip.key}
              className="inline-flex min-h-7 items-center gap-1.5 rounded-full border border-border bg-text/5 pr-1 pl-3 text-[12.5px]"
            >
              {chip.text}
              <button
                type="button"
                aria-label={t("cves.filter.remove", { filter: chip.text })}
                onClick={() => onChange(Object.fromEntries(chip.clear.map((name) => [name, ""])))}
                className="inline-flex size-5 cursor-pointer items-center justify-center rounded-full text-muted hover:text-text focus-visible:outline-2 focus-visible:outline-accent"
              >
                <X aria-hidden="true" size={12} />
              </button>
            </span>
          ))}
          <Button variant="small" onClick={onClearAll}>
            {t("cves.filter.clearAll")}
          </Button>
        </div>
      )}
    </search>
  );
}

function MappingFilterLabeled(props: { value: string; mappings: MappingListItem[]; onChange: (value: string) => void }) {
  return (
    <>
      <p className={LABEL}>{t("mappings.filter.label")}</p>
      <MappingFilter id="cve-mapping" {...props} />
    </>
  );
}
