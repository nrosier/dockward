import { ChevronDown } from "lucide-react";
import { useId, useState } from "react";
import { t } from "../../i18n";

export interface ComboOption {
  value: string;
  label: string;
}

interface ComboboxProps {
  id: string;
  label: string;
  value: string;
  options: ComboOption[];
  // The first option: it clears the choice.
  allLabel: string;
  onChange: (value: string) => void;
  // Also offers the typed text as a choice (the Tag filter with no mapping chosen).
  allowCustom?: boolean;
  // Shows `allLabel` as the value, not as a placeholder (the Mapping filter).
  allAsValue?: boolean;
}

const LABEL = "mb-1 block text-[11px] font-semibold tracking-[0.06em] text-muted uppercase";

// A searchable single-choice combobox (ARIA 1.2 list autocomplete). Down opens the list
// and moves, Up moves back, Enter picks, Escape closes. The text box filters the options.
export function Combobox({ id, label, value, options, allLabel, onChange, allowCustom = false, allAsValue = false }: ComboboxProps) {
  const listId = useId();
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [active, setActive] = useState(0);

  const needle = query.trim().toLowerCase();
  const shown: ComboOption[] = [];
  if (needle === "") {
    shown.push({ value: "", label: allLabel });
  }
  for (const option of options) {
    if (needle === "" || option.label.toLowerCase().includes(needle)) {
      shown.push(option);
    }
  }
  const typed = query.trim();
  if (allowCustom && typed !== "" && !options.some((option) => option.value === typed)) {
    shown.push({ value: typed, label: t("cves.combo.useValue", { value: typed }) });
  }

  const selected = options.find((option) => option.value === value);
  const display = open ? query : (selected?.label ?? (value !== "" ? value : allAsValue ? allLabel : ""));

  function openList() {
    if (!open) {
      setOpen(true);
      setQuery("");
      setActive(0);
    }
  }
  function close() {
    setOpen(false);
    setQuery("");
  }
  function choose(next: string) {
    onChange(next);
    close();
  }

  return (
    <div className="relative">
      <label htmlFor={id} className={LABEL}>
        {label}
      </label>
      <div className="relative">
        <input
          id={id}
          type="text"
          role="combobox"
          aria-expanded={open}
          aria-controls={listId}
          aria-autocomplete="list"
          aria-activedescendant={open && shown.length > 0 ? `${listId}-${active}` : undefined}
          autoComplete="off"
          value={display}
          placeholder={allLabel}
          onFocus={openList}
          onClick={openList}
          onBlur={close}
          onChange={(event) => {
            setOpen(true);
            setQuery(event.target.value);
            setActive(0);
          }}
          onKeyDown={(event) => {
            if (event.key === "ArrowDown") {
              event.preventDefault();
              if (open) {
                setActive((index) => Math.min(index + 1, shown.length - 1));
              } else {
                openList();
              }
            } else if (event.key === "ArrowUp") {
              event.preventDefault();
              setActive((index) => Math.max(index - 1, 0));
            } else if (event.key === "Enter" && open && shown[active] !== undefined) {
              event.preventDefault();
              choose(shown[active].value);
            } else if (event.key === "Escape" && open) {
              event.preventDefault();
              close();
            }
          }}
          className="min-h-9 w-full rounded-lg border border-muted bg-bg pr-8 pl-3 text-[13px] text-text placeholder:text-muted focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent"
        />
        <ChevronDown aria-hidden="true" size={16} className="pointer-events-none absolute top-1/2 right-2.5 -translate-y-1/2 text-muted" />
      </div>
      {open ? (
        <ul
          id={listId}
          // oxlint-disable-next-line jsx-a11y/no-noninteractive-element-to-interactive-role, jsx-a11y/prefer-tag-over-role -- the ARIA combobox popup; a native select cannot hold the search
          role="listbox"
          aria-label={label}
          className="absolute z-30 mt-1 max-h-64 w-full overflow-y-auto rounded-lg border border-border bg-surface p-1"
        >
          {shown.length === 0 ? (
            <li role="presentation" className="px-2 py-1.5 text-[13px] text-muted">
              {t("cves.combo.noMatch")}
            </li>
          ) : (
            shown.map((option, index) => (
              <li
                key={`${option.value}-${index}`}
                id={`${listId}-${index}`}
                // oxlint-disable-next-line jsx-a11y/no-noninteractive-element-to-interactive-role, jsx-a11y/prefer-tag-over-role -- option of the ARIA listbox above
                role="option"
                aria-selected={option.value === value}
                // mousedown keeps the focus in the text box, so blur does not close the list first.
                onMouseDown={(event) => {
                  event.preventDefault();
                  choose(option.value);
                }}
                onMouseEnter={() => setActive(index)}
                className={`flex min-h-8 cursor-pointer items-center rounded-md px-2 text-[13px] ${
                  index === active ? "bg-surface-2" : ""
                } ${option.value === value ? "font-semibold" : ""}`}
              >
                {option.label}
              </li>
            ))
          )}
        </ul>
      ) : null}
    </div>
  );
}
