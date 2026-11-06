import { useId, useState, type FocusEvent, type KeyboardEvent, type ReactNode } from "react";
import { INPUT } from "../mappings/styles";

export interface ComboOption {
  key: string;
  // What the option shows.
  content: ReactNode;
  // Called when the option is chosen.
  onSelect: () => void;
  // A control beside the option (for example Hide). Not part of the option itself.
  action?: ReactNode;
}

interface ComboboxProps {
  id: string;
  value: string;
  // Typing changes the value: typed entry always works, and the caller also
  // uses the text as the search.
  onChange: (text: string) => void;
  // Accessible name of the list of options.
  listLabel: string;
  options: ComboOption[];
  // False keeps the control a plain text input (no list).
  listEnabled?: boolean;
  // True disables the input and its list until it is enabled again.
  disabled?: boolean;
  placeholder?: string;
  invalid?: boolean;
  describedBy?: string;
  // Status and footer inside the popup: errors, the empty note, the pager.
  children?: ReactNode;
}

// A text input with a popup list of options that the caller filters from the
// text (WAI-ARIA combobox, list autocomplete). Arrow keys move, Enter chooses,
// Escape closes. The input keeps focus while the list is used.
export function Combobox({
  id,
  value,
  onChange,
  listLabel,
  options,
  listEnabled = true,
  disabled = false,
  placeholder,
  invalid = false,
  describedBy,
  children,
}: ComboboxProps) {
  const listId = useId();
  const [open, setOpen] = useState(false);
  const [active, setActive] = useState(-1);
  const shown = listEnabled && !disabled && open;
  const activeIndex = active < options.length ? active : -1;

  function choose(index: number) {
    const option = options[index];
    if (option !== undefined) {
      option.onSelect();
      setOpen(false);
      setActive(-1);
    }
  }

  function onKeyDown(event: KeyboardEvent<HTMLInputElement>) {
    if (!listEnabled) {
      return;
    }
    if (event.key === "ArrowDown") {
      event.preventDefault();
      setOpen(true);
      setActive(options.length === 0 ? -1 : (activeIndex + 1) % options.length);
    } else if (event.key === "ArrowUp") {
      event.preventDefault();
      setOpen(true);
      setActive(options.length === 0 ? -1 : (activeIndex <= 0 ? options.length : activeIndex) - 1);
    } else if (event.key === "Enter" && shown && activeIndex >= 0) {
      event.preventDefault();
      choose(activeIndex);
    } else if (event.key === "Escape" && shown) {
      event.preventDefault();
      setOpen(false);
    }
  }

  function onBlur(event: FocusEvent<HTMLDivElement>) {
    if (!event.currentTarget.contains(event.relatedTarget)) {
      setOpen(false);
    }
  }

  return (
    <div className="relative" onBlur={onBlur}>
      <input
        id={id}
        role="combobox"
        aria-expanded={shown}
        aria-controls={listId}
        aria-autocomplete="list"
        aria-activedescendant={shown && activeIndex >= 0 ? `${listId}-${activeIndex}` : undefined}
        aria-invalid={invalid}
        aria-describedby={describedBy}
        autoComplete="off"
        disabled={disabled}
        placeholder={placeholder}
        value={value}
        onChange={(event) => {
          setOpen(true);
          setActive(-1);
          onChange(event.target.value);
        }}
        onFocus={() => setOpen(true)}
        onClick={() => setOpen(true)}
        onKeyDown={onKeyDown}
        className={`${INPUT} ${invalid ? "border-crit!" : ""}`}
      />
      {/* oxlint-disable-next-line jsx-a11y/no-static-element-interactions -- keeps focus in the input; the options are keyboard-driven from it */}
      <div
        hidden={!shown}
        // Keep focus in the input when the popup is pressed.
        onMouseDown={(event) => {
          if (!(event.target instanceof Element) || event.target.closest("select") === null) {
            event.preventDefault();
          }
        }}
        className="absolute inset-x-0 top-full z-20 mt-1 flex max-h-80 flex-col gap-2 overflow-auto rounded-lg border border-border bg-surface p-2 shadow-lg"
      >
        {/* oxlint-disable-next-line jsx-a11y/no-noninteractive-element-to-interactive-role, jsx-a11y/prefer-tag-over-role -- the ARIA combobox popup; a native select cannot hold the search and pager */}
        <ul id={listId} role="listbox" aria-label={listLabel} className="m-0 grid list-none gap-0.5 p-0 font-mono text-[13px]">
          {options.map((option, index) => (
            <li key={option.key} role="presentation" className="flex items-center gap-1.5">
                            <div
                id={`${listId}-${index}`}
                // oxlint-disable-next-line jsx-a11y/prefer-tag-over-role -- option of the ARIA listbox above
                role="option"
                aria-selected={index === activeIndex}
                tabIndex={-1}
                onClick={() => choose(index)}
                onKeyDown={() => undefined}
                className={`min-w-0 flex-1 cursor-pointer truncate rounded-md px-2.5 py-1.5 hover:bg-surface-2 ${index === activeIndex ? "bg-surface-2" : ""}`}
              >
                {option.content}
              </div>
              {option.action}
            </li>
          ))}
        </ul>
        {children}
      </div>
    </div>
  );
}
