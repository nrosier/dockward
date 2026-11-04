export interface SegmentedOption {
  value: string;
  label: string;
}

interface SegmentedProps {
  label: string;
  options: SegmentedOption[];
  value: string;
  onChange: (value: string) => void;
  disabled?: boolean;
}

const BASE =
  "min-h-8 cursor-pointer px-3 text-[12.5px] font-medium focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent disabled:cursor-not-allowed disabled:opacity-50";

// A segmented control: a group of toggle buttons, one pressed.
export function Segmented({ label, options, value, onChange, disabled }: SegmentedProps) {
  return (
    <fieldset
      aria-label={label}
      className="m-0 inline-flex min-w-0 self-start overflow-hidden rounded-lg border border-muted p-0"
    >
      {options.map((option) => {
        const on = option.value === value;
        return (
          <button
            key={option.value}
            type="button"
            aria-pressed={on}
            disabled={disabled}
            onClick={() => onChange(option.value)}
            className={`${BASE} ${on ? "bg-surface-2 text-text" : "bg-transparent text-muted"}`}
          >
            {option.label}
          </button>
        );
      })}
    </fieldset>
  );
}
