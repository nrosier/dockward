import { Info } from "lucide-react";
import { useId, useState, type KeyboardEvent } from "react";

interface TooltipProps {
  // Accessible name of the trigger button.
  label: string;
  // The tooltip text. It stays in the DOM, so aria-describedby always resolves.
  text: string;
}

// An info button that shows `text` on hover and on keyboard focus. Escape
// dismisses it. Screen readers get the text through aria-describedby.
export function Tooltip({ label, text }: TooltipProps) {
  const id = useId();
  const [hovered, setHovered] = useState(false);
  const [focused, setFocused] = useState(false);
  const [dismissed, setDismissed] = useState(false);
  const shown = (hovered || focused) && !dismissed;

  function onKeyDown(event: KeyboardEvent) {
    if (event.key === "Escape" && shown) {
      event.stopPropagation();
      setDismissed(true);
    }
  }

  return (
    <span
      className="inline-flex"
      onMouseEnter={() => {
        setDismissed(false);
        setHovered(true);
      }}
      onMouseLeave={() => setHovered(false)}
    >
      <button
        type="button"
        aria-label={label}
        aria-describedby={id}
        onFocus={() => {
          setDismissed(false);
          setFocused(true);
        }}
        onBlur={() => setFocused(false)}
        onKeyDown={onKeyDown}
        className="inline-flex size-4 items-center justify-center rounded-full text-muted hover:text-text focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent"
      >
        <Info aria-hidden="true" size={14} />
      </button>
      <span
        id={id}
        role="tooltip"
        hidden={!shown}
        className="absolute top-full left-0 z-20 mt-1 max-w-72 rounded-lg border border-border bg-surface p-2.5 text-[12.5px] font-normal text-text shadow-lg"
      >
        {text}
      </span>
    </span>
  );
}
