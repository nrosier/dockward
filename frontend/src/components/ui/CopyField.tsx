import { Check, Copy } from "lucide-react";
import { t } from "../../i18n";
import { Button } from "./Button";
import { useCopy } from "./useCopy";

// A read-only value with a Copy button. Used for the shown-once webhook URL and
// auth secret, so the value is held only by the caller's component state.
export function CopyField({ id, value, label }: { id: string; value: string; label: string }) {
  const { copied, copy } = useCopy();
  return (
    <div className="flex items-center gap-2">
      <input
        id={id}
        aria-label={label}
        readOnly
        value={value}
        className="min-h-9 min-w-0 flex-1 rounded-lg border border-border bg-bg px-3 font-mono text-[12.5px] text-text"
      />
      <Button onClick={() => void copy(value)}>
        {copied ? <Check aria-hidden="true" size={14} /> : <Copy aria-hidden="true" size={14} />}
        {copied ? t("common.copied") : t("common.copy")}
      </Button>
    </div>
  );
}
