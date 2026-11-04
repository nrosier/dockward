import { Check, Copy } from "lucide-react";
import { t } from "../../i18n";
import { useCopy } from "./useCopy";

const SHORT_LENGTH = 8;

// The first 8 hex characters after `sha256:`. The full digest is what gets copied.
export function shortDigest(digest: string): string {
  const hex = digest.startsWith("sha256:") ? digest.slice("sha256:".length) : digest;
  return `sha256:${hex.slice(0, SHORT_LENGTH)}`;
}

export function ShaBadge({ digest }: { digest: string }) {
  const { copied, copy } = useCopy();
  return (
    <button
      type="button"
      title={t("sha.copyTitle")}
      onClick={() => void copy(digest)}
      className="inline-flex cursor-pointer items-center gap-1.5 rounded-md border border-border bg-surface-2 px-[7px] py-[3px] font-mono text-xs text-text focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent"
    >
      {shortDigest(digest)}
      {copied ? <Check aria-hidden="true" size={12} /> : <Copy aria-hidden="true" size={12} />}
      <output className="sr-only">{copied ? t("common.copied") : ""}</output>
    </button>
  );
}
