import type { ReactNode } from "react";
import { t } from "../../i18n";
import { ApiError } from "../../lib/api";
import { Button } from "../ui/Button";
import { Dialog } from "../ui/Dialog";

// Form controls use the muted token for their border (approved for #37).
export const INPUT = "min-h-9 w-full rounded-lg border border-muted bg-bg px-3 text-[13px] text-text";
export const TH = "px-4 py-2.5 text-left text-xs font-semibold text-muted";
export const TD = "px-4 py-3 align-top text-[13px]";
export const ROW = "border-t border-border";

export function messageOf(error: unknown): string {
  return error instanceof ApiError && error.message !== "" ? error.message : t("errors.generic");
}

export function statusOf(error: unknown): number {
  return error instanceof ApiError ? error.status : 0;
}

export function formatDate(iso: string | null): string {
  return iso === null ? "" : iso.slice(0, 10);
}

export function formatDateTime(value: string | number | null): string {
  if (value === null) {
    return "";
  }
  const date = new Date(typeof value === "number" ? value * 1000 : value);
  if (Number.isNaN(date.getTime())) {
    return "";
  }
  return date.toISOString().slice(0, 16).replace("T", " ");
}

export function daysLeft(expiresAt: string | null, now = Date.now()): number | null {
  if (expiresAt === null) {
    return null;
  }
  const end = new Date(expiresAt).getTime();
  return Number.isNaN(end) ? null : Math.ceil((end - now) / 86_400_000);
}

export type Tone = "ok" | "crit" | "warn" | "neutral";

const TONE: Record<Tone, string> = {
  ok: "text-ok-ink bg-ok/12 border-ok/45",
  crit: "text-crit-ink bg-crit/12 border-crit/45",
  warn: "text-high-ink bg-high/12 border-high/45",
  neutral: "text-text bg-text/5 border-border",
};

// A pill with its own text. Colour is never the only signal.
export function Badge({ tone, children }: { tone: Tone; children: ReactNode }) {
  return (
    <span
      className={`inline-flex h-[22px] items-center gap-1.5 rounded-full border px-[9px] text-[11px] leading-none font-semibold tracking-[0.05em] whitespace-nowrap uppercase ${TONE[tone]}`}
    >
      <span aria-hidden="true" className="size-1.5 rounded-full bg-current" />
      {children}
    </span>
  );
}

export function Tag({ children }: { children: ReactNode }) {
  return (
    <span className="inline-flex rounded-md border border-border bg-surface-2 px-2 py-0.5 font-mono text-xs">
      {children}
    </span>
  );
}

interface SegmentedProps {
  labelId: string;
  value: string;
  onChange: (value: string) => void;
  options: { value: string; label: string }[];
  disabled?: boolean;
}

export function Segmented({ labelId, value, onChange, options, disabled }: SegmentedProps) {
  return (
    <fieldset
      aria-labelledby={labelId}
      className="m-0 inline-flex min-w-0 self-start overflow-hidden rounded-lg border border-muted p-0"
    >
      {options.map((option) => (
        <button
          key={option.value}
          type="button"
          disabled={disabled}
          aria-pressed={value === option.value}
          onClick={() => onChange(option.value)}
          className={`min-h-9 cursor-pointer px-4 text-[13px] font-medium disabled:cursor-not-allowed disabled:opacity-50 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent ${
            value === option.value ? "bg-surface-2 text-text" : "bg-transparent text-muted"
          }`}
        >
          {option.label}
        </button>
      ))}
    </fieldset>
  );
}

interface ConfirmProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: string;
  description: string;
  confirmLabel: string;
  busy?: boolean;
  error?: string | null;
  onConfirm: () => void;
}

export function ConfirmDialog({
  open,
  onOpenChange,
  title,
  description,
  confirmLabel,
  busy,
  error,
  onConfirm,
}: ConfirmProps) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange} title={title} description={description}>
      {error ? (
        <p role="alert" className="text-[13px] text-crit-ink">
          {error}
        </p>
      ) : null}
      <div className="flex justify-end gap-2.5">
        <Button onClick={() => onOpenChange(false)}>{t("common.cancel")}</Button>
        <Button variant="danger" disabled={busy} onClick={onConfirm}>
          {confirmLabel}
        </Button>
      </div>
    </Dialog>
  );
}

export function CardHeading({
  id,
  title,
  help,
  action,
}: {
  id: string;
  title: string;
  help?: string;
  action?: ReactNode;
}) {
  return (
    <div className="flex flex-wrap items-start justify-between gap-3">
      <div className="flex flex-col gap-1">
        <h2 id={id} className="text-[15px] font-semibold">
          {title}
        </h2>
        {help === undefined ? null : <p className="text-[12.5px] text-muted">{help}</p>}
      </div>
      {action}
    </div>
  );
}

export function FormError({ message }: { message: string | null }) {
  return message === null ? null : (
    <p role="alert" className="text-[13px] text-crit-ink">
      {message}
    </p>
  );
}
