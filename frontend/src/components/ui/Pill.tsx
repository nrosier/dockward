import { t, type MessageKey } from "../../i18n";

export type PillKind =
  | "critical"
  | "high"
  | "medium"
  | "low"
  | "open"
  | "accepted"
  | "fixed"
  | "done"
  | "failed"
  | "running"
  | "queued"
  | "unknown";

// Colour is never the only signal: every pill carries a text label.
const LABEL: Record<PillKind, MessageKey> = {
  critical: "pill.critical",
  high: "pill.high",
  medium: "pill.medium",
  low: "pill.low",
  open: "pill.open",
  accepted: "pill.accepted",
  fixed: "pill.fixed",
  done: "pill.done",
  failed: "pill.failed",
  running: "pill.running",
  queued: "pill.queued",
  unknown: "pill.unknown",
};

const TONE: Record<PillKind, string> = {
  critical: "text-crit-ink bg-crit/12 border-crit/45",
  high: "text-high-ink bg-high/12 border-high/45",
  medium: "text-med-ink bg-med/10 border-med/40",
  low: "text-low-ink bg-low/12 border-low/45",
  open: "text-text bg-text/5 border-border",
  accepted: "text-accent bg-accent/15 border-accent/45",
  fixed: "text-ok-ink bg-ok/12 border-ok/45",
  done: "text-ok-ink bg-ok/12 border-ok/45",
  failed: "text-crit-ink bg-crit/12 border-crit/45",
  running: "text-low-ink bg-low/12 border-low/45",
  queued: "text-text bg-text/5 border-border",
  unknown: "text-text bg-text/5 border-border",
};

export function Pill({ kind }: { kind: PillKind }) {
  return (
    <span
      className={`inline-flex h-[22px] items-center gap-1.5 rounded-full border px-[9px] text-[11px] leading-none font-semibold tracking-[0.05em] whitespace-nowrap uppercase ${TONE[kind]}`}
    >
      <span aria-hidden="true" className="size-1.5 rounded-full bg-current" />
      {t(LABEL[kind])}
    </span>
  );
}
