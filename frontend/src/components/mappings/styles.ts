// Form controls use the `muted` token for their border (approved for #37):
// the card border is about 1.4:1, and WCAG 1.4.11 asks 3:1 for a control.
export const INPUT =
  "min-h-9 w-full rounded-lg border border-muted bg-bg px-3 text-[13px] text-text disabled:cursor-not-allowed disabled:opacity-50";
export const INPUT_INVALID = "border-crit!";
export const TEXTAREA = "min-h-[104px] w-full rounded-lg border border-muted bg-bg px-3 py-2.5 text-[13px] leading-normal text-text";

export const TABLE = "w-full border-collapse text-left";
export const TH =
  "border-b border-border px-3.5 py-3 text-left text-[11px] leading-none font-semibold tracking-[0.06em] whitespace-nowrap text-muted uppercase";
export const TD = "border-b border-border/60 px-3.5 py-[11px] align-middle";
export const LINK = "text-accent underline-offset-2 hover:underline";
