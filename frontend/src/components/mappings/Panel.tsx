import type { HTMLAttributes } from "react";

// A labelled card as a <section>, so it is a landmark region. Same look as the
// shared Card.
export function Panel({ className, ...rest }: HTMLAttributes<HTMLElement>) {
  const extra = className === undefined ? "" : ` ${className}`;
  return <section className={`rounded-[10px] border border-border bg-surface${extra}`} {...rest} />;
}
