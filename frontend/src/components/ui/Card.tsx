import type { HTMLAttributes } from "react";

export function Card({ className, ...rest }: HTMLAttributes<HTMLDivElement>) {
  const extra = className === undefined ? "" : ` ${className}`;
  return <div className={`rounded-[10px] border border-border bg-surface${extra}`} {...rest} />;
}
