import type { ReactNode } from "react";

// A horizontal scroll container for a table at phone width.
export function TableScroll({ label, children }: { label: string; children: ReactNode }) {
  return (
    <section aria-label={label} className="overflow-x-auto">
      {children}
    </section>
  );
}
