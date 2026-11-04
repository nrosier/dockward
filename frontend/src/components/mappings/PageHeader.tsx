import type { ReactNode } from "react";
import { PageTitle } from "../ui/PageTitle";

// Title and subtitle on the left, controls (scope toggle, primary action) on
// the right. Wraps on narrow screens.
export function PageHeader({ title, subtitle, children }: { title: string; subtitle: string; children?: ReactNode }) {
  return (
    <div className="flex flex-wrap items-end justify-between gap-4">
      <div className="flex flex-col gap-1">
        <PageTitle title={title} />
        <p className="text-muted">{subtitle}</p>
      </div>
      {children === undefined ? null : <div className="flex flex-wrap items-center gap-2.5">{children}</div>}
    </div>
  );
}
