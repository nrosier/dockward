import type { ReactNode } from "react";
import { t } from "../../i18n";
import { Button } from "../ui/Button";
import { INPUT } from "../mappings/styles";

export const PANEL = "flex min-w-0 flex-col rounded-[10px] border border-border bg-surface p-4";

export const PAGE_SIZES = [10, 25, 50, 100];

export function Note({ children }: { children: ReactNode }) {
  return <p className="rounded-lg border border-accent/40 bg-accent/10 px-3 py-2 text-[12.5px] text-text">{children}</p>;
}

interface SearchBoxProps {
  id: string;
  label: string;
  value: string;
  onChange: (value: string) => void;
}

// A labelled search input. The label is visually hidden; the placeholder is a hint.
export function SearchBox({ id, label, value, onChange }: SearchBoxProps) {
  return (
    <div className="flex flex-col gap-1">
      <label htmlFor={id} className="sr-only">
        {label}
      </label>
      <input
        id={id}
        type="search"
        value={value}
        placeholder={t("mapping.picker.searchPlaceholder")}
        maxLength={100}
        onChange={(event) => onChange(event.target.value)}
        className={INPUT}
      />
    </div>
  );
}

interface PagerProps {
  idPrefix: string;
  page: number;
  pageSize: number;
  total: number;
  onPage: (page: number) => void;
  onPageSize?: (size: number) => void;
}

// Previous / Next with the range, and the page size when the caller can change it.
export function Pager({ idPrefix, page, pageSize, total, onPage, onPageSize }: PagerProps) {
  const last = Math.max(1, Math.ceil(total / pageSize));
  const from = total === 0 ? 0 : (page - 1) * pageSize + 1;
  const to = Math.min(total, page * pageSize);
  return (
    <nav aria-label={t("pagination.label")} className="flex flex-wrap items-center justify-between gap-2">
      <span className="text-[12.5px] text-muted">{t("pagination.range", { from, to, total })}</span>
      <div className="flex items-center gap-2">
        {onPageSize === undefined ? null : (
          <>
            <label htmlFor={`${idPrefix}-size`} className="text-[12.5px] text-muted">
              {t("mapping.picker.pageSize")}
            </label>
            <select
              id={`${idPrefix}-size`}
              value={pageSize}
              onChange={(event) => onPageSize(Number(event.target.value))}
              className={`${INPUT} min-h-[30px] w-auto`}
            >
              {PAGE_SIZES.map((size) => (
                <option key={size} value={size}>
                  {size}
                </option>
              ))}
            </select>
          </>
        )}
        <Button variant="small" disabled={page <= 1} onClick={() => onPage(page - 1)}>
          {t("pagination.previous")}
        </Button>
        <Button variant="small" disabled={page >= last} onClick={() => onPage(page + 1)}>
          {t("pagination.next")}
        </Button>
      </div>
    </nav>
  );
}
