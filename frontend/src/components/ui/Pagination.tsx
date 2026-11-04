import { useSearchParams } from "react-router";
import { t } from "../../i18n";
import { Button } from "./Button";

export function currentPage(params: URLSearchParams): number {
  const parsed = Number.parseInt(params.get("page") ?? "1", 10);
  return Number.isFinite(parsed) && parsed >= 1 ? parsed : 1;
}

interface PaginationProps {
  total: number;
  pageSize: number;
}

// "1–8 of 56" with Previous and Next. The page lives in the URL as `page`.
export function Pagination({ total, pageSize }: PaginationProps) {
  const [params, setParams] = useSearchParams();
  const page = currentPage(params);
  const lastPage = Math.max(1, Math.ceil(total / pageSize));
  const from = total === 0 ? 0 : (page - 1) * pageSize + 1;
  const to = Math.min(total, page * pageSize);
  const go = (next: number) => {
    const updated = new URLSearchParams(params);
    if (next <= 1) {
      updated.delete("page");
    } else {
      updated.set("page", String(next));
    }
    setParams(updated);
  };
  return (
    <nav aria-label={t("pagination.label")} className="flex items-center justify-between gap-3 px-4 py-3">
      <span className="text-[12.5px] text-muted">{t("pagination.range", { from, to, total })}</span>
      <div className="flex gap-2">
        <Button variant="small" disabled={page <= 1} onClick={() => go(page - 1)}>
          {t("pagination.previous")}
        </Button>
        <Button variant="small" disabled={page >= lastPage} onClick={() => go(page + 1)}>
          {t("pagination.next")}
        </Button>
      </div>
    </nav>
  );
}
