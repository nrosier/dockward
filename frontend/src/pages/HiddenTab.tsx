import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { TABLE, TD, TH } from "../components/mappings/styles";
import { TableScroll } from "../components/mappings/TableScroll";
import { Note, Pager } from "../components/pickers/PickerControls";
import { PickerError } from "../components/pickers/PickerError";
import { formatDateTime } from "../components/syncjobs/dates";
import { Button } from "../components/ui/Button";
import { Card } from "../components/ui/Card";
import { Pill } from "../components/ui/Pill";
import { Segmented } from "../components/mappings/Segmented";
import { LoadingMessage } from "../components/ui/StatusMessage";
import { t } from "../i18n";
import { api } from "../lib/api";
import type { HiddenItem, Page } from "../types/api";

const PAGE_SIZE = 25;
const CAP = 1000;
type Filter = "all" | "harbor" | "github";

// Account > Hidden: what this user hid from the mapping pickers, per Harbor
// instance, newest first. Restore is immediate, with no confirmation (#126).
export default function HiddenTab() {
  const queryClient = useQueryClient();
  const [filter, setFilter] = useState<Filter>("all");
  const [page, setPage] = useState(1);
  const params = new URLSearchParams({ page: String(page), page_size: String(PAGE_SIZE), sort: "created_at", order: "desc" });
  if (filter !== "all") {
    params.set("source", filter);
  }
  const list = useQuery({
    queryKey: ["hidden", filter, page],
    queryFn: () => api<Page<HiddenItem>>("GET", `/pickers/hidden?${params.toString()}`),
    retry: false,
    refetchOnWindowFocus: false,
  });
  // The unfiltered total, for the count against the cap.
  const all = useQuery({
    queryKey: ["hidden", "count"],
    queryFn: () => api<Page<HiddenItem>>("GET", "/pickers/hidden?page=1&page_size=1"),
    retry: false,
    refetchOnWindowFocus: false,
  });
  const restore = useMutation({
    mutationFn: (id: string) => api<void>("DELETE", `/pickers/hidden/${encodeURIComponent(id)}`),
    onSuccess: async () => {
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ["hidden"] }),
        queryClient.invalidateQueries({ queryKey: ["picker"] }),
      ]);
    },
  });

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-col gap-1">
        <h2 className="text-lg font-semibold">{t("mapping.hidden.title")}</h2>
        <p className="text-muted">{t("mapping.hidden.intro")}</p>
      </div>
      <Card className="flex flex-col gap-2 p-4">
        <h3 className="text-[15px] font-semibold">{t("mapping.hidden.instanceTitle")}</h3>
        <p className="text-[12.5px] text-muted">{t("mapping.hidden.instanceNote")}</p>
      </Card>
      <Segmented
        label={t("mapping.hidden.filter")}
        value={filter}
        onChange={(value) => {
          setFilter(value === "harbor" || value === "github" ? value : "all");
          setPage(1);
        }}
        options={[
          { value: "all", label: t("mapping.hidden.filterAll") },
          { value: "harbor", label: t("mapping.hidden.filterHarbor") },
          { value: "github", label: t("mapping.hidden.filterGithub") },
        ]}
      />
      {list.isError ? <PickerError error={list.error} onRetry={() => void list.refetch()} /> : null}
      {restore.isError ? <PickerError error={restore.error} /> : null}
      {list.isPending ? <LoadingMessage /> : null}
      {list.data === undefined ? null : (
        <Card>
          <TableScroll label={t("mapping.hidden.list")}>
            <table className={TABLE}>
              <thead>
                <tr>
                  <th className={TH}>{t("mapping.hidden.col.source")}</th>
                  <th className={TH}>{t("mapping.hidden.col.item")}</th>
                  <th className={TH}>{t("mapping.hidden.col.instance")}</th>
                  <th className={TH}>{t("mapping.hidden.col.hiddenAt")}</th>
                  <th className={TH}>
                    <span className="sr-only">{t("mapping.hidden.col.action")}</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {list.data.items.map((item) => (
                  <tr key={item.id}>
                    <td className={TD}>
                      <Pill kind="unknown" label={item.source === "harbor" ? t("mapping.hidden.sourceHarbor") : t("mapping.hidden.sourceGithub")} />
                    </td>
                    <td className={`${TD} font-mono`}>{item.full_name}</td>
                    <td className={TD}>
                      {item.harbor_base_url === null ? (
                        <span className="text-muted">{t("mapping.hidden.noInstance")}</span>
                      ) : (
                        <span className="font-mono">{item.harbor_base_url}</span>
                      )}
                    </td>
                    <td className={`${TD} font-mono`}>{formatDateTime(item.created_at)}</td>
                    <td className={TD}>
                      <Button variant="small" disabled={restore.isPending} onClick={() => restore.mutate(item.id)}>
                        {t("mapping.hidden.restore")}
                        <span className="sr-only">{item.full_name}</span>
                      </Button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </TableScroll>
          {list.data.items.length === 0 ? <p className="p-4 text-[12.5px] text-muted">{t("mapping.hidden.empty")}</p> : null}
          <div className="p-3">
            <Pager idPrefix="hidden" page={page} pageSize={PAGE_SIZE} total={list.data.total} onPage={setPage} />
          </div>
        </Card>
      )}
      <Card className="flex flex-col gap-2.5 p-4">
        {all.data === undefined ? null : (
          <p className="text-xs text-muted">{t("mapping.hidden.count", { count: all.data.total, cap: CAP })}</p>
        )}
        <Note>{t("mapping.hidden.capNote")}</Note>
      </Card>
    </div>
  );
}
