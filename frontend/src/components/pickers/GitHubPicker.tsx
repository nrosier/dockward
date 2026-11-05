import { useState } from "react";
import { t } from "../../i18n";
import type { GitHubRepository } from "../../types/api";
import { TABLE, TD, TH } from "../mappings/styles";
import { TableScroll } from "../mappings/TableScroll";
import { Button } from "../ui/Button";
import { Pill } from "../ui/Pill";
import { PANEL, Note, Pager, SearchBox } from "./PickerControls";
import { HideError, PickerError } from "./PickerError";
import { useDebounced } from "./useDebounced";
import { useHide } from "./useHide";
import { usePickerList } from "./usePickerList";

interface Props {
  credentialId: string | undefined;
  savedOwner: string;
  savedRepo: string;
  onUse: (owner: string, repo: string) => void;
}

// Keyed by credential in the form, so a new credential starts it fresh.
// The GitHub repository picker: the list of what the token can see, with the
// fixed organisation note always shown (#126).
export function GitHubPicker({ credentialId, savedOwner, savedRepo, onUse }: Props) {
  const [search, setSearch] = useState("");
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(50);
  const hide = useHide();
  const q = useDebounced(search);
  const list = usePickerList<GitHubRepository>({
    path: credentialId === undefined ? null : `/credentials/${encodeURIComponent(credentialId)}/github-repositories`,
    q,
    page,
    pageSize,
    sort: "full_name",
  });
  const saved = savedOwner !== "" && savedRepo !== "" ? `${savedOwner.trim()}/${savedRepo.trim()}` : null;

  return (
    <section aria-label={t("mapping.github.title")} className={`${PANEL} gap-3`}>
      <h3 className="text-[15px] font-semibold">{t("mapping.github.title")}</h3>
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="min-w-0 flex-1">
          <SearchBox
            id="github-search"
            label={t("mapping.github.searchLabel")}
            value={search}
            onChange={(value) => {
              setSearch(value);
              setPage(1);
            }}
          />
        </div>
        {list.data === undefined ? null : (
          <span className="text-[12.5px] text-muted">{t("mapping.github.count", { count: list.data.total })}</span>
        )}
      </div>
      <Note>{t("mapping.github.orgNote")}</Note>
      {list.data?.truncated === true ? <Note>{t("mapping.github.cut")}</Note> : null}
      {list.isError ? <PickerError error={list.error} stamp={list.errorUpdatedAt} onRetry={() => void list.refetch()} /> : null}
      {hide.failed ? <HideError error={hide.error} /> : null}
      {list.data === undefined ? null : (
        <>
          <TableScroll label={t("mapping.github.list")}>
            <table className={TABLE}>
              <thead>
                <tr>
                  <th className={TH}>{t("mapping.github.col.repository")}</th>
                  <th className={TH}>{t("mapping.github.col.visibility")}</th>
                  <th className={TH}>{t("mapping.github.col.flags")}</th>
                  <th className={TH}>
                    <span className="sr-only">{t("mapping.github.col.action")}</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {list.data.items.map((item) => (
                  <tr key={item.full_name}>
                    <td className={`${TD} font-mono`}>{item.full_name}</td>
                    <td className={TD}>
                      <Pill kind={item.private ? "unknown" : "done"} label={item.private ? t("mapping.github.private") : t("mapping.github.public")} />
                    </td>
                    <td className={TD}>{item.archived ? <Pill kind="medium" label={t("mapping.github.archived")} /> : null}</td>
                    <td className={TD}>
                      <div className="flex gap-1.5">
                        <Button
                          variant="small"
                          aria-label={t("mapping.github.useNamed", { name: item.full_name })}
                          onClick={() => onUse(item.owner, item.repo)}
                        >
                          {t("mapping.github.use")}
                        </Button>
                        <Button
                          variant="small"
                          disabled={hide.pending}
                          onClick={() => hide.hide({ source: "github", full_name: item.full_name })}
                        >
                          {t("mapping.hide.action")}
                          <span className="sr-only">{item.full_name}</span>
                        </Button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </TableScroll>
          {list.data.items.length === 0 ? <p className="text-[12.5px] text-muted">{t("mapping.picker.empty")}</p> : null}
          <Pager
            idPrefix="github"
            page={page}
            pageSize={pageSize}
            total={list.data.total}
            onPage={setPage}
            onPageSize={(size) => {
              setPageSize(size);
              setPage(1);
            }}
          />
        </>
      )}
      {saved === null ? null : <p className="font-mono text-xs text-muted">{t("mapping.picker.saved", { value: saved })}</p>}
    </section>
  );
}
