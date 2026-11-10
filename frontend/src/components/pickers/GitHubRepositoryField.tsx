import { useState } from "react";
import { t } from "../../i18n";
import type { GitHubRepository } from "../../types/api";
import { Field } from "../ui/Field";
import { Pill } from "../ui/Pill";
import { Tooltip } from "../ui/Tooltip";
import { Combobox, type ComboOption } from "./Combobox";
import { Note, Pager } from "./PickerControls";
import { PickerError } from "./PickerError";
import { useDebounced } from "./useDebounced";
import { usePickerList } from "./usePickerList";

interface Props {
  credentialId: string | undefined;
  // What the input shows: owner/repo, or whatever was typed.
  value: string;
  // Set when the owner/repository pair is already used by another mapping.
  error?: string;
  onText: (text: string) => void;
  onPick: (owner: string, repo: string) => void;
}

// The GitHub repository field: a searchable combobox over what the token can
// see (#126, #167). Typing filters through the server-side search and still
// works as free entry for a repository that is not listed. The fixed
// organisation note is a tooltip on the field label. A new credential
// starts the search and page clean.
export function GitHubRepositoryField({ credentialId, value, error, onText, onPick }: Props) {
  const [search, setSearch] = useState("");
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(50);
  // A new credential starts the list clean. The input stays mounted so typing
  // is not interrupted when the default credential is filled in.
  const [seenCredential, setSeenCredential] = useState(credentialId);
  if (seenCredential !== credentialId) {
    setSeenCredential(credentialId);
    setSearch("");
    setPage(1);
  }
  const q = useDebounced(search);
  const list = usePickerList<GitHubRepository>({
    path: credentialId === undefined ? null : `/credentials/${encodeURIComponent(credentialId)}/github-repositories`,
    q,
    page,
    pageSize,
    sort: "full_name",
  });
  const options: ComboOption[] = (list.data?.items ?? []).map((item) => ({
    key: item.full_name,
    content: (
      <span className="flex min-w-0 items-center gap-2">
        <span className="min-w-0 truncate">{item.full_name}</span>
        <Pill kind={item.private ? "unknown" : "done"} label={item.private ? t("mapping.github.private") : t("mapping.github.public")} />
        {item.archived ? <Pill kind="medium" label={t("mapping.github.archived")} /> : null}
      </span>
    ),
    onSelect: () => {
      setSearch("");
      setPage(1);
      onPick(item.owner, item.repo);
    },
  }));

  return (
    <Field
      id="github-repository"
      label={t("mappings.form.githubRepository")}
      error={error}
      hint={<Tooltip label={t("mapping.github.orgNoteLabel")} text={t("mapping.github.orgNote")} />}
    >
      <Combobox
        id="github-repository"
        value={value}
        listEnabled={credentialId !== undefined}
        placeholder={t("mapping.picker.searchPlaceholder")}
        listLabel={t("mapping.github.list")}
        options={options}
        invalid={error !== undefined}
        describedBy={error === undefined ? undefined : "github-repository-error"}
        onChange={(text) => {
          setSearch(text);
          setPage(1);
          onText(text);
        }}
      >
        {list.isError ? <PickerError error={list.error} stamp={list.errorUpdatedAt} onRetry={() => void list.refetch()} /> : null}
        {list.data === undefined ? null : (
          <>
            {list.data.items.length === 0 ? <p className="text-[12.5px] text-muted">{t("mapping.picker.empty")}</p> : null}
            {list.data.truncated ? <Note>{t("mapping.github.cut")}</Note> : null}
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
      </Combobox>
    </Field>
  );
}
