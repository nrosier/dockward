import { useState } from "react";
import { t } from "../../i18n";
import type { Credential, HarborProject, HarborRepository } from "../../types/api";
import { Button } from "../ui/Button";
import { Field } from "../ui/Field";
import { Combobox, type ComboOption } from "./Combobox";
import { Note, Pager } from "./PickerControls";
import { HideError, PickerError } from "./PickerError";
import { useDebounced } from "./useDebounced";
import { useHide } from "./useHide";
import { usePickerList } from "./usePickerList";

interface Props {
  credential: Credential | undefined;
  // The project picked from the list, or null (typed entry is not "picked").
  project: string | null;
  // What the two inputs show.
  projectValue: string;
  repositoryValue: string;
  // Set when the repository pair is already used by another mapping.
  repositoryError?: string;
  onProjectText: (text: string) => void;
  onProject: (name: string) => void;
  onRepositoryText: (text: string) => void;
  onRepository: (repository: string) => void;
}

// The Harbor project and repository fields, each a searchable combobox over the
// live list for the credential (#126, #167). Typing filters the list through
// the server-side search and still works as free entry for a value that is not
// listed. The repository list opens only once a project is picked.
export function HarborPickers({
  credential,
  project,
  projectValue,
  repositoryValue,
  repositoryError,
  onProjectText,
  onProject,
  onRepositoryText,
  onRepository,
}: Props) {
  const credentialId = credential?.id;
  const baseUrl = credential?.base_url ?? null;
  // The search is what the user typed since the last pick, not the picked name.
  const [search, setSearch] = useState("");
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(50);
  const hide = useHide();
  // A new credential starts the list clean. The inputs stay mounted so typing
  // is not interrupted when the default credential is filled in.
  const [seenCredential, setSeenCredential] = useState(credentialId);
  if (seenCredential !== credentialId) {
    setSeenCredential(credentialId);
    setSearch("");
    setPage(1);
  }
  const q = useDebounced(search);
  const projects = usePickerList<HarborProject>({
    path: credentialId === undefined ? null : `/credentials/${encodeURIComponent(credentialId)}/harbor-projects`,
    q,
    page,
    pageSize,
    sort: "name",
  });
  const options: ComboOption[] = (projects.data?.items ?? []).map((item) => ({
    key: item.name,
    content: item.name,
    onSelect: () => {
      setSearch("");
      setPage(1);
      onProject(item.name);
    },
    action: (
      <Button
        variant="small"
        disabled={hide.pending || baseUrl === null}
        onClick={() => {
          if (baseUrl !== null) {
            hide.hide({ source: "harbor", full_name: item.name, harbor_base_url: baseUrl });
          }
        }}
      >
        {t("mapping.hide.action")}
        <span className="sr-only">{item.name}</span>
      </Button>
    ),
  }));

  return (
    <>
      <Field id="harbor-project" label={t("mappings.form.harborProject")}>
        <Combobox
          id="harbor-project"
          value={projectValue}
          placeholder={t("mapping.picker.searchPlaceholder")}
          listLabel={t("mapping.picker.projectList")}
          options={options}
          onChange={(text) => {
            setSearch(text);
            setPage(1);
            onProjectText(text);
          }}
        >
          {projects.isError ? (
            <PickerError error={projects.error} stamp={projects.errorUpdatedAt} onRetry={() => void projects.refetch()} />
          ) : null}
          {hide.failed ? <HideError error={hide.error} /> : null}
          {projects.data === undefined ? null : (
            <>
              {projects.data.items.length === 0 ? <p className="text-[12.5px] text-muted">{t("mapping.picker.empty")}</p> : null}
              {projects.data.truncated ? <Note>{t("mapping.picker.cut")}</Note> : null}
              <Pager
                idPrefix="project"
                page={page}
                pageSize={pageSize}
                total={projects.data.total}
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
      <RepositoryField
        // A different project starts the repository search and page clean.
        key={`${credentialId ?? ""}/${project ?? ""}`}
        credentialId={credentialId}
        baseUrl={baseUrl}
        project={project}
        value={repositoryValue}
        error={repositoryError}
        onText={onRepositoryText}
        onPick={onRepository}
      />
    </>
  );
}

interface RepositoryFieldProps {
  credentialId: string | undefined;
  baseUrl: string | null;
  project: string | null;
  value: string;
  error: string | undefined;
  onText: (text: string) => void;
  onPick: (fullName: string) => void;
}

function RepositoryField({ credentialId, baseUrl, project, value, error, onText, onPick }: RepositoryFieldProps) {
  const [search, setSearch] = useState("");
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(50);
  const hide = useHide();
  const q = useDebounced(search);
  const listed = project !== null && credentialId !== undefined;
  const repositories = usePickerList<HarborRepository>({
    path: listed
      ? `/credentials/${encodeURIComponent(credentialId)}/harbor-projects/${encodeURIComponent(project)}/repositories`
      : null,
    q,
    page,
    pageSize,
    sort: "name",
  });
  const options: ComboOption[] = (repositories.data?.items ?? []).map((item) => ({
    key: item.full_name,
    content: item.repository,
    onSelect: () => {
      setSearch("");
      setPage(1);
      onPick(item.full_name);
    },
    action: (
      <Button
        variant="small"
        disabled={hide.pending || baseUrl === null}
        onClick={() => {
          if (baseUrl !== null) {
            hide.hide({ source: "harbor", full_name: item.full_name, harbor_base_url: baseUrl });
          }
        }}
      >
        {t("mapping.hide.action")}
        <span className="sr-only">{item.repository}</span>
      </Button>
    ),
  }));
  return (
    <Field
      id="harbor-repository"
      label={t("mappings.form.harborRepository")}
      error={error}
    >
      <Combobox
        id="harbor-repository"
        value={value}
        listEnabled={listed}
        placeholder={listed ? t("mapping.picker.searchPlaceholder") : undefined}
        listLabel={t("mapping.picker.repositoryList")}
        options={options}
        invalid={error !== undefined}
        describedBy={error === undefined ? "harbor-repository-help" : "harbor-repository-help harbor-repository-error"}
        onChange={(text) => {
          setSearch(text);
          setPage(1);
          onText(text);
        }}
      >
        {repositories.isError ? (
          <PickerError error={repositories.error} stamp={repositories.errorUpdatedAt} onRetry={() => void repositories.refetch()} />
        ) : null}
        {hide.failed ? <HideError error={hide.error} /> : null}
        {repositories.data === undefined ? null : (
          <>
            {repositories.data.items.length === 0 ? <p className="text-[12.5px] text-muted">{t("mapping.picker.empty")}</p> : null}
            {repositories.data.truncated ? <Note>{t("mapping.picker.cut")}</Note> : null}
            <Pager
              idPrefix="repository"
              page={page}
              pageSize={pageSize}
              total={repositories.data.total}
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
