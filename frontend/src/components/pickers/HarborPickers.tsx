import { useState } from "react";
import { t } from "../../i18n";
import type { Credential, HarborProject, HarborRepository } from "../../types/api";
import { Button } from "../ui/Button";
import { Note, PANEL, Pager, SearchBox } from "./PickerControls";
import { HideError, PickerError } from "./PickerError";
import { useDebounced } from "./useDebounced";
import { useHide } from "./useHide";
import { usePickerList } from "./usePickerList";

interface Props {
  credential: Credential | undefined;
  // The project picked from the list, or null (typed entry is not "picked").
  project: string | null;
  // The repository picked, as `<project>/<repository>`, or null.
  repository: string;
  savedProject: string;
  savedRepository: string;
  onProject: (name: string) => void;
  onRepository: (repository: string) => void;
}

const ROW = "flex items-center gap-1.5";

// The Harbor project picker and, once a project is picked, its repository
// picker. Both lists are live per credential (#126).
// Keyed by credential in the form, so a new credential starts both lists fresh.
export function HarborPickers({ credential, project, repository, savedProject, savedRepository, onProject, onRepository }: Props) {
  const credentialId = credential?.id;
  const [projectSearch, setProjectSearch] = useState("");
  const [projectPage, setProjectPage] = useState(1);
  const [projectSize, setProjectSize] = useState(50);
  const hide = useHide();


  const projectQ = useDebounced(projectSearch);
  const projects = usePickerList<HarborProject>({
    path: credentialId === undefined ? null : `/credentials/${encodeURIComponent(credentialId)}/harbor-projects`,
    q: projectQ,
    page: projectPage,
    pageSize: projectSize,
    sort: "name",
  });
  const baseUrl = credential?.base_url ?? null;
  const hideHarbor = (fullName: string) => {
    if (baseUrl !== null) {
      hide.hide({ source: "harbor", full_name: fullName, harbor_base_url: baseUrl });
    }
  };
  const saved = savedProject !== "" && savedRepository !== "" ? `${savedProject.trim()}/${savedRepository.trim()}` : null;

  return (
    <div className="grid gap-4 md:grid-cols-2">
      <section aria-label={t("mapping.picker.projectLabel")} className={`${PANEL} gap-2.5`}>
        <h3 className="text-[15px] font-semibold">{t("mapping.picker.harborProject")}</h3>
        <SearchBox
          id="project-search"
          label={t("mapping.picker.searchProjects")}
          value={projectSearch}
          onChange={(value) => {
            setProjectSearch(value);
            setProjectPage(1);
          }}
        />
        {projects.isError ? <PickerError error={projects.error} stamp={projects.errorUpdatedAt} onRetry={() => void projects.refetch()} /> : null}
        {hide.failed ? <HideError error={hide.error} /> : null}
        {projects.data === undefined ? null : (
          <>
            <ul aria-label={t("mapping.picker.projectList")} className="m-0 grid list-none gap-1 p-0 font-mono text-[13px]">
              {projects.data.items.map((item) => (
                <li key={item.name} className={ROW}>
                  <Button
                    className="min-w-0 flex-1 justify-start"
                    aria-pressed={item.name === project}
                    onClick={() => {
                      onProject(item.name);
                    }}
                  >
                    {item.name}
                  </Button>
                  <Button variant="small" disabled={hide.pending} onClick={() => hideHarbor(item.name)}>
                    {t("mapping.hide.action")}
                    <span className="sr-only">{item.name}</span>
                  </Button>
                </li>
              ))}
            </ul>
            {projects.data.items.length === 0 ? <p className="text-[12.5px] text-muted">{t("mapping.picker.empty")}</p> : null}
            {projects.data.truncated ? <Note>{t("mapping.picker.cut")}</Note> : null}
            <Pager
              idPrefix="project"
              page={projectPage}
              pageSize={projectSize}
              total={projects.data.total}
              onPage={setProjectPage}
              onPageSize={(size) => {
                setProjectSize(size);
                setProjectPage(1);
              }}
            />
          </>
        )}
      </section>

      <section aria-label={t("mapping.picker.repositoryLabel")} className={`${PANEL} gap-2.5`}>
        <h3 className="text-[15px] font-semibold">{t("mapping.picker.harborRepository")}</h3>
        <p className="text-[12.5px] text-muted">{t("mapping.picker.repositoryHint")}</p>
        {project === null || credentialId === undefined ? null : (
          <RepositoryList
            key={`${credentialId}/${project}`}
            credentialId={credentialId}
            baseUrl={baseUrl}
            project={project}
            repository={repository}
            onRepository={onRepository}
          />
        )}
        {saved === null ? null : <p className="font-mono text-xs text-muted">{t("mapping.picker.saved", { value: saved })}</p>}
      </section>
    </div>
  );
}

interface RepositoryListProps {
  credentialId: string;
  baseUrl: string | null;
  project: string;
  repository: string;
  onRepository: (fullName: string) => void;
}

// The repositories of one picked project. Keyed by credential and project in
// the parent, so a different project starts with a clean search and page.
function RepositoryList({ credentialId, baseUrl, project, repository, onRepository }: RepositoryListProps) {
  const [search, setSearch] = useState("");
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(50);
  const hide = useHide();
  const q = useDebounced(search);
  const repositories = usePickerList<HarborRepository>({
    path: `/credentials/${encodeURIComponent(credentialId)}/harbor-projects/${encodeURIComponent(project)}/repositories`,
    q,
    page,
    pageSize,
    sort: "name",
  });
  return (
    <>
      <SearchBox
        id="repository-search"
        label={t("mapping.picker.searchRepositories")}
        value={search}
        onChange={(value) => {
          setSearch(value);
          setPage(1);
        }}
      />
      {repositories.isError ? (
        <PickerError error={repositories.error} stamp={repositories.errorUpdatedAt} onRetry={() => void repositories.refetch()} />
      ) : null}
      {hide.failed ? <HideError error={hide.error} /> : null}
      {repositories.data === undefined ? null : (
        <>
          <ul aria-label={t("mapping.picker.repositoryList")} className="m-0 grid list-none gap-1 p-0 font-mono text-[13px]">
            {repositories.data.items.map((item) => (
              <li key={item.full_name} className={ROW}>
                <Button className="min-w-0 flex-1 justify-start" aria-pressed={item.full_name === repository} onClick={() => onRepository(item.full_name)}>
                  {item.repository}
                </Button>
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
              </li>
            ))}
          </ul>
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
    </>
  );
}
