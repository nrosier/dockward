import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState, type FormEvent } from "react";
import { Link, useNavigate, useParams } from "react-router";
import { CREDENTIALS_KEY } from "../components/account/CredentialsCard";
import { FormError, INPUT, messageOf } from "../components/admin/parts";
import { ConfirmDialog } from "../components/mappings/ConfirmDialog";
import { ImagesTable } from "../components/sources/ImagesTable";
import { ScanNow } from "../components/sources/ScanNow";
import { SOURCES_KEY, useHubs } from "../components/sources/useSources";
import { Button } from "../components/ui/Button";
import { Card } from "../components/ui/Card";
import { Field } from "../components/ui/Field";
import { PageTitle } from "../components/ui/PageTitle";
import { LoadingMessage } from "../components/ui/StatusMessage";
import { Switch } from "../components/ui/Switch";
import { t } from "../i18n";
import { api } from "../lib/api";
import { isValidRepository, tagValueKind } from "../lib/sourceValidation";
import type { Credential, IssueSeverity, Page } from "../types/api";
import type { Source } from "../types/sources";

export default function SourceFormPage() {
  const { id } = useParams();
  const existing = useQuery({
    queryKey: [...SOURCES_KEY, "form", id],
    enabled: id !== undefined,
    queryFn: () => api<Source>("GET", `/image-sources/${id}`),
  });
  if (id !== undefined && existing.isPending) {
    return <LoadingMessage />;
  }
  if (id !== undefined && !existing.data) {
    return <FormError message={t("errors.notFound.body")} />;
  }
  return <SourceForm id={id} loaded={existing.data ?? null} />;
}

function SourceForm({ id, loaded }: { id: string | undefined; loaded: Source | null }) {
  const editing = id !== undefined;
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const hubs = useHubs();
  const credentials = useQuery({
    queryKey: [...CREDENTIALS_KEY, "sources-form"],
    queryFn: () => api<Page<Credential>>("GET", "/credentials?page_size=200"),
  });

  const [hubId, setHubId] = useState(loaded?.hub_id ?? "");
  const [repository, setRepository] = useState(loaded?.repository ?? "");
  const [tagValue, setTagValue] = useState(loaded?.tag_value ?? "");
  const [githubCredId, setGithubCredId] = useState(loaded?.github_cred_id ?? "");
  const [owner, setOwner] = useState(loaded?.github_owner ?? "");
  const [repo, setRepo] = useState(loaded?.github_repo ?? "");
  const [branch, setBranch] = useState(loaded?.default_branch ?? "main");
  const [autoIssues, setAutoIssues] = useState(loaded?.auto_create_issues ?? false);
  const [severity, setSeverity] = useState<IssueSeverity>(loaded?.min_issue_severity ?? "CRITICAL");
  const [registryUser, setRegistryUser] = useState("");
  const [registryToken, setRegistryToken] = useState("");
  const [touched, setTouched] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [deleteError, setDeleteError] = useState<string | null>(null);

  const hubList = hubs.data ?? [];
  const hubHost = hubList.find((hub) => hub.id === hubId)?.host ?? "";
  const kind = tagValueKind(tagValue);
  const repositoryOk = isValidRepository(repository);
  const tagOk = kind === "exact" || kind === "pattern";
  const credentialOk = registryToken === "" || registryUser.trim() !== "";
  const valid =
    hubId !== "" &&
    repositoryOk &&
    tagOk &&
    githubCredId !== "" &&
    owner.trim() !== "" &&
    repo.trim() !== "" &&
    branch.trim() !== "" &&
    credentialOk;

  const save = useMutation({
    mutationFn: async () => {
      const body = {
        hub_id: hubId,
        repository,
        tag_value: tagValue,
        github_cred_id: githubCredId,
        github_owner: owner.trim(),
        github_repo: repo.trim(),
        default_branch: branch.trim(),
        auto_create_issues: autoIssues,
        min_issue_severity: severity,
      };
      const saved = editing
        ? await api<Source>("PUT", `/image-sources/${id}`, body)
        : await api<Source>("POST", "/image-sources", body);
      if (registryToken !== "") {
        await api("PUT", `/image-sources/${saved.id}/credential`, {
          username: registryUser.trim(),
          token: registryToken,
        });
      }
      return saved;
    },
    onSuccess: (saved) => {
      // The secret is never kept after the request resolves.
      setRegistryToken("");
      void queryClient.invalidateQueries({ queryKey: SOURCES_KEY });
      void navigate(`/sources/${saved.id}`);
    },
    onError: (failure) => {
      setRegistryToken("");
      setSaveError(messageOf(failure));
    },
  });

  const remove = useMutation({
    mutationFn: () => api("DELETE", `/image-sources/${id}`),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: SOURCES_KEY });
      void navigate("/sources");
    },
    onError: (failure) => setDeleteError(messageOf(failure)),
  });

  function submit(event: FormEvent) {
    event.preventDefault();
    setTouched(true);
    if (valid && !save.isPending) {
      setSaveError(null);
      save.mutate();
    }
  }

  const repositoryError = touched && !repositoryOk ? t("sources.form.repositoryInvalid") : undefined;
  const tagError = touched && !tagOk ? t("sources.form.tagInvalid") : undefined;
  const tagHint =
    kind === "exact"
      ? t("sources.form.tagHintExact")
      : kind === "pattern"
        ? t("sources.form.tagHintPattern")
        : kind === "invalid"
          ? t("sources.form.tagInvalid")
          : t("sources.form.tagHelp");
  const credentialNote =
    hubHost === "docker.io"
      ? loaded?.has_credential
        ? null
        : t("sources.form.noCredentialDockerHub")
      : hubHost === "ghcr.io"
        ? t("sources.form.ghcrHint")
        : null;

  return (
    <div className="flex flex-col gap-5">
      <div className="flex flex-col gap-1">
        <Link to="/sources" className="text-[13px] text-accent hover:underline">
          {t("sources.back")}
        </Link>
        <PageTitle title={editing ? t("page.sourceEdit") : t("page.sourceNew")} />
      </div>
      {editing ? <ScanNow sourceId={id} /> : null}
      <form onSubmit={submit} noValidate className="flex flex-col gap-5">
        <Card className="flex flex-col gap-4 p-5">
          <Field id="source-hub" label={t("sources.form.hub")}>
            <select id="source-hub" className={INPUT} value={hubId} onChange={(event) => setHubId(event.target.value)}>
              <option value="">{t("sources.form.hubPlaceholder")}</option>
              {hubList.map((hub) => (
                <option key={hub.id} value={hub.id}>
                  {hub.host}
                </option>
              ))}
            </select>
          </Field>
          <Field
            id="source-repository"
            label={t("sources.form.repository")}
            help={t("sources.form.repositoryHelp")}
            error={repositoryError}
          >
            <input
              id="source-repository"
              className={INPUT}
              value={repository}
              aria-invalid={repositoryError !== undefined}
              onChange={(event) => setRepository(event.target.value)}
            />
          </Field>
          <Field id="source-tag" label={t("sources.form.tag")} error={tagError}>
            <input
              id="source-tag"
              className={INPUT}
              value={tagValue}
              aria-invalid={tagError !== undefined}
              aria-describedby="source-tag-hint"
              onChange={(event) => setTagValue(event.target.value)}
            />
            <p id="source-tag-hint" className="text-[12.5px] text-muted">
              {tagHint}
            </p>
          </Field>
        </Card>

        <Card className="flex flex-col gap-4 p-5">
          <Field id="source-cred" label={t("sources.form.githubCredential")}>
            <select
              id="source-cred"
              className={INPUT}
              value={githubCredId}
              onChange={(event) => setGithubCredId(event.target.value)}
            >
              <option value="">{t("sources.form.credentialPlaceholder")}</option>
              {(credentials.data?.items ?? []).map((credential) => (
                <option key={credential.id} value={credential.id}>
                  {credential.label}
                </option>
              ))}
            </select>
          </Field>
          <Field id="source-owner" label={t("mappings.form.githubOwner")}>
            <input id="source-owner" className={INPUT} value={owner} onChange={(event) => setOwner(event.target.value)} />
          </Field>
          <Field id="source-repo" label={t("mappings.form.githubRepository")}>
            <input id="source-repo" className={INPUT} value={repo} onChange={(event) => setRepo(event.target.value)} />
          </Field>
          <Field id="source-branch" label={t("sources.form.defaultBranch")}>
            <input id="source-branch" className={INPUT} value={branch} onChange={(event) => setBranch(event.target.value)} />
          </Field>
          <div className="flex items-center justify-between gap-3">
            <label htmlFor="source-auto" className="text-[13px] font-semibold">
              {t("sources.form.autoIssues")}
            </label>
            <Switch id="source-auto" checked={autoIssues} onCheckedChange={setAutoIssues} />
          </div>
          <Field id="source-severity" label={t("sources.form.minSeverity")}>
            <select
              id="source-severity"
              className={INPUT}
              value={severity}
              onChange={(event) => setSeverity(event.target.value === "HIGH" ? "HIGH" : "CRITICAL")}
            >
              <option value="CRITICAL">{t("pill.critical")}</option>
              <option value="HIGH">{t("pill.high")}</option>
            </select>
          </Field>
        </Card>

        <Card className="flex flex-col gap-4 p-5">
          <h2 className="text-[15px] font-semibold">{t("sources.form.registryCredential")}</h2>
          {credentialNote === null ? null : <p className="text-[12.5px] text-muted">{credentialNote}</p>}
          {loaded?.has_credential ? <p className="text-[12.5px] text-muted">{t("sources.form.credentialSet")}</p> : null}
          <Field id="source-reg-user" label={t("sources.form.registryUsername")}>
            <input
              id="source-reg-user"
              className={INPUT}
              autoComplete="off"
              value={registryUser}
              onChange={(event) => setRegistryUser(event.target.value)}
            />
          </Field>
          <Field id="source-reg-token" label={t("sources.form.registryToken")} help={t("credentials.form.tokenHelp")}>
            <input
              id="source-reg-token"
              className={INPUT}
              type="password"
              autoComplete="off"
              placeholder={loaded?.has_credential ? t("credentials.form.keepToken") : undefined}
              value={registryToken}
              onChange={(event) => setRegistryToken(event.target.value)}
            />
          </Field>
        </Card>

        <FormError message={saveError} />
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            {editing ? (
              <Button variant="danger" onClick={() => setConfirmDelete(true)}>
                {t("sources.delete.button")}
              </Button>
            ) : null}
          </div>
          <div className="flex flex-wrap items-center gap-3">
            <Button type="submit" variant="primary" disabled={save.isPending}>
              {save.isPending ? t("sources.form.saving") : t("sources.form.save")}
            </Button>
            <Button onClick={() => void navigate("/sources")}>{t("common.cancel")}</Button>
          </div>
        </div>
      </form>

      {editing ? <ImagesTable sourceId={id} /> : null}

      <ConfirmDialog
        open={confirmDelete}
        onOpenChange={setConfirmDelete}
        title={t("sources.delete.title")}
        description={t("sources.delete.body")}
        confirmLabel={t("sources.delete.confirm")}
        danger
        pending={remove.isPending}
        error={deleteError}
        onConfirm={() => {
          setDeleteError(null);
          remove.mutate();
        }}
      />
    </div>
  );
}
