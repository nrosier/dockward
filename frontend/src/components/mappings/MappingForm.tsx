import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState, type FormEvent, type ReactNode } from "react";
import { Link, useNavigate } from "react-router";
import { t } from "../../i18n";
import { ApiError, api } from "../../lib/api";
import type { Credential, IssueSeverity, Mapping, MappingCreated, MappingListItem, Page } from "../../types/api";
import { Button, buttonClass } from "../ui/Button";
import { Card } from "../ui/Card";
import { Tooltip } from "../ui/Tooltip";
import { Field } from "../ui/Field";
import { Switch } from "../ui/Switch";
import { GitHubRepositoryField } from "../pickers/GitHubRepositoryField";
import { HarborPickers } from "../pickers/HarborPickers";
import { SourceSuggestion } from "../pickers/SourceSuggestion";
import { useCredentials } from "../pickers/useCredentials";
import { Segmented } from "./Segmented";
import { INPUT, LINK } from "./styles";
import { mappingName } from "./useMappings";

interface FormValues {
  harborProject: string;
  harborRepository: string;
  harborCredId: string;
  githubCredId: string;
  githubOwner: string;
  githubRepo: string;
  defaultBranch: string;
  autoCreate: boolean;
  minSeverity: IssueSeverity;
}

function initialValues(mapping: Mapping | undefined): FormValues {
  return {
    harborProject: mapping?.harbor_project ?? "",
    harborRepository: mapping?.harbor_repository ?? "",
    harborCredId: mapping?.harbor_cred_id ?? "",
    githubCredId: mapping?.github_cred_id ?? "",
    githubOwner: mapping?.github_owner ?? "",
    githubRepo: mapping?.github_repo ?? "",
    defaultBranch: mapping?.default_branch ?? "main",
    autoCreate: mapping?.auto_create_issues ?? true,
    minSeverity: mapping?.min_issue_severity ?? "HIGH",
  };
}

const same = (a: string, b: string) => a.trim().toLowerCase() === b.trim().toLowerCase();

// The fields that changed, in the API's names, for `PUT`.
function changedFields(initial: FormValues, now: FormValues): Record<string, string | boolean> {
  const body: Record<string, string | boolean> = {};
  if (now.harborProject !== initial.harborProject) body.harbor_project = now.harborProject.trim();
  if (now.harborRepository !== initial.harborRepository) body.harbor_repository = now.harborRepository.trim();
  if (now.harborCredId !== initial.harborCredId) body.harbor_cred_id = now.harborCredId;
  if (now.githubCredId !== initial.githubCredId) body.github_cred_id = now.githubCredId;
  if (now.githubOwner !== initial.githubOwner) body.github_owner = now.githubOwner.trim();
  if (now.githubRepo !== initial.githubRepo) body.github_repo = now.githubRepo.trim();
  if (now.defaultBranch !== initial.defaultBranch) body.default_branch = now.defaultBranch.trim();
  if (now.autoCreate !== initial.autoCreate) body.auto_create_issues = now.autoCreate;
  if (now.minSeverity !== initial.minSeverity) body.min_issue_severity = now.minSeverity;
  return body;
}

// One column of the two-column card: a heading and its fields. The columns
// share one bordered card with a divider; narrow screens stack them (#167).
// From md up each column is a subgrid over the same rows (the heading, then
// one row per field), so the fields line up across the columns. A div with
// role "group" is used because a fieldset does not take part in subgrid.
function Column({ id, title, rows, children }: { id: string; title: string; rows: 4 | 5; children: ReactNode }) {
  return (
    <div
      // oxlint-disable-next-line jsx-a11y/prefer-tag-over-role -- a fieldset does not take part in a grid subgrid
      role="group"
      aria-labelledby={id}
      className={`m-0 flex min-w-0 flex-col gap-[18px] p-5 max-md:border-t max-md:border-border max-md:first:border-t-0 md:grid md:grid-rows-subgrid md:gap-y-[18px] md:border-l md:border-border md:first:border-l-0 ${rows === 5 ? "md:row-span-5" : "md:row-span-4"}`}
    >
      <h2 id={id} className="m-0 mb-0.5 text-[15px] font-semibold">
        {title}
      </h2>
      {children}
    </div>
  );
}

interface CredentialSelectProps {
  id: string;
  label: string;
  type: "harbor" | "github";
  value: string;
  onChange: (value: string) => void;
  help?: ReactNode;
}

function CredentialSelect({ id, label, type, value, onChange, help }: CredentialSelectProps) {
  const query = useQuery({
    queryKey: ["credentials", type],
    queryFn: () => api<Page<Credential>>("GET", `/credentials?service_type=${type}&page_size=200`),
  });
  const items = query.data?.items ?? [];
  const effective = value !== "" ? value : (items[0]?.id ?? "");
  // The first credential is the default; report it so the form can submit it.
  useEffect(() => {
    if (value === "" && effective !== "") {
      onChange(effective);
    }
  }, [value, effective, onChange]);
  if (query.isSuccess && items.length === 0) {
    return (
      <div className="flex flex-col gap-1.5">
        <span className="text-[13px] font-semibold">{label}</span>
        <p className="text-[13px] text-muted">
          {t("mappings.form.noCredential")}{" "}
          <Link to="/account" className={LINK}>
            {t("mappings.form.noCredentialLink")}
          </Link>
        </p>
      </div>
    );
  }
  return (
    <Field id={id} label={label}>
      <select id={id} value={effective} onChange={(event) => onChange(event.target.value)} className={INPUT}>
        {items.map((credential) => (
          <option key={credential.id} value={credential.id}>
            {credential.base_url === null
              ? credential.label
              : t("mappings.form.credentialOption", { label: credential.label, host: hostOf(credential.base_url) })}
          </option>
        ))}
      </select>
      {help}
    </Field>
  );
}

function hostOf(url: string): string {
  try {
    return new URL(url).host;
  } catch {
    return url;
  }
}

interface MappingFormProps {
  // Set when editing.
  mapping?: Mapping;
  readOnly?: boolean;
  // Called with the create response. The caller keeps it in component state only.
  onCreated: (created: MappingCreated) => void;
}

export function MappingForm({ mapping, readOnly = false, onCreated }: MappingFormProps) {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const initial = initialValues(mapping);
  const [values, setValues] = useState<FormValues>(initial);
  const [serverError, setServerError] = useState<string | null>(null);
  // What the user picked from the Harbor lists (typed entry leaves these null).
  const [picked, setPicked] = useState<{ project: string; repository: string | null } | null>(null);
  // What the GitHub repository field shows: owner/repo, or what was typed.
  const [githubText, setGithubText] = useState(
    initial.githubOwner !== "" || initial.githubRepo !== "" ? `${initial.githubOwner}/${initial.githubRepo}` : "",
  );
  const [dismissed, setDismissed] = useState<string[]>([]);
  const harborCreds = useCredentials("harbor");
  const harborCredential = harborCreds.data?.items.find((item) => item.id === values.harborCredId);
  const set = <K extends keyof FormValues>(key: K, value: FormValues[K]) => {
    setServerError(null);
    setValues((current) => ({ ...current, [key]: value }));
  };

  // The user's own mappings, for the duplicate-target check before submit.
  const own = useQuery({
    queryKey: ["mappings", "own"],
    queryFn: () => api<Page<MappingListItem>>("GET", "/mappings?page_size=200"),
  });
  const others = (own.data?.items ?? []).filter((item) => item.id !== mapping?.id);
  const githubClash = others.find(
    (item) => values.githubOwner.trim() !== "" && values.githubRepo.trim() !== "" &&
      same(item.github_owner, values.githubOwner) && same(item.github_repo, values.githubRepo),
  );
  const harborClash = others.find(
    (item) => values.harborProject.trim() !== "" && values.harborRepository.trim() !== "" &&
      same(item.harbor_project, values.harborProject) && same(item.harbor_repository, values.harborRepository),
  );

  const save = useMutation({
    // Secret-bearing results go straight to the caller's state. The mutation
    // itself returns nothing, so the mutation cache holds no secret.
    mutationFn: async (): Promise<void> => {
      if (mapping === undefined) {
        const created = await api<MappingCreated>("POST", "/mappings", {
          harbor_cred_id: values.harborCredId,
          github_cred_id: values.githubCredId,
          harbor_project: values.harborProject.trim(),
          harbor_repository: values.harborRepository.trim(),
          github_owner: values.githubOwner.trim(),
          github_repo: values.githubRepo.trim(),
          default_branch: values.defaultBranch.trim(),
          auto_create_issues: values.autoCreate,
          min_issue_severity: values.minSeverity,
        });
        onCreated(created);
        return;
      }
      await api("PUT", `/mappings/${encodeURIComponent(mapping.id)}`, changedFields(initial, values));
    },
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["mappings"] });
      if (mapping !== undefined) {
        void navigate("/mappings");
      }
    },
    onError: (failure) => {
      if (failure instanceof ApiError && failure.code === "code_scanning_unavailable") {
        setServerError(t("mappings.form.codeScanningUnavailable"));
      } else if (failure instanceof ApiError && (failure.status === 409 || failure.status === 422)) {
        setServerError(failure.message);
      } else {
        setServerError(t("errors.generic"));
      }
    },
  });

  // One suggestion per picked project/repository pair; null once dismissed.
  const pairKey = picked === null || picked.repository === null ? null : `${picked.project}/${values.harborRepository}`;
  const suggestKey = pairKey === null || dismissed.includes(pairKey) ? null : pairKey;

  const showSuggestion = !(suggestKey === null || values.harborCredId === "" || picked === null || picked.repository === null);

  const filled = [
    values.harborProject,
    values.harborRepository,
    values.harborCredId,
    values.githubCredId,
    values.githubOwner,
    values.githubRepo,
    values.defaultBranch,
  ].every((value) => value.trim() !== "");
  const changed = mapping === undefined || Object.keys(changedFields(initial, values)).length > 0;
  const canSave = !readOnly && filled && changed && githubClash === undefined && harborClash === undefined && !save.isPending;

  function submit(event: FormEvent) {
    event.preventDefault();
    if (!canSave) {
      return;
    }
    setServerError(null);
    save.mutate();
  }

  return (
    <form onSubmit={submit} className="flex flex-col gap-5" noValidate>
      <fieldset disabled={readOnly} className="m-0 flex min-w-0 flex-col gap-5 border-0 p-0">
        <Card className="m-0 grid min-w-0 grid-cols-1 md:grid-cols-2">
        <Column id="harbor-section" title={t("mappings.form.harborSection")} rows={showSuggestion ? 5 : 4}>
          <CredentialSelect
            id="harbor-cred"
            label={t("mappings.form.harborCredential")}
            type="harbor"
            value={values.harborCredId}
            onChange={(value) => {
              if (values.harborCredId !== "" && value !== values.harborCredId) {
                // A different Harbor instance: the project and repository no longer apply.
                setPicked(null);
                setValues((current) => ({ ...current, harborProject: "", harborRepository: "" }));
              }
              set("harborCredId", value);
            }}
          />
          <HarborPickers
            credential={harborCredential}
            project={picked?.project ?? null}
            projectValue={values.harborProject}
            repositoryValue={values.harborRepository}
            repositoryError={
              harborClash === undefined
                ? undefined
                : t("mappings.form.duplicate", { name: mappingName(harborClash) })
            }
            onProjectText={(text) => {
              setPicked(null);
              set("harborProject", text);
            }}
            onProject={(name) => {
              setPicked({ project: name, repository: null });
              setValues((current) => ({ ...current, harborProject: name, harborRepository: "" }));
              setServerError(null);
            }}
            onRepositoryText={(text) => {
              setPicked((current) => (current === null ? null : { ...current, repository: null }));
              set("harborRepository", text);
            }}
            onRepository={(fullName) => {
              const slash = fullName.indexOf("/");
              setPicked((current) => (current === null ? null : { ...current, repository: fullName }));
              set("harborRepository", fullName.slice(slash + 1));
            }}
          />
          {!showSuggestion || suggestKey === null || picked === null ? null : (
            <SourceSuggestion
              key={suggestKey}
              harborCredId={values.harborCredId}
              githubCredId={values.githubCredId}
              project={picked.project}
              repository={values.harborRepository}
              onConfirm={(owner, repo) => {
                setGithubText(`${owner}/${repo}`);
                setValues((current) => ({ ...current, githubOwner: owner, githubRepo: repo }));
              }}
              onDismiss={() => setDismissed((current) => [...current, suggestKey])}
            />
          )}
        </Column>

        <Column id="github-section" title={t("mappings.form.githubSection")} rows={showSuggestion ? 5 : 4}>
          <CredentialSelect
            id="github-cred"
            label={t("mappings.form.githubCredential")}
            type="github"
            value={values.githubCredId}
            onChange={(value) => {
              if (values.githubCredId !== "" && value !== values.githubCredId) {
                setGithubText("");
                setValues((current) => ({ ...current, githubOwner: "", githubRepo: "" }));
              }
              set("githubCredId", value);
            }}
          />
          <GitHubRepositoryField
            credentialId={values.githubCredId === "" ? undefined : values.githubCredId}
            value={githubText}
            error={
              githubClash === undefined ? undefined : t("mappings.form.duplicate", { name: mappingName(githubClash) })
            }
            onText={(text) => {
              const slash = text.indexOf("/");
              setGithubText(text);
              set("githubOwner", slash < 0 ? text : text.slice(0, slash));
              set("githubRepo", slash < 0 ? "" : text.slice(slash + 1));
            }}
            onPick={(owner, repo) => {
              setGithubText(`${owner}/${repo}`);
              setValues((current) => ({ ...current, githubOwner: owner, githubRepo: repo }));
              setServerError(null);
            }}
          />
          <Field id="default-branch" label={t("mappings.form.defaultBranch")} hint={<Tooltip label={t("mappings.form.defaultBranchTipLabel")} text={t("mappings.form.defaultBranchHelp")} />}>
            <input
              id="default-branch"
              value={values.defaultBranch}
              onChange={(event) => set("defaultBranch", event.target.value)}
              aria-describedby="default-branch-help"
              className={INPUT}
            />
          </Field>
        </Column>
        </Card>

        <Card className="m-0 flex min-w-0 flex-col gap-[18px] px-[22px] py-5">
          <div className="flex items-start justify-between gap-4">
            <div className="flex flex-col gap-1.5">
              <label htmlFor="auto-issues" className="text-[13px] font-semibold">
                {t("mappings.form.autoCreate")}
              </label>
              <p id="auto-issues-help" className="text-[12.5px] text-muted">
                {t("mappings.form.autoCreateHelp")}
              </p>
            </div>
            <Switch id="auto-issues" checked={values.autoCreate} onCheckedChange={(checked) => set("autoCreate", checked)} />
          </div>
          <div className="flex flex-col gap-1.5">
            <span id="min-severity-label" className="text-[13px] font-semibold">
              {t("mappings.form.minSeverity")}
            </span>
            <Segmented
              label={t("mappings.form.minSeverity")}
              value={values.minSeverity}
              disabled={!values.autoCreate}
              onChange={(value) => set("minSeverity", value === "CRITICAL" ? "CRITICAL" : "HIGH")}
              options={[
                { value: "HIGH", label: t("mappings.form.sevHigh") },
                { value: "CRITICAL", label: t("mappings.form.sevCritical") },
              ]}
            />
          </div>
        </Card>
      </fieldset>

      {serverError === null ? null : (
        <p role="alert" className="text-[13px] text-crit-ink">
          {serverError}
        </p>
      )}

      {readOnly ? null : (
        <div className="flex flex-wrap justify-end gap-2.5">
          <Link to="/mappings" className={buttonClass("default")}>
            {t("mappings.cancel")}
          </Link>
          <Button type="submit" variant="primary" disabled={!canSave}>
            {t("mappings.form.save")}
          </Button>
        </div>
      )}
    </form>
  );
}
