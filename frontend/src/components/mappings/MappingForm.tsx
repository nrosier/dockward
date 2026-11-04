import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState, type FormEvent, type ReactNode } from "react";
import { Link, useNavigate } from "react-router";
import { t } from "../../i18n";
import { ApiError, api } from "../../lib/api";
import type { Credential, IssueSeverity, Mapping, MappingCreated, MappingListItem, Page } from "../../types/api";
import { Button, buttonClass } from "../ui/Button";
import { Card } from "../ui/Card";
import { Field } from "../ui/Field";
import { Switch } from "../ui/Switch";
import { Segmented } from "./Segmented";
import { INPUT, INPUT_INVALID, LINK } from "./styles";
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

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <Card className="m-0 flex min-w-0 flex-col gap-[18px] px-[22px] py-5">
      <fieldset className="m-0 flex min-w-0 flex-col gap-[18px] border-0 p-0">
        <legend className="float-left mb-0.5 text-[15px] font-semibold">{title}</legend>
        <div className="clear-both flex flex-col gap-[18px]">{children}</div>
      </fieldset>
    </Card>
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
        <Section title={t("mappings.form.harborSection")}>
          <Field id="harbor-project" label={t("mappings.form.harborProject")}>
            <input
              id="harbor-project"
              value={values.harborProject}
              onChange={(event) => set("harborProject", event.target.value)}
              className={INPUT}
            />
          </Field>
          <Field
            id="harbor-repository"
            label={t("mappings.form.harborRepository")}
            help={t("mappings.form.harborRepositoryHelp")}
            error={
              harborClash === undefined
                ? undefined
                : t("mappings.form.duplicate", { name: mappingName(harborClash) })
            }
          >
            <input
              id="harbor-repository"
              value={values.harborRepository}
              onChange={(event) => set("harborRepository", event.target.value)}
              aria-invalid={harborClash !== undefined}
              aria-describedby={
                harborClash === undefined ? "harbor-repository-help" : "harbor-repository-help harbor-repository-error"
              }
              className={`${INPUT} ${harborClash === undefined ? "" : INPUT_INVALID}`}
            />
          </Field>
          <CredentialSelect
            id="harbor-cred"
            label={t("mappings.form.harborCredential")}
            type="harbor"
            value={values.harborCredId}
            onChange={(value) => set("harborCredId", value)}
            help={
              <p className="text-[12.5px] text-muted">
                {t("mappings.form.credentialHelpBefore")}{" "}
                <Link to="/account" className={LINK}>
                  {t("nav.account")}
                </Link>{" "}
                {t("mappings.form.credentialHelpAfter")}
              </p>
            }
          />
        </Section>

        <Section title={t("mappings.form.githubSection")}>
          <CredentialSelect
            id="github-cred"
            label={t("mappings.form.githubCredential")}
            type="github"
            value={values.githubCredId}
            onChange={(value) => set("githubCredId", value)}
          />
          <Field id="github-owner" label={t("mappings.form.githubOwner")}>
            <input
              id="github-owner"
              value={values.githubOwner}
              onChange={(event) => set("githubOwner", event.target.value)}
              className={INPUT}
            />
          </Field>
          <Field
            id="github-repo"
            label={t("mappings.form.githubRepository")}
            error={
              githubClash === undefined ? undefined : t("mappings.form.duplicate", { name: mappingName(githubClash) })
            }
          >
            <input
              id="github-repo"
              value={values.githubRepo}
              onChange={(event) => set("githubRepo", event.target.value)}
              aria-invalid={githubClash !== undefined}
              aria-describedby={githubClash === undefined ? undefined : "github-repo-error"}
              className={`${INPUT} ${githubClash === undefined ? "" : INPUT_INVALID}`}
            />
          </Field>
          <Field id="default-branch" label={t("mappings.form.defaultBranch")} help={t("mappings.form.defaultBranchHelp")}>
            <input
              id="default-branch"
              value={values.defaultBranch}
              onChange={(event) => set("defaultBranch", event.target.value)}
              aria-describedby="default-branch-help"
              className={INPUT}
            />
          </Field>
        </Section>

        <Section title={t("mappings.form.issuesSection")}>
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
        </Section>
      </fieldset>

      {serverError === null ? null : (
        <p role="alert" className="text-[13px] text-crit-ink">
          {serverError}
        </p>
      )}

      {readOnly ? (
        <p className="text-[13px] text-muted">{t("mappings.form.readOnly")}</p>
      ) : (
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
