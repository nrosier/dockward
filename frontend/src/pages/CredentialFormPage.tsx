import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState, type FormEvent } from "react";
import { Link, useNavigate, useParams } from "react-router";
import { ChecksList } from "../components/account/ChecksList";
import { CREDENTIALS_KEY } from "../components/account/CredentialsCard";
import { FormError, INPUT, messageOf, Segmented, statusOf } from "../components/admin/parts";
import { Button, buttonClass } from "../components/ui/Button";
import { Card } from "../components/ui/Card";
import { Field } from "../components/ui/Field";
import { PageTitle } from "../components/ui/PageTitle";
import { LoadingMessage } from "../components/ui/StatusMessage";
import { t } from "../i18n";
import { api } from "../lib/api";
import type { Credential, Page, TestResult } from "../types/api";

type Service = "harbor" | "github";

// "2027-11-03" becomes the end of that day in UTC, as a unix timestamp.
function endOfDayUnix(date: string): number | null {
  const ms = Date.parse(`${date}T23:59:59Z`);
  return Number.isNaN(ms) ? null : Math.floor(ms / 1000);
}

export default function CredentialFormPage() {
  const { id } = useParams();
  const existing = useQuery({
    queryKey: [...CREDENTIALS_KEY, "form", id],
    enabled: id !== undefined,
    queryFn: async () => {
      const page = await api<Page<Credential>>("GET", "/credentials?page_size=200");
      return page.items.find((item) => item.id === id) ?? null;
    },
  });
  if (id !== undefined && existing.isPending) {
    return <LoadingMessage />;
  }
  if (id !== undefined && !existing.data) {
    return <FormError message={t("errors.notFound.body")} />;
  }
  return <CredentialForm id={id} loaded={existing.data ?? null} />;
}

function CredentialForm({ id, loaded }: { id: string | undefined; loaded: Credential | null }) {
  const editing = id !== undefined;
  const queryClient = useQueryClient();
  const navigate = useNavigate();

  const [service, setService] = useState<Service>(loaded?.service_type ?? "harbor");
  const [label, setLabel] = useState(loaded?.label ?? "");
  const [baseUrl, setBaseUrl] = useState(loaded?.base_url ?? "");
  const [username, setUsername] = useState(loaded?.username ?? "");
  const [token, setToken] = useState("");
  const [expires, setExpires] = useState(loaded?.expires_at ? loaded.expires_at.slice(0, 10) : "");
  const [owner, setOwner] = useState("");
  const [repo, setRepo] = useState("");
  const [savedId, setSavedId] = useState<string | null>(id ?? null);
  const [saveError, setSaveError] = useState<string | null>(null);
  const [result, setResult] = useState<TestResult | null>(null);
  const [testError, setTestError] = useState<string | null>(null);

  const runTest = useMutation({
    mutationFn: (credentialId: string) =>
      api<TestResult>(
        "POST",
        `/credentials/${credentialId}/test`,
        service === "github" ? { owner: owner.trim(), repo: repo.trim() } : undefined,
      ),
    onSuccess: (body) => {
      setResult(body);
      setTestError(null);
    },
    onError: (failure) => {
      setResult(null);
      setTestError(statusOf(failure) === 502 ? t("credentials.test.unreachable") : messageOf(failure));
    },
  });

  const save = useMutation({
    mutationFn: async () => {
      const body: Record<string, unknown> = { label: label.trim() };
      if (service === "harbor") {
        if (loaded === null || baseUrl.trim() !== loaded.base_url) {
          body.base_url = baseUrl.trim();
        }
        body.username = username.trim();
      }
      if (token !== "") {
        body.token = token;
      }
      if (expires !== "") {
        body.expires_at = endOfDayUnix(expires);
      }
      if (savedId === null) {
        body.service_type = service;
        return api<Credential>("POST", "/credentials", { token: "", ...body });
      }
      return api<Credential>("PUT", `/credentials/${savedId}`, body);
    },
    onSuccess: (credential) => {
      // The secret is never kept after the request resolves.
      setToken("");
      setSaveError(null);
      setSavedId(credential.id);
      void queryClient.invalidateQueries({ queryKey: CREDENTIALS_KEY });
      runTest.mutate(credential.id);
    },
    onError: (failure) => {
      setToken("");
      setResult(null);
      setSaveError(statusOf(failure) === 422 ? messageOf(failure) : messageOf(failure));
    },
  });

  const isGithub = service === "github";
  const canSubmit =
    label.trim() !== "" &&
    (editing || token !== "") &&
    (isGithub ? owner.trim() !== "" && repo.trim() !== "" : baseUrl.trim() !== "" && username.trim() !== "") &&
    !save.isPending;

  function submit(event: FormEvent) {
    event.preventDefault();
    if (canSubmit) {
      setSaveError(null);
      save.mutate();
    }
  }

  const tested = result !== null || testError !== null;

  return (
    <div className="flex flex-col gap-5">
      <div className="flex flex-col gap-1">
        <Link to="/account" className="text-[13px] text-accent hover:underline">
          {t("credentials.back")}
        </Link>
        <PageTitle title={editing ? t("page.credentialEdit") : t("page.credentialNew")} />
      </div>
      <form onSubmit={submit} className="flex flex-col gap-5">
        <Card className="flex flex-col gap-4 p-5">
          <div className="flex flex-col gap-1.5">
            <span id="cred-service" className="text-[13px] font-semibold">
              {t("credentials.form.service")}
            </span>
            <Segmented
              labelId="cred-service"
              value={service}
              disabled={editing}
              onChange={(value) => setService(value === "github" ? "github" : "harbor")}
              options={[
                { value: "harbor", label: t("credentials.service.harbor") },
                { value: "github", label: t("credentials.service.github") },
              ]}
            />
          </div>
          <Field id="cred-label" label={t("credentials.form.label")} help={t("credentials.form.labelHelp")}>
            <input id="cred-label" className={INPUT} value={label} onChange={(event) => setLabel(event.target.value)} />
          </Field>
          {isGithub ? null : (
            <>
              <Field id="cred-url" label={t("credentials.form.baseUrl")} help={t("credentials.form.baseUrlHelp")}>
                <input
                  id="cred-url"
                  className={INPUT}
                  value={baseUrl}
                  onChange={(event) => setBaseUrl(event.target.value)}
                />
              </Field>
              <Field id="cred-user" label={t("credentials.form.robot")}>
                <input
                  id="cred-user"
                  className={INPUT}
                  autoComplete="off"
                  value={username}
                  onChange={(event) => setUsername(event.target.value)}
                />
              </Field>
            </>
          )}
          <Field
            id="cred-token"
            label={isGithub ? t("credentials.form.githubToken") : t("credentials.form.robotSecret")}
            help={t("credentials.form.tokenHelp")}
          >
            <input
              id="cred-token"
              className={INPUT}
              type="password"
              autoComplete="off"
              placeholder={editing ? t("credentials.form.keepToken") : undefined}
              aria-describedby="cred-token-help"
              value={token}
              onChange={(event) => setToken(event.target.value)}
            />
          </Field>
          <Field id="cred-expires" label={t("credentials.form.expires")} help={t("credentials.form.expiresHelp")}>
            <input
              id="cred-expires"
              className={INPUT}
              type="date"
              value={expires}
              onChange={(event) => setExpires(event.target.value)}
            />
          </Field>
          {isGithub ? (
            <>
              <Field id="cred-owner" label={t("credentials.form.owner")} help={t("credentials.form.testOnlyHelp")}>
                <input
                  id="cred-owner"
                  className={INPUT}
                  value={owner}
                  onChange={(event) => setOwner(event.target.value)}
                />
              </Field>
              <Field id="cred-repo" label={t("credentials.form.repo")}>
                <input id="cred-repo" className={INPUT} value={repo} onChange={(event) => setRepo(event.target.value)} />
              </Field>
            </>
          ) : null}
        </Card>

        {tested ? (
          <Card className="flex flex-col gap-3 p-5" aria-labelledby="cred-test">
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div className="flex flex-col gap-1">
                <h2 id="cred-test" className="text-[15px] font-semibold">
                  {t("credentials.test.title")}
                </h2>
                <span className="text-[12.5px] text-muted">{t("credentials.test.saved")}</span>
              </div>
              <Button disabled={savedId === null || runTest.isPending} onClick={() => savedId && runTest.mutate(savedId)}>
                {t("credentials.test.again")}
              </Button>
            </div>
            {result ? <ChecksList checks={result.checks} /> : null}
            <FormError message={testError} />
          </Card>
        ) : null}

        <FormError message={saveError} />
        <div className="flex flex-wrap items-center justify-end gap-3">
          {tested ? (
            <Link to="/account" className={buttonClass("primary")}>
              {t("credentials.done")}
            </Link>
          ) : null}
          <Button type="submit" variant={tested ? "default" : "primary"} disabled={!canSubmit}>
            {save.isPending ? t("credentials.saving") : t("credentials.saveAndTest")}
          </Button>
          <Button onClick={() => void navigate("/account")}>{t("common.cancel")}</Button>
        </div>
      </form>
    </div>
  );
}
