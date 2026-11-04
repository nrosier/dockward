import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState, type FormEvent } from "react";
import { CardHeading, FormError, INPUT, messageOf, statusOf } from "../components/admin/parts";
import { Button } from "../components/ui/Button";
import { Card } from "../components/ui/Card";
import { CopyField } from "../components/ui/CopyField";
import { Field } from "../components/ui/Field";
import { ErrorMessage, LoadingMessage } from "../components/ui/StatusMessage";
import { Switch } from "../components/ui/Switch";
import { t } from "../i18n";
import { api } from "../lib/api";
import type { OidcSettings } from "../types/api";

export const OIDC_KEY = ["admin", "oidc"] as const;

export default function AdminOidcPage() {
  const settings = useQuery({ queryKey: OIDC_KEY, queryFn: () => api<OidcSettings>("GET", "/admin/oidc") });
  if (settings.isPending) {
    return <LoadingMessage />;
  }
  if (settings.isError || !settings.data) {
    return <ErrorMessage />;
  }
  // The form is seeded once. "Discard changes" resets it to the saved values.
  return <OidcForm data={settings.data} />;
}

function OidcForm({ data }: { data: OidcSettings }) {
  const queryClient = useQueryClient();
  const [issuer, setIssuer] = useState(data.issuer_url ?? "");
  const [clientId, setClientId] = useState(data.client_id ?? "");
  const [secret, setSecret] = useState("");
  const [claim, setClaim] = useState(data.role_claim ?? "");
  const [adminGroup, setAdminGroup] = useState(data.admin_group ?? "");
  const [userGroup, setUserGroup] = useState(data.user_group ?? "");
  const [only, setOnly] = useState(data.oidc_only_users);
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);

  function reset(source: OidcSettings) {
    setIssuer(source.issuer_url ?? "");
    setClientId(source.client_id ?? "");
    setClaim(source.role_claim ?? "");
    setAdminGroup(source.admin_group ?? "");
    setUserGroup(source.user_group ?? "");
    setOnly(source.oidc_only_users);
    setSecret("");
  }

  const save = useMutation({
    mutationFn: () => {
      const body: Record<string, unknown> = {
        issuer_url: issuer.trim(),
        client_id: clientId.trim(),
        role_claim: claim.trim(),
        admin_group: adminGroup.trim(),
        user_group: userGroup.trim(),
        oidc_only_users: only,
      };
      if (secret !== "") {
        body.client_secret = secret;
      }
      return api<OidcSettings>("PUT", "/admin/oidc", body);
    },
    onSuccess: (next) => {
      setSecret("");
      setError(null);
      setSaved(true);
      queryClient.setQueryData(OIDC_KEY, next);
    },
    onError: (failure) => {
      setSecret("");
      setSaved(false);
      setError(statusOf(failure) === 422 ? messageOf(failure) : t("errors.generic"));
    },
  });

  function submit(event: FormEvent) {
    event.preventDefault();
    setSaved(false);
    setError(null);
    save.mutate();
  }

  return (
    <form onSubmit={submit} className="flex flex-col gap-5">
      <Card className="flex flex-col gap-4 p-5" aria-labelledby="oidc-idp">
        <CardHeading id="oidc-idp" title={t("admin.oidc.idp")} />
        <Field id="oidc-redirect" label={t("admin.oidc.redirect")} help={t("admin.oidc.redirectHelp")}>
          <CopyField
            id="oidc-redirect"
            label={t("admin.oidc.redirect")}
            value={`${window.location.origin}/api/v1/auth/oidc/callback`}
          />
        </Field>
        <Field id="oidc-issuer" label={t("admin.oidc.issuer")} help={t("admin.oidc.issuerHelp")}>
          <input id="oidc-issuer" className={INPUT} value={issuer} onChange={(e) => setIssuer(e.target.value)} />
        </Field>
        <Field id="oidc-client" label={t("admin.oidc.clientId")}>
          <input id="oidc-client" className={INPUT} value={clientId} onChange={(e) => setClientId(e.target.value)} />
        </Field>
        <Field
          id="oidc-secret"
          label={t("admin.oidc.secret")}
          help={data.client_secret_set ? t("admin.oidc.secretSet") : undefined}
        >
          <input
            id="oidc-secret"
            className={INPUT}
            type="password"
            autoComplete="off"
            placeholder={data.client_secret_set ? t("admin.oidc.secretPlaceholder") : undefined}
            value={secret}
            onChange={(e) => setSecret(e.target.value)}
          />
        </Field>
      </Card>

      <Card className="flex flex-col gap-4 p-5" aria-labelledby="oidc-roles">
        <CardHeading id="oidc-roles" title={t("admin.oidc.roles")} help={t("admin.oidc.rolesHelp")} />
        <Field id="oidc-claim" label={t("admin.oidc.claim")}>
          <input id="oidc-claim" className={INPUT} value={claim} onChange={(e) => setClaim(e.target.value)} />
        </Field>
        <Field id="oidc-admin-group" label={t("admin.oidc.adminGroup")}>
          <input
            id="oidc-admin-group"
            className={INPUT}
            value={adminGroup}
            onChange={(e) => setAdminGroup(e.target.value)}
          />
        </Field>
        <Field id="oidc-user-group" label={t("admin.oidc.userGroup")}>
          <input
            id="oidc-user-group"
            className={INPUT}
            value={userGroup}
            onChange={(e) => setUserGroup(e.target.value)}
          />
        </Field>
      </Card>

      <Card className="flex items-start justify-between gap-4 p-5" aria-labelledby="oidc-only-label">
        <div className="flex flex-col gap-1">
          <label id="oidc-only-label" htmlFor="oidc-only" className="text-[13px] font-semibold">
            {t("admin.oidc.only")}
          </label>
          <span className="text-[12.5px] text-muted">{t("admin.oidc.onlyHelp")}</span>
        </div>
        <Switch id="oidc-only" checked={only} onCheckedChange={setOnly} />
      </Card>

      <FormError message={error} />
      {saved ? <output className="text-[13px] text-ok-ink">{t("admin.oidc.saved")}</output> : null}
      <div className="flex flex-wrap justify-end gap-2.5">
        <Button
          onClick={() => {
            reset(data);
            setError(null);
            setSaved(false);
          }}
        >
          {t("admin.oidc.discard")}
        </Button>
        <Button type="submit" variant="primary" disabled={save.isPending}>
          {t("admin.oidc.save")}
        </Button>
      </div>
    </form>
  );
}
