import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { useNavigate } from "react-router";
import { CredentialsCard } from "../components/account/CredentialsCard";
import { PasswordCard } from "../components/account/PasswordCard";
import { CardHeading, ConfirmDialog, INPUT, Segmented } from "../components/admin/parts";
import { Button } from "../components/ui/Button";
import { Card } from "../components/ui/Card";
import { Field } from "../components/ui/Field";
import { LoadingMessage } from "../components/ui/StatusMessage";
import { PageTitle } from "../components/ui/PageTitle";
import { t } from "../i18n";
import { api } from "../lib/api";
import { getLanguage, getTheme, setLanguage, setTheme, type Language, type Theme } from "../lib/preferences";
import { useMe } from "../lib/session";

function ProfileRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex flex-col gap-0.5">
      <dt className="text-xs text-muted">{label}</dt>
      <dd className="m-0 text-[13px]">{value}</dd>
    </div>
  );
}

export default function AccountPage() {
  const me = useMe();
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const [theme, setThemeState] = useState<Theme>(getTheme);
  const [language, setLanguageState] = useState<Language>(getLanguage);
  const [confirmOut, setConfirmOut] = useState(false);

  const signOutAll = useMutation({
    mutationFn: () => api<void>("POST", "/auth/logout-all"),
    onSettled: () => {
      queryClient.clear();
      void navigate("/login", { replace: true });
    },
  });

  const user = me.data;
  if (!user) {
    return <LoadingMessage />;
  }
  const isLocal = user.auth_provider === "local";

  return (
    <div className="flex flex-col gap-5">
      <div className="flex flex-col gap-1">
        <PageTitle title={t("page.account")} />
        <p className="text-muted">{t("account.intro")}</p>
      </div>

      <Card className="flex flex-col gap-4 p-5" aria-labelledby="account-profile">
        <CardHeading id="account-profile" title={t("account.profile.title")} />
        <dl className="m-0 grid grid-cols-1 gap-4 sm:grid-cols-4">
          <ProfileRow label={t("account.profile.username")} value={user.username} />
          <ProfileRow label={t("account.profile.email")} value={user.email} />
          <ProfileRow label={t("account.profile.role")} value={t(user.role === "admin" ? "role.admin" : "role.user")} />
          <ProfileRow
            label={t("account.profile.signIn")}
            value={isLocal ? t("account.profile.local") : t("account.profile.sso")}
          />
        </dl>
      </Card>

      {isLocal ? <PasswordCard /> : null}

      <Card className="flex flex-wrap items-center justify-between gap-4 p-5" aria-labelledby="account-signout">
        <div className="flex flex-col gap-1">
          <h2 id="account-signout" className="text-[13px] font-semibold">
            {t("account.signOutAll.title")}
          </h2>
          <p className="text-[12.5px] text-muted">{t("account.signOutAll.help")}</p>
        </div>
        <Button variant="danger" onClick={() => setConfirmOut(true)}>
          {t("account.signOutAll.title")}
        </Button>
      </Card>
      <ConfirmDialog
        open={confirmOut}
        onOpenChange={setConfirmOut}
        title={t("account.signOutAll.confirmTitle")}
        description={t("account.signOutAll.confirmBody")}
        confirmLabel={t("account.signOutAll.title")}
        busy={signOutAll.isPending}
        onConfirm={() => signOutAll.mutate()}
      />

      <Card className="flex flex-col gap-4 p-5" aria-labelledby="account-appearance">
        <CardHeading id="account-appearance" title={t("account.appearance.title")} help={t("account.appearance.help")} />
        <div className="flex flex-col gap-1.5">
          <span id="account-theme" className="text-[13px] font-semibold">
            {t("account.appearance.theme")}
          </span>
          <Segmented
            labelId="account-theme"
            value={theme}
            onChange={(value) => {
              const next: Theme = value === "light" ? "light" : "dark";
              setTheme(next);
              setThemeState(next);
            }}
            options={[
              { value: "dark", label: t("account.appearance.dark") },
              { value: "light", label: t("account.appearance.light") },
            ]}
          />
        </div>
        <Field id="account-language" label={t("account.appearance.language")}>
          <select
            id="account-language"
            className={INPUT}
            value={language}
            onChange={() => {
              setLanguage("en");
              setLanguageState("en");
            }}
          >
            <option value="en">{t("account.appearance.english")}</option>
          </select>
        </Field>
      </Card>

      <CredentialsCard />
    </div>
  );
}
