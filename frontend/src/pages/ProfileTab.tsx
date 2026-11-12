import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { useNavigate } from "react-router";
import { PasswordCard } from "../components/account/PasswordCard";
import { TotpCard } from "../components/account/TotpCard";
import { CardHeading, ConfirmDialog } from "../components/admin/parts";
import { Button } from "../components/ui/Button";
import { Card } from "../components/ui/Card";
import { LoadingMessage } from "../components/ui/StatusMessage";
import { t } from "../i18n";
import { api } from "../lib/api";
import { useMe } from "../lib/session";

function ProfileRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex flex-col gap-0.5">
      <dt className="text-xs text-muted">{label}</dt>
      <dd className="m-0 text-[13px]">{value}</dd>
    </div>
  );
}

// Profile tab: the profile, the password and two-factor sign-in (local accounts
// only), and sign out everywhere.
export function ProfileTab() {
  const me = useMe();
  const queryClient = useQueryClient();
  const navigate = useNavigate();
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
      {isLocal ? <TotpCard /> : null}

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
      <ConfirmDialog
        open={confirmOut}
        onOpenChange={setConfirmOut}
        title={t("account.signOutAll.confirmTitle")}
        description={t("account.signOutAll.confirmBody")}
        confirmLabel={t("account.signOutAll.title")}
        busy={signOutAll.isPending}
        onConfirm={() => signOutAll.mutate()}
      />
    </div>
  );
}
