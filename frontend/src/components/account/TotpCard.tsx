import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { t } from "../../i18n";
import { api } from "../../lib/api";
import { CardHeading, FormError } from "../admin/parts";
import { Button } from "../ui/Button";
import { Card } from "../ui/Card";
import { Pill } from "../ui/Pill";
import { TotpDisableDialog } from "./TotpDisableDialog";
import { TotpEnrolDialog } from "./TotpEnrolDialog";

export const TOTP_QUERY_KEY = ["account", "totp"] as const;

// Local accounts only (the API answers 403 for OIDC). Shows whether TOTP is on,
// and opens the enrolment or the turn-off dialog.
export function TotpCard() {
  const queryClient = useQueryClient();
  const status = useQuery({
    queryKey: TOTP_QUERY_KEY,
    queryFn: () => api<{ enabled: boolean }>("GET", "/account/totp"),
  });
  const [enrolling, setEnrolling] = useState(false);
  const [disabling, setDisabling] = useState(false);
  const [done, setDone] = useState(false);

  const enabled = status.data?.enabled === true;

  function refresh(next: boolean) {
    queryClient.setQueryData(TOTP_QUERY_KEY, { enabled: next });
    void queryClient.invalidateQueries({ queryKey: TOTP_QUERY_KEY });
  }

  return (
    <Card className="flex flex-col gap-4 p-5" aria-labelledby="account-totp">
      <CardHeading
        id="account-totp"
        title={t("account.totp.title")}
        help={status.isSuccess ? t(enabled ? "account.totp.helpOn" : "account.totp.helpOff") : undefined}
        action={enabled ? <Pill kind="fixed" label={t("account.totp.statusOn")} /> : undefined}
      />
      {status.isPending ? <output className="text-[13px] text-muted">{t("common.loading")}</output> : null}
      {status.isError ? <FormError message={t("errors.generic")} /> : null}
      {done ? <output className="text-[13px] text-ok-ink">{t("account.totp.disable.done")}</output> : null}
      {status.isSuccess ? (
        <div>
          {enabled ? (
            <Button
              variant="danger"
              onClick={() => {
                setDone(false);
                setDisabling(true);
              }}
            >
              {t("account.totp.disable")}
            </Button>
          ) : (
            <Button
              variant="primary"
              onClick={() => {
                setDone(false);
                setEnrolling(true);
              }}
            >
              {t("account.totp.setup")}
            </Button>
          )}
        </div>
      ) : null}
      {enrolling ? (
        <TotpEnrolDialog
          onEnabled={() => refresh(true)}
          onClose={() => setEnrolling(false)}
        />
      ) : null}
      {disabling ? (
        <TotpDisableDialog
          onDisabled={() => {
            refresh(false);
            setDisabling(false);
            setDone(true);
          }}
          onClose={() => setDisabling(false)}
        />
      ) : null}
    </Card>
  );
}
