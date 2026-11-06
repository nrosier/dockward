import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Link } from "react-router";
import { t } from "../../i18n";
import { api } from "../../lib/api";
import type { Credential, Page, TestResult } from "../../types/api";
import { Badge, CardHeading, daysLeft, formatDate, messageOf, statusOf, Tag, TD, TH, ROW, ConfirmDialog, FormError } from "../admin/parts";
import { Button, buttonClass } from "../ui/Button";
import { Card } from "../ui/Card";
import { Dialog } from "../ui/Dialog";
import { ChecksList } from "./ChecksList";

const WARNING_DAYS = 14;
export const CREDENTIALS_KEY = ["credentials"] as const;

function ExpiryCell({ credential }: { credential: Credential }) {
  if (credential.expires_at === null) {
    return <span className="text-muted">{t("account.credentials.noExpiry")}</span>;
  }
  const left = daysLeft(credential.expires_at);
  const date = formatDate(credential.expires_at);
  if (left !== null && left <= WARNING_DAYS) {
    return (
      <div className="flex flex-col gap-1">
        <Badge tone="warn">{t("account.credentials.days", { n: Math.max(left, 0) })}</Badge>
        <span className="text-muted">{date}</span>
      </div>
    );
  }
  return <span className="text-muted">{date}</span>;
}

function TestDialog({ credential, onClose }: { credential: Credential; onClose: () => void }) {
  const test = useMutation({
    mutationFn: () => api<TestResult>("POST", `/credentials/${credential.id}/test`),
  });
  return (
    <Dialog
      open
      onOpenChange={(open) => (open ? undefined : onClose())}
      title={t("account.credentials.testTitle", { label: credential.label })}
    >
      {test.isError ? (
        <FormError message={statusOf(test.error) === 502 ? t("credentials.test.unreachable") : messageOf(test.error)} />
      ) : null}
      {test.data?.repository ? (
        <p className="m-0 text-[13px]">{t("credentials.test.repository", { name: test.data.repository })}</p>
      ) : null}
      {test.data ? <ChecksList checks={test.data.checks} /> : null}
      <div className="flex justify-end gap-2.5">
        <Button onClick={onClose}>{t("common.close")}</Button>
        <Button variant="primary" disabled={test.isPending} onClick={() => test.mutate()}>
          {test.data || test.isError ? t("credentials.test.again") : t("account.credentials.test")}
        </Button>
      </div>
    </Dialog>
  );
}

export function CredentialsCard() {
  const queryClient = useQueryClient();
  const list = useQuery({
    queryKey: CREDENTIALS_KEY,
    queryFn: () => api<Page<Credential>>("GET", "/credentials?page_size=200"),
  });
  const [testing, setTesting] = useState<Credential | null>(null);
  const [deleting, setDeleting] = useState<Credential | null>(null);
  const [deleteError, setDeleteError] = useState<string | null>(null);

  const remove = useMutation({
    mutationFn: (id: string) => api<void>("DELETE", `/credentials/${id}`),
    onSuccess: () => {
      setDeleting(null);
      void queryClient.invalidateQueries({ queryKey: CREDENTIALS_KEY });
    },
    onError: (failure) =>
      setDeleteError(statusOf(failure) === 409 ? t("account.credentials.inUse") : messageOf(failure)),
  });

  return (
    <Card className="flex flex-col gap-4 py-5" aria-labelledby="account-credentials">
      <div className="px-5">
        <CardHeading
          id="account-credentials"
          title={t("account.credentials.title")}
          help={t("account.credentials.help")}
          action={
            <Link to="/account/credentials/new" className={buttonClass("primary")}>
              {t("account.credentials.add")}
            </Link>
          }
        />
      </div>
      {list.isPending ? <p className="px-5 text-muted">{t("common.loading")}</p> : null}
      {list.isError ? <FormError message={t("errors.generic")} /> : null}
      {list.data ? (
        <div className="overflow-x-auto">
          <table className="w-full border-collapse">
            <thead>
              <tr>
                <th className={TH}>{t("account.credentials.label")}</th>
                <th className={TH}>{t("account.credentials.service")}</th>
                <th className={TH}>{t("account.credentials.baseUrl")}</th>
                <th className={TH}>{t("account.credentials.expires")}</th>
                <th className={TH}>{t("account.credentials.usedBy")}</th>
                <th className={TH}>
                  <span className="sr-only">{t("account.credentials.actions")}</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {list.data.items.map((credential) => (
                <tr key={credential.id} className={ROW}>
                  <td className={TD}>{credential.label}</td>
                  <td className={TD}>
                    <Tag>
                      {credential.service_type === "harbor"
                        ? t("credentials.service.harbor")
                        : t("credentials.service.github")}
                    </Tag>
                  </td>
                  <td className={`${TD} font-mono text-xs`}>{credential.base_url ?? ""}</td>
                  <td className={TD}>
                    <ExpiryCell credential={credential} />
                  </td>
                  <td className={`${TD} text-muted`}>
                    {(credential.mapping_count ?? 0) > 0
                      ? t("account.credentials.mappings", { n: credential.mapping_count ?? 0 })
                      : t("account.credentials.notUsed")}
                  </td>
                  <td className={TD}>
                    <div className="flex gap-1.5">
                      <Button
                        variant="small"
                        aria-label={t("account.credentials.testAria", { label: credential.label })}
                        onClick={() => setTesting(credential)}
                      >
                        {t("account.credentials.test")}
                      </Button>
                      <Link
                        to={`/account/credentials/${credential.id}`}
                        aria-label={t("account.credentials.editAria", { label: credential.label })}
                        className={buttonClass("small")}
                      >
                        {t("account.credentials.edit")}
                      </Link>
                      <Button
                        variant="small"
                        aria-label={t("account.credentials.deleteAria", { label: credential.label })}
                        onClick={() => {
                          setDeleteError(null);
                          setDeleting(credential);
                        }}
                      >
                        {t("account.credentials.delete")}
                      </Button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}
      {testing === null ? null : <TestDialog credential={testing} onClose={() => setTesting(null)} />}
      <ConfirmDialog
        open={deleting !== null}
        onOpenChange={(open) => (open ? undefined : setDeleting(null))}
        title={t("account.credentials.deleteTitle", { label: deleting?.label ?? "" })}
        description={t("account.credentials.deleteBody")}
        confirmLabel={t("account.credentials.delete")}
        busy={remove.isPending}
        error={deleteError}
        onConfirm={() => deleting && remove.mutate(deleting.id)}
      />
    </Card>
  );
}
