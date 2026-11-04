import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState, type FormEvent } from "react";
import { CardHeading, ConfirmDialog, FormError, formatDate, INPUT, messageOf, ROW, statusOf, Tag, TD, TH } from "../components/admin/parts";
import { Button } from "../components/ui/Button";
import { Card } from "../components/ui/Card";
import { Field } from "../components/ui/Field";
import { ErrorMessage, LoadingMessage } from "../components/ui/StatusMessage";
import { t } from "../i18n";
import { api } from "../lib/api";
import { useMe, type Role, type User } from "../lib/session";
import type { OidcSettings } from "../types/api";
import { OIDC_KEY } from "./AdminOidcPage";

const USERS_KEY = ["admin", "users", "all"] as const;
const MIN_LENGTH = 15;
const MAX_LENGTH = 64;

function roleLabel(role: Role): string {
  return role === "admin" ? t("role.admin") : t("role.user");
}

function RoleSelect({ user, onError }: { user: User; onError: (message: string | null) => void }) {
  const queryClient = useQueryClient();
  const [value, setValue] = useState<Role>(user.role);
  const change = useMutation({
    mutationFn: (role: Role) => api<User>("PUT", `/admin/users/${user.id}/role`, { role }),
    onSuccess: () => {
      onError(null);
      void queryClient.invalidateQueries({ queryKey: USERS_KEY });
    },
    onError: (failure) => {
      // The select goes back to the saved role.
      setValue(user.role);
      onError(statusOf(failure) === 409 ? t("admin.users.lastAdmin") : messageOf(failure));
    },
  });
  return (
    <>
      <label htmlFor={`role-${user.id}`} className="sr-only">
        {t("admin.users.roleFor", { name: user.username })}
      </label>
      <select
        id={`role-${user.id}`}
        className={`${INPUT} w-auto`}
        value={value}
        disabled={change.isPending}
        onChange={(event) => {
          const next: Role = event.target.value === "admin" ? "admin" : "user";
          setValue(next);
          change.mutate(next);
        }}
      >
        <option value="user">{t("role.user")}</option>
        <option value="admin">{t("role.admin")}</option>
      </select>
    </>
  );
}

function CreateUserCard() {
  const queryClient = useQueryClient();
  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState<Role>("user");
  const [error, setError] = useState<string | null>(null);
  const [created, setCreated] = useState(false);

  const create = useMutation({
    mutationFn: (body: { username: string; email: string; password: string; role: Role }) =>
      api<User>("POST", "/admin/users", body),
    onSuccess: () => {
      setUsername("");
      setEmail("");
      setRole("user");
      setError(null);
      setCreated(true);
      void queryClient.invalidateQueries({ queryKey: USERS_KEY });
    },
    onError: (failure) => {
      setCreated(false);
      setError(messageOf(failure));
    },
  });

  const length = [...password].length;
  const canSubmit = username.trim() !== "" && length >= MIN_LENGTH && length <= MAX_LENGTH && !create.isPending;

  function submit(event: FormEvent) {
    event.preventDefault();
    if (!canSubmit) {
      return;
    }
    setCreated(false);
    create.mutate({ username: username.trim(), email: email.trim(), password, role });
    // The password is cleared as soon as it is sent.
    setPassword("");
  }

  return (
    <Card className="p-5" aria-labelledby="users-create">
      <form onSubmit={submit} className="flex flex-col gap-4">
        <CardHeading id="users-create" title={t("admin.users.create")} help={t("admin.users.createHelp")} />
        <Field id="new-username" label={t("admin.users.username")}>
          <input id="new-username" className={INPUT} autoComplete="off" value={username} onChange={(e) => setUsername(e.target.value)} />
        </Field>
        <Field id="new-email" label={t("admin.users.email")}>
          <input id="new-email" className={INPUT} type="email" autoComplete="off" value={email} onChange={(e) => setEmail(e.target.value)} />
        </Field>
        <Field id="new-password" label={t("admin.users.password")} help={t("admin.users.passwordHelp")}>
          <input
            id="new-password"
            className={INPUT}
            type="password"
            autoComplete="new-password"
            aria-describedby="new-password-help"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
        </Field>
        <Field id="new-role" label={t("admin.users.role")}>
          <select id="new-role" className={INPUT} value={role} onChange={(e) => setRole(e.target.value === "admin" ? "admin" : "user")}>
            <option value="user">{t("role.user")}</option>
            <option value="admin">{t("role.admin")}</option>
          </select>
        </Field>
        <FormError message={error} />
        {created ? <output className="text-[13px] text-ok-ink">{t("admin.users.created")}</output> : null}
        <div>
          <Button type="submit" variant="primary" disabled={!canSubmit}>
            {t("admin.users.createSubmit")}
          </Button>
        </div>
      </form>
    </Card>
  );
}

export default function AdminUsersPage() {
  const queryClient = useQueryClient();
  const me = useMe();
  const users = useQuery({
    queryKey: USERS_KEY,
    queryFn: () => api<User[]>("GET", "/admin/users"),
  });
  const oidc = useQuery({ queryKey: OIDC_KEY, queryFn: () => api<OidcSettings>("GET", "/admin/oidc") });
  const [rowError, setRowError] = useState<string | null>(null);
  const [deleting, setDeleting] = useState<User | null>(null);
  const [deleteError, setDeleteError] = useState<string | null>(null);

  const remove = useMutation({
    mutationFn: (id: string) => api<void>("DELETE", `/admin/users/${id}`),
    onSuccess: () => {
      setDeleting(null);
      void queryClient.invalidateQueries({ queryKey: USERS_KEY });
    },
    onError: (failure) => setDeleteError(messageOf(failure)),
  });

  if (users.isPending) {
    return <LoadingMessage />;
  }
  if (users.isError) {
    return <ErrorMessage />;
  }

  return (
    <div className="flex flex-col gap-5">
      <Card className="flex flex-col gap-3 py-5" aria-labelledby="users-list">
        <div className="px-5">
          <CardHeading id="users-list" title={t("admin.users.title")} help={t("admin.users.help")} />
        </div>
        <div className="px-5">
          <FormError message={rowError} />
        </div>
        <div className="overflow-x-auto">
          <table className="w-full border-collapse">
            <thead>
              <tr>
                <th className={TH}>{t("admin.users.username")}</th>
                <th className={TH}>{t("admin.users.email")}</th>
                <th className={TH}>{t("admin.users.signIn")}</th>
                <th className={TH}>{t("admin.users.role")}</th>
                <th className={TH}>{t("admin.users.createdAt")}</th>
                <th className={TH}>
                  <span className="sr-only">{t("account.credentials.actions")}</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {users.data.map((user) => {
                const self = user.id === me.data?.id;
                const group = user.role === "admin" ? oidc.data?.admin_group : oidc.data?.user_group;
                return (
                  <tr key={user.id} className={ROW}>
                    <td className={TD}>
                      {user.username}
                      {self ? <span className="text-muted"> {t("admin.users.you")}</span> : null}
                    </td>
                    <td className={`${TD} text-muted`}>{user.email}</td>
                    <td className={TD}>
                      <Tag>{user.auth_provider === "local" ? t("admin.users.local") : t("admin.users.sso")}</Tag>
                    </td>
                    <td className={TD}>
                      {user.auth_provider === "local" ? (
                        <RoleSelect user={user} onError={setRowError} />
                      ) : (
                        <div className="flex flex-col gap-0.5">
                          <span>{roleLabel(user.role)}</span>
                          {group ? <span className="text-xs text-muted">{t("admin.users.fromGroup", { group })}</span> : null}
                        </div>
                      )}
                    </td>
                    <td className={`${TD} text-muted`}>{formatDate(user.created_at)}</td>
                    <td className={TD}>
                      <Button
                        variant="small"
                        disabled={self}
                        title={self ? t("admin.users.deleteSelf") : undefined}
                        aria-label={t("admin.users.deleteAria", { name: user.username })}
                        onClick={() => {
                          setDeleteError(null);
                          setDeleting(user);
                        }}
                      >
                        {t("account.credentials.delete")}
                      </Button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </Card>
      <CreateUserCard />
      <ConfirmDialog
        open={deleting !== null}
        onOpenChange={(open) => (open ? undefined : setDeleting(null))}
        title={t("admin.users.deleteTitle", { name: deleting?.username ?? "" })}
        description={t("admin.users.deleteBody")}
        confirmLabel={t("account.credentials.delete")}
        busy={remove.isPending}
        error={deleteError}
        onConfirm={() => deleting && remove.mutate(deleting.id)}
      />
    </div>
  );
}
