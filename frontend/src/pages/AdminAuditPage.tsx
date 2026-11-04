import { useQuery } from "@tanstack/react-query";
import { useSearchParams } from "react-router";
import { formatDateTime, INPUT, ROW, Tag, TD, TH } from "../components/admin/parts";
import { Card } from "../components/ui/Card";
import { Pagination, currentPage } from "../components/ui/Pagination";
import { ErrorMessage, LoadingMessage } from "../components/ui/StatusMessage";
import { t } from "../i18n";
import { api } from "../lib/api";
import type { User } from "../lib/session";
import type { AuditEntry, Page } from "../types/api";

const PAGE_SIZE = 50;

// The vocabulary in specs/database.md, "Audit action vocabulary".
const ACTIONS = [
  "user.create",
  "user.delete",
  "user.role_change",
  "oidc.config_change",
  "credential.create",
  "credential.rotate",
  "credential.delete",
  "cve.accept",
  "cve.unaccept",
  "mapping.create",
  "mapping.update",
  "mapping.delete",
  "mapping.webhook_token_rotate",
  "mapping.auth_secret_rotate",
  "alert.config_change",
  "backup.run",
  "restore.run",
];

// A short `key: value` list. Always a plain string, rendered as escaped text.
export function describeDetails(details: unknown): string {
  if (details === null || details === undefined) {
    return "";
  }
  if (typeof details !== "object" || Array.isArray(details)) {
    return String(JSON.stringify(details));
  }
  return Object.entries(details as Record<string, unknown>)
    .map(([key, value]) => `${key}: ${typeof value === "string" ? value : JSON.stringify(value)}`)
    .join(", ");
}

export default function AdminAuditPage() {
  const [params, setParams] = useSearchParams();
  const action = params.get("action") ?? "";
  const actor = params.get("actor_user_id") ?? "";
  const page = currentPage(params);

  const users = useQuery({
    queryKey: ["admin", "users", "all"],
    queryFn: () => api<User[]>("GET", "/admin/users"),
  });
  const log = useQuery({
    queryKey: ["admin", "audit", action, actor, page],
    queryFn: () => {
      const query = new URLSearchParams({ page: String(page), page_size: String(PAGE_SIZE) });
      if (action) {
        query.set("action", action);
      }
      if (actor) {
        query.set("actor_user_id", actor);
      }
      return api<Page<AuditEntry>>("GET", `/admin/audit-log?${query.toString()}`);
    },
  });

  function setFilter(name: string, value: string) {
    const updated = new URLSearchParams(params);
    if (value) {
      updated.set(name, value);
    } else {
      updated.delete(name);
    }
    updated.delete("page");
    setParams(updated);
  }

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap gap-3">
        <label className="flex flex-col gap-1 text-xs text-muted">
          {t("admin.audit.action")}
          <select className={`${INPUT} min-w-52`} value={action} onChange={(e) => setFilter("action", e.target.value)}>
            <option value="">{t("admin.audit.allActions")}</option>
            {ACTIONS.map((name) => (
              <option key={name} value={name}>
                {name}
              </option>
            ))}
          </select>
        </label>
        <label className="flex flex-col gap-1 text-xs text-muted">
          {t("admin.audit.actor")}
          <select
            className={`${INPUT} min-w-52`}
            value={actor}
            onChange={(e) => setFilter("actor_user_id", e.target.value)}
          >
            <option value="">{t("admin.audit.allActors")}</option>
            {(users.data ?? []).map((u) => (
              <option key={u.id} value={u.id}>
                {u.username}
              </option>
            ))}
          </select>
        </label>
      </div>
      {log.isPending ? <LoadingMessage /> : null}
      {log.isError ? <ErrorMessage /> : null}
      {log.data ? (
        <Card className="overflow-x-auto" aria-label={t("admin.audit.table")}>
          <table className="w-full border-collapse">
            <thead>
              <tr>
                <th className={TH}>{t("admin.audit.col.time")}</th>
                <th className={TH}>{t("admin.audit.col.actor")}</th>
                <th className={TH}>{t("admin.audit.col.action")}</th>
                <th className={TH}>{t("admin.audit.col.target")}</th>
                <th className={TH}>{t("admin.audit.col.details")}</th>
              </tr>
            </thead>
            <tbody>
              {log.data.items.map((entry) => (
                <tr key={entry.id} className={ROW}>
                  <td className={`${TD} text-muted`}>{formatDateTime(entry.created_at)}</td>
                  <td className={TD}>{entry.actor_username}</td>
                  <td className={TD}>
                    <Tag>{entry.action}</Tag>
                  </td>
                  <td className={TD}>{entry.target}</td>
                  <td className={`${TD} text-muted`}>{describeDetails(entry.details) || t("admin.audit.noDetails")}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <Pagination total={log.data.total} pageSize={PAGE_SIZE} />
        </Card>
      ) : null}
    </div>
  );
}
