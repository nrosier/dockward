import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { INPUT, ROW, TD, TH, statusOf } from "../components/admin/parts";
import { Segmented } from "../components/mappings/Segmented";
import { Card } from "../components/ui/Card";
import { Pill, type PillKind } from "../components/ui/Pill";
import { ErrorMessage, LoadingMessage } from "../components/ui/StatusMessage";
import { t } from "../i18n";
import { api } from "../lib/api";
import { LEVEL_KEY, TRUNCATED_MARKER, useLogLevel, type LevelStatus, type LogLevel, type LogsView } from "../lib/appLog";

const SETTABLE = ["info", "debug", "trace"] as const;
const FILTER_LEVELS = ["error", "warn", "info", "debug", "trace"] as const;

const PILL: Record<LogLevel, PillKind> = {
  error: "failed",
  warn: "medium",
  info: "done",
  debug: "low",
  trace: "unknown",
};

function clock(timestamp: string): string {
  const date = new Date(timestamp);
  return Number.isNaN(date.getTime()) ? timestamp : date.toISOString().slice(11, 19);
}

export default function AdminLogPage() {
  const client = useQueryClient();
  const [level, setLevel] = useState("");
  const [text, setText] = useState("");

  const current = useLogLevel();
  const logs = useQuery({
    queryKey: ["admin", "logs", level, text],
    queryFn: () => {
      const query = new URLSearchParams();
      if (level) {
        query.set("level", level);
      }
      if (text) {
        query.set("q", text);
      }
      const suffix = query.toString();
      return api<LogsView>("GET", `/admin/logs${suffix ? `?${suffix}` : ""}`);
    },
    refetchInterval: 5_000,
    retry: false,
  });
  const change = useMutation({
    mutationFn: (next: string) => api<LevelStatus>("PUT", "/admin/log-level", { level: next }),
    onSuccess: (status) => {
      client.setQueryData(LEVEL_KEY, status);
      void client.invalidateQueries({ queryKey: ["admin", "logs"] });
    },
  });

  if (statusOf(logs.error) === 403) {
    return (
      <p role="alert" className="p-8 text-crit-ink">
        {t("adminLog.forbidden")}
      </p>
    );
  }

  return (
    <div className="flex flex-col gap-4">
      <Card className="flex flex-wrap items-start justify-between gap-4 p-5">
        <div>
          <h2 className="text-2xl font-semibold tracking-tight">{t("adminLog.title")}</h2>
          <p className="mt-1 text-muted">{t("adminLog.subtitle")}</p>
        </div>
        <div className="flex items-center gap-3">
          <span className="text-xs text-muted">{t("adminLog.level.current")}</span>
          <Segmented
            label={t("adminLog.level.label")}
            options={SETTABLE.map((name) => ({ value: name, label: t(`adminLog.level.${name}`) }))}
            value={current.data?.level ?? ""}
            onChange={(next) => change.mutate(next)}
            disabled={change.isPending || current.data === undefined}
          />
        </div>
        {change.isError ? (
          <p role="alert" className="w-full text-crit-ink">
            {t("adminLog.level.saveFailed")}
          </p>
        ) : null}
      </Card>

      <Card className="grid gap-4 p-5" style={{ gridTemplateColumns: "repeat(auto-fit, minmax(12rem, 1fr))" }}>
        <label className="flex flex-col gap-1.5 text-xs text-muted">
          {t("adminLog.filter.level")}
          <select className={INPUT} value={level} onChange={(e) => setLevel(e.target.value)}>
            <option value="">{t("adminLog.filter.allLevels")}</option>
            {FILTER_LEVELS.map((name) => (
              <option key={name} value={name}>
                {t(`adminLog.filter.${name}`)}
              </option>
            ))}
          </select>
        </label>
        <label className="flex flex-col gap-1.5 text-xs text-muted">
          {t("adminLog.filter.text")}
          <input
            type="search"
            className={INPUT}
            value={text}
            placeholder={t("adminLog.filter.textPlaceholder")}
            onChange={(e) => setText(e.target.value)}
          />
        </label>
      </Card>

      {logs.isPending ? <LoadingMessage /> : null}
      {logs.isError ? <ErrorMessage /> : null}
      {logs.data && logs.data.items.length === 0 ? (
        <p className="p-8 text-muted">{t("adminLog.empty")}</p>
      ) : null}
      {logs.data && logs.data.items.length > 0 ? (
        <Card className="overflow-x-auto" aria-label={t("adminLog.table")}>
          <table className="w-full border-collapse font-mono text-xs">
            <thead>
              <tr>
                <th className={TH}>{t("adminLog.col.time")}</th>
                <th className={TH}>{t("adminLog.col.level")}</th>
                <th className={TH}>{t("adminLog.col.target")}</th>
                <th className={TH}>{t("adminLog.col.message")}</th>
              </tr>
            </thead>
            <tbody>
              {logs.data.items.map((line) => {
                const cut = line.message.endsWith(TRUNCATED_MARKER);
                const message = cut ? line.message.slice(0, -TRUNCATED_MARKER.length) : line.message;
                return (
                  <tr key={line.seq} className={ROW}>
                    <td className={`${TD} text-muted`}>{clock(line.timestamp)}</td>
                    <td className={TD}>
                      <Pill kind={PILL[line.level] ?? "unknown"} label={line.level} />
                    </td>
                    <td className={TD}>{line.target}</td>
                    <td className={`${TD} break-all`}>
                      {message}
                      {cut ? <span className="ml-1 text-muted">{t("adminLog.line.truncated")}</span> : null}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </Card>
      ) : null}
    </div>
  );
}
