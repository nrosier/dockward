import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState, type FormEvent } from "react";
import { CardHeading, FormError, formatDate, INPUT, messageOf, Segmented, statusOf } from "../components/admin/parts";
import { Button } from "../components/ui/Button";
import { Card } from "../components/ui/Card";
import { Field } from "../components/ui/Field";
import { ErrorMessage, LoadingMessage } from "../components/ui/StatusMessage";
import { Switch } from "../components/ui/Switch";
import { t } from "../i18n";
import { api } from "../lib/api";
import type { AlertChannel, Page } from "../types/api";

const CHANNELS_KEY = ["admin", "alert-channels"] as const;

type Kind = "smtp" | "webhook";
type Tls = "implicit" | "starttls";
interface HeaderRow {
  name: string;
  value: string;
}

// `null` id means a new channel. The form holds secrets, so it only lives in
// this component's state and is unmounted after a successful save.
function ChannelForm({
  kind: initialKind,
  channel,
  onDone,
}: {
  kind: Kind | null;
  channel: AlertChannel | null;
  onDone: () => void;
}) {
  const queryClient = useQueryClient();
  const [kind, setKind] = useState<Kind>(initialKind ?? "smtp");
  const [host, setHost] = useState("");
  const [port, setPort] = useState("");
  const [tls, setTls] = useState<Tls>("implicit");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [from, setFrom] = useState("");
  const [to, setTo] = useState("");
  const [url, setUrl] = useState("");
  const [headers, setHeaders] = useState<HeaderRow[]>([]);
  const [error, setError] = useState<string | null>(null);

  function clearConfig() {
    setHost("");
    setPort("");
    setUsername("");
    setPassword("");
    setFrom("");
    setTo("");
    setUrl("");
    setHeaders([]);
  }

  function buildConfig(): Record<string, unknown> {
    if (kind === "smtp") {
      const config: Record<string, unknown> = {
        host: host.trim(),
        port: Number.parseInt(port, 10),
        tls,
        from: from.trim(),
        to: to
          .split(",")
          .map((address) => address.trim())
          .filter((address) => address !== ""),
      };
      if (username !== "") {
        config.username = username;
      }
      if (password !== "") {
        config.password = password;
      }
      return config;
    }
    const config: Record<string, unknown> = { url: url.trim() };
    const filled = headers.filter((row) => row.name.trim() !== "");
    if (filled.length > 0) {
      config.headers = Object.fromEntries(filled.map((row) => [row.name.trim(), row.value]));
    }
    return config;
  }

  const save = useMutation({
    mutationFn: () => {
      const config = buildConfig();
      if (channel === null) {
        return api<AlertChannel>("POST", "/admin/alert-channels", { kind, enabled: true, config });
      }
      return api<AlertChannel>("PUT", `/admin/alert-channels/${channel.id}`, { enabled: channel.enabled, config });
    },
    onSuccess: () => {
      clearConfig();
      void queryClient.invalidateQueries({ queryKey: CHANNELS_KEY });
      onDone();
    },
    onError: (failure) => {
      clearConfig();
      setError(statusOf(failure) === 422 ? messageOf(failure) : t("errors.generic"));
    },
  });

  function submit(event: FormEvent) {
    event.preventDefault();
    setError(null);
    save.mutate();
  }

  const fixedKind = channel?.kind ?? null;
  const title = channel
    ? t(channel.kind === "smtp" ? "admin.alerts.editSmtp" : "admin.alerts.editWebhook")
    : t("admin.alerts.add");

  return (
    <Card className="p-5" aria-labelledby="alert-form">
      <form onSubmit={submit} className="flex flex-col gap-4">
        <CardHeading id="alert-form" title={title} help={t("admin.alerts.formNote")} />
        {fixedKind === null ? (
          <div className="flex flex-col gap-1.5">
            <span id="alert-kind" className="text-[13px] font-semibold">
              {t("admin.alerts.kind")}
            </span>
            <Segmented
              labelId="alert-kind"
              value={kind}
              onChange={(value) => setKind(value === "webhook" ? "webhook" : "smtp")}
              options={[
                { value: "smtp", label: t("admin.alerts.smtp") },
                { value: "webhook", label: t("admin.alerts.webhook") },
              ]}
            />
          </div>
        ) : null}
        {kind === "smtp" ? (
          <>
            <Field id="smtp-host" label={t("admin.alerts.host")}>
              <input id="smtp-host" className={INPUT} autoComplete="off" value={host} onChange={(e) => setHost(e.target.value)} />
            </Field>
            <div className="flex flex-wrap gap-4">
              <div className="flex-1 basis-36">
                <Field id="smtp-port" label={t("admin.alerts.port")}>
                  <input id="smtp-port" className={INPUT} inputMode="numeric" value={port} onChange={(e) => setPort(e.target.value)} />
                </Field>
              </div>
              <div className="flex flex-[3] basis-60 flex-col gap-1.5">
                <span id="smtp-tls" className="text-[13px] font-semibold">
                  {t("admin.alerts.tls")}
                </span>
                <Segmented
                  labelId="smtp-tls"
                  value={tls}
                  onChange={(value) => setTls(value === "starttls" ? "starttls" : "implicit")}
                  options={[
                    { value: "implicit", label: t("admin.alerts.implicit") },
                    { value: "starttls", label: t("admin.alerts.starttls") },
                  ]}
                />
              </div>
            </div>
            <span className="text-[12.5px] text-muted">{t("admin.alerts.noPlain")}</span>
            <Field id="smtp-user" label={t("admin.alerts.username")}>
              <input id="smtp-user" className={INPUT} autoComplete="off" value={username} onChange={(e) => setUsername(e.target.value)} />
            </Field>
            <Field id="smtp-password" label={t("admin.alerts.password")}>
              <input
                id="smtp-password"
                className={INPUT}
                type="password"
                autoComplete="new-password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
              />
            </Field>
            <Field id="smtp-from" label={t("admin.alerts.from")}>
              <input id="smtp-from" className={INPUT} value={from} onChange={(e) => setFrom(e.target.value)} />
            </Field>
            <Field id="smtp-to" label={t("admin.alerts.to")} help={t("admin.alerts.toHelp")}>
              <input id="smtp-to" className={INPUT} value={to} onChange={(e) => setTo(e.target.value)} />
            </Field>
          </>
        ) : (
          <>
            <Field id="hook-url" label={t("admin.alerts.url")}>
              <input id="hook-url" className={INPUT} autoComplete="off" value={url} onChange={(e) => setUrl(e.target.value)} />
            </Field>
            <div className="flex flex-col gap-2">
              <span className="text-[13px] font-semibold">{t("admin.alerts.headers")}</span>
              {headers.map((row, index) => (
                <div key={index} className="flex flex-wrap gap-2">
                  <input
                    aria-label={t("admin.alerts.headerName")}
                    className={`${INPUT} flex-1`}
                    autoComplete="off"
                    value={row.name}
                    onChange={(e) => setHeaders(headers.map((r, i) => (i === index ? { ...r, name: e.target.value } : r)))}
                  />
                  <input
                    aria-label={t("admin.alerts.headerValue")}
                    className={`${INPUT} flex-1`}
                    type="password"
                    autoComplete="off"
                    value={row.value}
                    onChange={(e) => setHeaders(headers.map((r, i) => (i === index ? { ...r, value: e.target.value } : r)))}
                  />
                  <Button variant="small" onClick={() => setHeaders(headers.filter((_, i) => i !== index))}>
                    {t("admin.alerts.removeHeader")}
                  </Button>
                </div>
              ))}
              <div>
                <Button variant="small" onClick={() => setHeaders([...headers, { name: "", value: "" }])}>
                  {t("admin.alerts.addHeader")}
                </Button>
              </div>
            </div>
          </>
        )}
        <FormError message={error} />
        <div className="flex flex-wrap justify-end gap-2.5">
          <Button
            onClick={() => {
              clearConfig();
              onDone();
            }}
          >
            {t("common.cancel")}
          </Button>
          <Button type="submit" variant="primary" disabled={save.isPending}>
            {t("admin.alerts.save")}
          </Button>
        </div>
      </form>
    </Card>
  );
}

export default function AdminAlertsPage() {
  const queryClient = useQueryClient();
  const channels = useQuery({
    queryKey: CHANNELS_KEY,
    queryFn: () => api<Page<AlertChannel>>("GET", "/admin/alert-channels?page_size=200"),
  });
  // "new" opens the add form; a channel opens its edit form.
  const [form, setForm] = useState<"new" | AlertChannel | null>(null);
  const [toggleError, setToggleError] = useState<string | null>(null);

  const toggle = useMutation({
    mutationFn: (input: { id: string; enabled: boolean }) =>
      api<AlertChannel>("PUT", `/admin/alert-channels/${input.id}`, { enabled: input.enabled }),
    onSuccess: () => {
      setToggleError(null);
      void queryClient.invalidateQueries({ queryKey: CHANNELS_KEY });
    },
    onError: (failure) => setToggleError(messageOf(failure)),
  });

  if (channels.isPending) {
    return <LoadingMessage />;
  }
  if (channels.isError) {
    return <ErrorMessage />;
  }

  return (
    <div className="flex flex-col gap-5">
      <Card className="flex flex-col gap-3 py-5" aria-labelledby="alerts-list">
        <div className="px-5">
          <CardHeading
            id="alerts-list"
            title={t("admin.alerts.title")}
            help={t("admin.alerts.help")}
            action={
              <Button variant="primary" onClick={() => setForm("new")}>
                {t("admin.alerts.add")}
              </Button>
            }
          />
        </div>
        <div className="px-5">
          <FormError message={toggleError} />
        </div>
        {channels.data.items.length === 0 ? <p className="px-5 text-muted">{t("admin.alerts.empty")}</p> : null}
        <ul className="m-0 list-none p-0">
          {channels.data.items.map((channel) => {
            const name = t(channel.kind === "smtp" ? "admin.alerts.smtp" : "admin.alerts.webhook");
            const dates =
              channel.updated_at === channel.created_at
                ? t("admin.alerts.added", { date: formatDate(channel.created_at) })
                : t("admin.alerts.addedUpdated", {
                    added: formatDate(channel.created_at),
                    updated: formatDate(channel.updated_at),
                  });
            const editing = typeof form === "object" && form !== null && form.id === channel.id;
            return (
              <li key={channel.id} className="flex flex-wrap items-center justify-between gap-3 border-t border-border px-5 py-3">
                <div className="flex flex-col">
                  <span className="font-medium">{name}</span>
                  <span className="text-[12.5px] text-muted">{dates}</span>
                </div>
                <div className="flex items-center gap-3">
                  <label htmlFor={`enabled-${channel.id}`} className="text-[12.5px] text-muted">
                    {channel.enabled ? t("admin.alerts.enabled") : t("admin.alerts.disabled")}
                    <span className="sr-only"> {name}</span>
                  </label>
                  <Switch
                    id={`enabled-${channel.id}`}
                    checked={channel.enabled}
                    disabled={toggle.isPending}
                    onCheckedChange={(enabled) => toggle.mutate({ id: channel.id, enabled })}
                  />
                  <Button variant="small" aria-pressed={editing} onClick={() => setForm(channel)}>
                    {editing ? t("admin.alerts.editing") : t("account.credentials.edit")}
                  </Button>
                </div>
              </li>
            );
          })}
        </ul>
      </Card>
      {form === null ? null : (
        <ChannelForm
          key={form === "new" ? "new" : form.id}
          kind={null}
          channel={form === "new" ? null : form}
          onDone={() => setForm(null)}
        />
      )}
    </div>
  );
}
