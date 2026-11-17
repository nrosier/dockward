import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link2, Mail } from "lucide-react";
import { useState, type FormEvent, type KeyboardEvent } from "react";
import { CardHeading, FormError, formatDate, INPUT, messageOf, Segmented, statusOf } from "../components/admin/parts";
import { Button } from "../components/ui/Button";
import { Card } from "../components/ui/Card";
import { Field } from "../components/ui/Field";
import { ErrorMessage, LoadingMessage } from "../components/ui/StatusMessage";
import { Switch } from "../components/ui/Switch";
import { t, type MessageKey } from "../i18n";
import { api } from "../lib/api";
import type {
  AlertChannel,
  AlertChannelSettings,
  AlertEvent,
  AlertSmtpSettings,
  AlertTestResult,
  Page,
} from "../types/api";

const CHANNELS_KEY = ["admin", "alert-channels"] as const;

// The routable events, in the order of the API and the approved layout (#458).
const EVENTS: { value: AlertEvent; label: MessageKey; help: MessageKey }[] = [
  { value: "job_failed", label: "admin.alerts.event.jobFailed", help: "admin.alerts.event.jobFailedHelp" },
  { value: "new_high_or_critical", label: "admin.alerts.event.newCve", help: "admin.alerts.event.newCveHelp" },
  { value: "cve_fixed", label: "admin.alerts.event.fixed", help: "admin.alerts.event.fixedHelp" },
];

// A new channel receives job failures, as every channel did before #458.
const DEFAULT_EVENTS: AlertEvent[] = ["job_failed"];

// Splits typed text into addresses: every piece before a comma is complete.
function splitAddresses(text: string): { done: string[]; rest: string } {
  const parts = text.split(",");
  const rest = parts.pop() ?? "";
  return { done: parts.map((part) => part.trim()).filter((part) => part !== ""), rest };
}

function addUnique(list: string[], more: string[]): string[] {
  return more.reduce((acc, address) => (acc.includes(address) ? acc : [...acc, address]), list);
}

type Kind = "smtp" | "webhook";
type Tls = "implicit" | "starttls";
interface HeaderRow {
  name: string;
  value: string;
}

// `null` channel means a new channel. The form holds secrets, so it only lives in
// this component's state and is unmounted after a successful save. `saved` holds the
// settings of an SMTP channel that are safe to show again (never the password).
function ChannelForm({
  kind: initialKind,
  channel,
  saved,
  onDone,
}: {
  kind: Kind | null;
  channel: AlertChannel | null;
  saved: AlertSmtpSettings | null;
  onDone: () => void;
}) {
  const queryClient = useQueryClient();
  const [kind, setKind] = useState<Kind>(channel?.kind ?? initialKind ?? "smtp");
  const [host, setHost] = useState(saved?.host ?? "");
  const [port, setPort] = useState(saved === null ? "" : String(saved.port));
  const [tls, setTls] = useState<Tls>(saved?.tls ?? "implicit");
  const [username, setUsername] = useState(saved?.username ?? "");
  const [password, setPassword] = useState("");
  const [from, setFrom] = useState(saved?.from ?? "");
  const [to, setTo] = useState<string[]>(saved === null ? [] : saved.to);
  const [toDraft, setToDraft] = useState("");
  const [events, setEvents] = useState<AlertEvent[]>(channel?.events ?? DEFAULT_EVENTS);
  const [url, setUrl] = useState("");
  const [headers, setHeaders] = useState<HeaderRow[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [testResult, setTestResult] = useState<{ ok: boolean; text: string } | null>(null);
  const keepPassword = saved?.password_set === true;

  function clearConfig() {
    setHost("");
    setPort("");
    setUsername("");
    setPassword("");
    setFrom("");
    setTo([]);
    setToDraft("");
    setUrl("");
    setHeaders([]);
  }

  // The chips plus whatever is still typed in the address field.
  function recipients(): string[] {
    const draft = toDraft.trim();
    return draft === "" ? to : addUnique(to, [draft]);
  }

  function onToChange(value: string) {
    const { done, rest } = splitAddresses(value);
    if (done.length > 0) {
      setTo(addUnique(to, done));
    }
    setToDraft(rest);
  }

  function onToKey(event: KeyboardEvent<HTMLInputElement>) {
    if (event.key === "Enter") {
      event.preventDefault();
      const draft = toDraft.trim();
      if (draft !== "") {
        setTo(addUnique(to, [draft]));
        setToDraft("");
      }
    } else if (event.key === "Backspace" && toDraft === "" && to.length > 0) {
      setTo(to.slice(0, -1));
    }
  }

  function toggleEvent(value: AlertEvent, on: boolean) {
    const next = on ? [...events, value] : events.filter((event) => event !== value);
    setEvents(EVENTS.map((event) => event.value).filter((event) => next.includes(event)));
  }

  function buildConfig(): Record<string, unknown> {
    if (kind === "smtp") {
      const config: Record<string, unknown> = {
        host: host.trim(),
        port: Number.parseInt(port, 10),
        tls,
        from: from.trim(),
        to: recipients(),
      };
      if (username !== "") {
        config.username = username;
      }
      if (password !== "") {
        config.password = password;
      } else if (keepPassword) {
        config.keep_password = true;
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

  // A saved webhook keeps its URL and headers when the URL field is left empty, so the
  // events can change without entering a secret again.
  const keepWebhook = channel !== null && kind === "webhook" && url.trim() === "" && headers.length === 0;

  const save = useMutation({
    mutationFn: () => {
      if (channel === null) {
        return api<AlertChannel>("POST", "/admin/alert-channels", {
          kind,
          enabled: true,
          events,
          config: buildConfig(),
        });
      }
      const body: Record<string, unknown> = { enabled: channel.enabled, events };
      if (!keepWebhook) {
        body.config = buildConfig();
      }
      return api<AlertChannel>("PUT", `/admin/alert-channels/${channel.id}`, body);
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

  const test = useMutation({
    mutationFn: () => {
      const body: Record<string, unknown> = { config: buildConfig() };
      if (channel !== null) {
        body.channel_id = channel.id;
      }
      return api<AlertTestResult>("POST", "/admin/alert-channels/test", body);
    },
    onSuccess: (result) => {
      setTestResult(
        result.ok
          ? { ok: true, text: t("admin.alerts.testOk", { to: recipients().join(", ") }) }
          : { ok: false, text: t("admin.alerts.testFailed", { reason: result.error ?? t("errors.generic") }) },
      );
    },
    onError: (failure) => {
      const status = statusOf(failure);
      setTestResult({
        ok: false,
        text: status === 429 ? t("admin.alerts.testLimit") : status === 422 ? messageOf(failure) : t("errors.generic"),
      });
    },
  });

  function submit(event: FormEvent) {
    event.preventDefault();
    setError(null);
    save.mutate();
  }

  function runTest() {
    setTestResult(null);
    test.mutate();
  }

  const fixedKind = channel?.kind ?? null;
  const title = channel
    ? t(channel.kind === "smtp" ? "admin.alerts.editSmtp" : "admin.alerts.editWebhook")
    : t("admin.alerts.add");
  const note =
    saved !== null
      ? t("admin.alerts.formNoteSmtp")
      : channel !== null && channel.kind === "webhook"
        ? t("admin.alerts.formNoteWebhook")
        : t("admin.alerts.formNote");
  const optional = <span className="font-normal text-muted"> {t("admin.alerts.optional")}</span>;

  return (
    <Card className="p-5" aria-labelledby="alert-form">
      <form onSubmit={submit} className="flex flex-col gap-5">
        <CardHeading id="alert-form" title={title} help={note} />
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

        {/* Section A: the events this channel receives. */}
        <fieldset className="m-0 flex flex-col gap-2.5 border-0 p-0">
          <legend className="mb-2.5 text-[13px] font-semibold">{t("admin.alerts.events")}</legend>
          <div className="grid grid-cols-1 gap-x-5 gap-y-4 md:grid-cols-3">
            {EVENTS.map((event) => (
              <div key={event.value} className="flex items-start gap-2.5">
                <input
                  id={`event-${event.value}`}
                  type="checkbox"
                  className="mt-[3px] size-4 cursor-pointer accent-accent"
                  aria-describedby={`event-${event.value}-help`}
                  checked={events.includes(event.value)}
                  onChange={(e) => toggleEvent(event.value, e.target.checked)}
                />
                <div className="flex flex-col">
                  <label htmlFor={`event-${event.value}`} className="cursor-pointer text-[13px] font-medium">
                    {t(event.label)}
                  </label>
                  <span id={`event-${event.value}-help`} className="text-[12.5px] text-muted">
                    {t(event.help)}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </fieldset>

        {kind === "smtp" ? (
          <>
            {/* Section B: connection, 60 / 15 / 25. */}
            <div className="flex flex-col gap-2">
              <div className="grid grid-cols-1 items-start gap-x-5 gap-y-4 lg:grid-cols-[12fr_3fr_5fr]">
                <Field id="smtp-host" label={t("admin.alerts.host")}>
                  <input id="smtp-host" className={INPUT} autoComplete="off" value={host} onChange={(e) => setHost(e.target.value)} />
                </Field>
                <Field id="smtp-port" label={t("admin.alerts.port")}>
                  <input
                    id="smtp-port"
                    className={`${INPUT} max-w-28`}
                    inputMode="numeric"
                    value={port}
                    onChange={(e) => setPort(e.target.value)}
                  />
                </Field>
                <div className="flex min-w-0 flex-col gap-1.5">
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
              <p className="text-[12.5px] text-high-ink">{t("admin.alerts.noPlain")}</p>
            </div>

            {/* Section C: credentials, 50 / 50. The password is never shown. */}
            <div className="grid grid-cols-1 items-start gap-x-5 gap-y-4 md:grid-cols-2">
              <div className="flex flex-col gap-1.5">
                <label htmlFor="smtp-user" className="text-[13px] font-semibold">
                  {t("admin.alerts.username")}
                  {optional}
                </label>
                <input id="smtp-user" className={INPUT} autoComplete="off" value={username} onChange={(e) => setUsername(e.target.value)} />
              </div>
              <div className="flex flex-col gap-1.5">
                <label htmlFor="smtp-password" className="text-[13px] font-semibold">
                  {t("admin.alerts.password")}
                  {optional}
                </label>
                <input
                  id="smtp-password"
                  className={INPUT}
                  type="password"
                  autoComplete="new-password"
                  placeholder={keepPassword ? t("admin.alerts.passwordKeep") : undefined}
                  aria-describedby={keepPassword ? "smtp-password-help" : undefined}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                />
                {keepPassword ? (
                  <p id="smtp-password-help" className="text-[12.5px] text-muted">
                    {t("admin.alerts.passwordSaved")}
                  </p>
                ) : null}
              </div>
            </div>

            {/* Section D: addresses, 50 / 50. The to addresses are removable chips. */}
            <div className="grid grid-cols-1 items-start gap-x-5 gap-y-4 md:grid-cols-2">
              <Field id="smtp-from" label={t("admin.alerts.from")}>
                <input id="smtp-from" className={INPUT} value={from} onChange={(e) => setFrom(e.target.value)} />
              </Field>
              <div className="flex flex-col gap-1.5">
                <label htmlFor="smtp-to" className="text-[13px] font-semibold">
                  {t("admin.alerts.to")}
                </label>
                <div className="flex min-h-9 flex-wrap items-center gap-1.5 rounded-lg border border-muted bg-bg px-2.5 py-1.5">
                  {to.map((address) => (
                    <span
                      key={address}
                      className="inline-flex items-center gap-1.5 rounded-full border border-border bg-surface-2 py-0.5 pr-1 pl-2.5 text-[12.5px]"
                    >
                      {address}
                      <button
                        type="button"
                        className="cursor-pointer rounded-full px-1 font-semibold text-muted hover:text-text focus-visible:outline-2 focus-visible:outline-accent"
                        aria-label={t("admin.alerts.toRemove", { address })}
                        onClick={() => setTo(to.filter((item) => item !== address))}
                      >
                        ×
                      </button>
                    </span>
                  ))}
                  <input
                    id="smtp-to"
                    className="min-w-30 flex-1 basis-40 border-0 bg-transparent text-[13px] text-text outline-none"
                    placeholder={t("admin.alerts.toAdd")}
                    aria-describedby="smtp-to-help"
                    value={toDraft}
                    onChange={(e) => onToChange(e.target.value)}
                    onKeyDown={onToKey}
                  />
                </div>
                <p id="smtp-to-help" className="text-[12.5px] text-muted">
                  {t("admin.alerts.toHelp")}
                </p>
              </div>
            </div>
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

        {/* Section E: the footer. Test email left, with its result beside it; Cancel and Save right. */}
        <div className="flex flex-wrap items-center justify-between gap-3 border-t border-border pt-4">
          <div className="flex min-w-0 flex-wrap items-center gap-3">
            {kind === "smtp" ? (
              <Button onClick={runTest} disabled={test.isPending || save.isPending}>
                {test.isPending ? t("admin.alerts.testing") : t("admin.alerts.test")}
              </Button>
            ) : null}
            {testResult === null ? null : testResult.ok ? (
              <output className="text-[12.5px] text-ok-ink">{testResult.text}</output>
            ) : (
              <p role="alert" className="text-[12.5px] text-crit-ink">
                {testResult.text}
              </p>
            )}
          </div>
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
        </div>
      </form>
    </Card>
  );
}

// The summary line of a channel in the list: host, recipients and events for email; the
// events alone for a webhook, whose settings are secret.
function ChannelSummary({ channel }: { channel: AlertChannel }) {
  const settings = useQuery({
    queryKey: [...CHANNELS_KEY, channel.id, "summary"],
    queryFn: () => api<AlertChannelSettings>("GET", `/admin/alert-channels/${channel.id}/settings`),
    enabled: channel.kind === "smtp",
  });
  const count = channel.events.length;
  const events =
    count === 0
      ? t("admin.alerts.summaryNoEvents")
      : count === 1
        ? t("admin.alerts.summaryEvent")
        : t("admin.alerts.summaryEvents", { count });
  const parts: string[] = [];
  const smtp = settings.data?.smtp ?? null;
  if (channel.kind === "webhook") {
    parts.push(t("admin.alerts.webhook"));
  } else if (smtp !== null) {
    parts.push(smtp.host);
    parts.push(
      smtp.to.length === 1
        ? t("admin.alerts.summaryRecipient")
        : t("admin.alerts.summaryRecipients", { count: smtp.to.length }),
    );
  }
  parts.push(events);
  return <span className="text-[12.5px] text-muted">{parts.join(" · ")}</span>;
}

// Loads the saved SMTP settings, then opens the edit form with them filled in. Nothing
// is cached, so every open reads the current settings.
function EditChannelForm({ channel, onDone }: { channel: AlertChannel; onDone: () => void }) {
  const settings = useQuery({
    queryKey: [...CHANNELS_KEY, channel.id, "settings"],
    queryFn: () => api<AlertChannelSettings>("GET", `/admin/alert-channels/${channel.id}/settings`),
    gcTime: 0,
  });
  if (settings.isPending) {
    return <LoadingMessage />;
  }
  if (settings.isError) {
    return <ErrorMessage />;
  }
  return <ChannelForm kind={null} channel={channel} saved={settings.data.smtp} onDone={onDone} />;
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
              <li
                key={channel.id}
                className="grid grid-cols-1 items-center gap-3 border-t border-border px-5 py-3 md:grid-cols-[auto_1fr_auto] md:gap-3.5"
              >
                <div className="flex items-center gap-3">
                  {channel.kind === "smtp" ? (
                    <Mail aria-hidden="true" className="size-5 text-muted" />
                  ) : (
                    <Link2 aria-hidden="true" className="size-5 text-muted" />
                  )}
                  <div className="flex flex-col">
                    <span className="font-medium">{name}</span>
                    <span className="text-[12px] text-muted">{dates}</span>
                  </div>
                </div>
                <ChannelSummary channel={channel} />
                <div className="flex items-center gap-3 md:justify-end">
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
      {form === null ? null : form === "new" ? (
        <ChannelForm key="new" kind={null} channel={null} saved={null} onDone={() => setForm(null)} />
      ) : (
        <EditChannelForm key={form.id} channel={form} onDone={() => setForm(null)} />
      )}
    </div>
  );
}
