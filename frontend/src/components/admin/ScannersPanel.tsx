import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useRef, useState, type RefObject } from "react";
import { t, type MessageKey } from "../../i18n";
import { api, ApiError } from "../../lib/api";
import type { AboutReport, ScannerState } from "../../types/api";
import { Button } from "../ui/Button";
import { Card } from "../ui/Card";
import { Dialog } from "../ui/Dialog";
import { Badge, CardHeading, formatDateTime, ROW, TD, TH } from "./parts";

type Key = "trivy" | "grype";
const KEYS: Key[] = ["trivy", "grype"];

const nameOf = (key: Key) => t(key === "trivy" ? "admin.scanners.name.trivy" : "admin.scanners.name.grype");

// The fixed `kind` words of the install routes (specs/api.md). Anything else, and a refusal
// with no kind, shows the generic line. A message never holds a path, a URL or upstream text.
const KINDS = new Set([
  "scanner_busy",
  "no_previous_version",
  "unsupported_platform",
  "bundled_version_unknown",
  "release_unavailable",
  "not_newer_than_bundled",
  "already_installed",
  "download_failed",
  "download_too_large",
  "checksum_missing",
  "checksum_mismatch",
  "signature_invalid",
  "archive_refused",
  "storage_failed",
]);

export function failureReason(error: unknown): string {
  if (error instanceof ApiError) {
    if (error.status === 429) {
      return t("admin.scanners.failed.rate_limited");
    }
    if (error.kind !== undefined && KINDS.has(error.kind)) {
      return t(`admin.scanners.failed.${error.kind}` as MessageKey);
    }
  }
  return t("admin.scanners.failed.unknown");
}

interface Failure {
  scanner: Key;
  version: string;
  reason: string;
}

function bundledVersion(about: AboutReport, key: Key): string {
  return about[key] ?? t("admin.scanners.unknown");
}

function inUseVersion(about: AboutReport, key: Key): string {
  return about.scanners[key].downloaded_version ?? bundledVersion(about, key);
}

function StatusPill({ state }: { state: ScannerState }) {
  if (state.update_available) {
    return <Badge tone="accent">{t("admin.scanners.status.update")}</Badge>;
  }
  if (state.latest_version === null && state.downloaded_version === null) {
    return <Badge tone="neutral">{t("admin.scanners.status.bundled")}</Badge>;
  }
  return <Badge tone="ok">{t("admin.scanners.status.upToDate")}</Badge>;
}

interface ConfirmProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: string;
  description: string;
  confirmLabel: string;
  danger: boolean;
  busy: boolean;
  error: string | null;
  onConfirm: () => void;
  returnFocusTo: RefObject<HTMLElement | null>;
}

function Confirm({
  open,
  onOpenChange,
  title,
  description,
  confirmLabel,
  danger,
  busy,
  error,
  onConfirm,
  returnFocusTo,
}: ConfirmProps) {
  return (
    <Dialog
      open={open}
      onOpenChange={onOpenChange}
      title={title}
      description={description}
      onCloseAutoFocus={(event) => {
        // Focus goes back to the button that opened the dialog, when it is still there.
        const target = returnFocusTo.current;
        if (target !== null && target.isConnected && !(target as HTMLButtonElement).disabled) {
          event.preventDefault();
          target.focus();
        }
      }}
    >
      {error === null ? null : (
        <p role="alert" className="text-[13px] text-crit-ink">
          {error}
        </p>
      )}
      <div className="flex flex-wrap justify-end gap-2.5">
        <Button onClick={() => onOpenChange(false)}>{t("common.cancel")}</Button>
        <Button variant={danger ? "danger" : "primary"} disabled={busy} onClick={onConfirm}>
          {confirmLabel}
        </Button>
      </div>
    </Dialog>
  );
}

// The Scanners card, the install failure and broken-scanner cards, and the data-volume card
// (specs/frontend.md, "Admin health page"). Nothing installs without the confirmation.
export function ScannersPanel() {
  const client = useQueryClient();
  const about = useQuery({
    queryKey: ["about"],
    queryFn: () => api<AboutReport>("GET", "/about"),
  });
  const [installing, setInstalling] = useState<Key | null>(null);
  const [rollingBack, setRollingBack] = useState<Key | null>(null);
  const [failure, setFailure] = useState<Failure | null>(null);
  const [rollbackError, setRollbackError] = useState<string | null>(null);
  const [clearError, setClearError] = useState<string | null>(null);
  const opener = useRef<HTMLElement | null>(null);

  const refresh = () => client.invalidateQueries({ queryKey: ["about"] });
  const post = (key: Key, action: "install" | "rollback" | "clear-broken") =>
    api<{ scanner: string; version: string }>("POST", `/admin/scanners/${key}/${action}`);

  const install = useMutation({
    mutationFn: (key: Key) => post(key, "install"),
  });
  const rollback = useMutation({
    mutationFn: (key: Key) => post(key, "rollback"),
  });
  const clear = useMutation({
    mutationFn: (key: Key) => post(key, "clear-broken"),
  });

  if (about.data === undefined) {
    // The scanner state is extra to the page: nothing is shown until it has loaded.
    return null;
  }
  const data = about.data;

  const confirmInstall = (key: Key) => {
    const version = data.scanners[key].latest_version ?? "";
    setFailure(null);
    install.mutate(key, {
      onError: (error) => setFailure({ scanner: key, version, reason: failureReason(error) }),
      onSettled: () => {
        setInstalling(null);
        void refresh();
      },
    });
  };

  const confirmRollback = (key: Key) => {
    setRollbackError(null);
    rollback.mutate(key, {
      onSuccess: () => setRollingBack(null),
      onError: () => setRollbackError(t("admin.scanners.rollback.failed")),
      onSettled: () => void refresh(),
    });
  };

  const clearBroken = (key: Key) => {
    setClearError(null);
    clear.mutate(key, {
      onError: () => setClearError(t("admin.scanners.broken.failed")),
      onSettled: () => void refresh(),
    });
  };

  const broken = KEYS.filter((key) => data.scanners[key].broken_version !== null);
  const downloaded = KEYS.filter((key) => data.scanners[key].downloaded_version !== null);

  return (
    <>
      {failure === null ? null : (
        <Card className="flex flex-col gap-1.5 border-crit/45 p-5" aria-labelledby="scanner-failed">
          <h2 id="scanner-failed" className="text-[15px] font-semibold">
            {t("admin.scanners.failed.title")}
          </h2>
          <p role="alert" className="text-[12.5px]">
            {t("admin.scanners.failed.lead", {
              name: nameOf(failure.scanner),
              version: failure.version,
              reason: failure.reason,
            })}{" "}
            {t("admin.scanners.failed.unchanged", {
              name: nameOf(failure.scanner),
              current: inUseVersion(data, failure.scanner),
            })}
          </p>
          <p className="text-[12.5px] text-muted">{t("admin.scanners.failed.hint")}</p>
        </Card>
      )}

      {broken.map((key) => (
        <Card key={key} className="flex flex-col gap-3 border-high/45 p-5" aria-labelledby={`scanner-broken-${key}`}>
          <h2 id={`scanner-broken-${key}`} className="text-[15px] font-semibold">
            {t("admin.scanners.broken.title")}
          </h2>
          <p className="text-[12.5px] text-high-ink">
            {t("admin.scanners.broken.body", {
              name: nameOf(key),
              version: data.scanners[key].broken_version ?? "",
              bundled: bundledVersion(data, key),
            })}
          </p>
          {clearError === null ? null : (
            <p role="alert" className="text-[13px] text-crit-ink">
              {clearError}
            </p>
          )}
          <div className="flex flex-wrap items-center justify-between gap-3">
            <Badge tone="warn">{t("admin.scanners.status.broken")}</Badge>
            <Button disabled={clear.isPending} onClick={() => clearBroken(key)}>
              {clear.isPending ? t("admin.scanners.broken.clearing") : t("admin.scanners.broken.clear")}
            </Button>
          </div>
        </Card>
      ))}

      <Card className="flex flex-col gap-3 py-5" aria-labelledby="scanners-card">
        <div className="px-5">
          <CardHeading id="scanners-card" title={t("admin.scanners.title")} help={t("admin.scanners.help")} />
        </div>
        <div className="overflow-x-auto">
          <table className="w-full border-collapse">
            <thead>
              <tr>
                <th className={TH}>{t("admin.scanners.col.scanner")}</th>
                <th className={TH}>{t("admin.scanners.col.inUse")}</th>
                <th className={TH}>{t("admin.scanners.col.latest")}</th>
                <th className={TH}>{t("admin.scanners.col.status")}</th>
                <th className={`${TH} text-right`}>{t("admin.scanners.col.action")}</th>
              </tr>
            </thead>
            <tbody>
              {KEYS.map((key) => {
                const state = data.scanners[key];
                const latest = state.latest_version;
                return (
                  <tr key={key} className={ROW}>
                    <td className={TD}>
                      <div>{nameOf(key)}</div>
                      <div className="text-xs text-muted">
                        {state.checked_at === null
                          ? t("admin.scanners.notChecked")
                          : t("admin.scanners.checked", { time: formatDateTime(state.checked_at) })}
                      </div>
                    </td>
                    <td className={`${TD} font-mono text-xs`}>
                      {inUseVersion(data, key)}{" "}
                      <span className="text-muted">
                        {state.in_use === "downloaded"
                          ? t("admin.scanners.downloadedTag")
                          : t("admin.scanners.bundledTag")}
                      </span>
                    </td>
                    <td className={`${TD} font-mono text-xs`}>{latest ?? t("admin.scanners.unknown")}</td>
                    <td className={TD}>
                      <StatusPill state={state} />
                    </td>
                    <td className={`${TD} text-right`}>
                      {state.update_available && latest !== null ? (
                        <Button
                          variant="primary"
                          disabled={install.isPending}
                          aria-label={`${t("admin.scanners.installVersion", { version: latest })} (${nameOf(key)})`}
                          onClick={(event) => {
                            opener.current = event.currentTarget;
                            setInstalling(key);
                          }}
                        >
                          {t("admin.scanners.installVersion", { version: latest })}
                        </Button>
                      ) : (
                        <Button disabled>{t("admin.scanners.install")}</Button>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </Card>

      {downloaded.length === 0 ? null : (
        <Card className="flex flex-col gap-3 py-5" aria-labelledby="scanners-volume">
          <div className="px-5">
            <CardHeading
              id="scanners-volume"
              title={t("admin.scanners.volume.title")}
              help={t("admin.scanners.volume.help")}
            />
          </div>
          <div className="overflow-x-auto">
            <table className="w-full border-collapse">
              <thead>
                <tr>
                  <th className={TH}>{t("admin.scanners.col.scanner")}</th>
                  <th className={TH}>{t("admin.scanners.col.current")}</th>
                  <th className={TH}>{t("admin.scanners.col.previous")}</th>
                  <th className={TH}>{t("admin.scanners.col.status")}</th>
                  <th className={`${TH} text-right`}>{t("admin.scanners.col.action")}</th>
                </tr>
              </thead>
              <tbody>
                {downloaded.map((key) => {
                  const state = data.scanners[key];
                  const previous = state.previous_version;
                  return (
                    <tr key={key} className={ROW}>
                      <td className={TD}>{nameOf(key)}</td>
                      <td className={`${TD} font-mono text-xs`}>{state.downloaded_version}</td>
                      <td className={`${TD} font-mono text-xs`}>{previous ?? t("admin.scanners.none")}</td>
                      <td className={TD}>
                        <Badge tone="ok">{t("admin.scanners.status.verified")}</Badge>
                      </td>
                      <td className={`${TD} text-right`}>
                        <Button
                          variant="danger"
                          disabled={previous === null || rollback.isPending}
                          aria-label={`${previous === null ? t("admin.scanners.rollback") : t("admin.scanners.rollbackTo", { version: previous })} (${nameOf(key)})`}
                          onClick={(event) => {
                            opener.current = event.currentTarget;
                            setRollbackError(null);
                            setRollingBack(key);
                          }}
                        >
                          {previous === null
                            ? t("admin.scanners.rollback")
                            : t("admin.scanners.rollbackTo", { version: previous })}
                        </Button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </Card>
      )}

      {installing === null ? null : (
        <Confirm
          open
          onOpenChange={(open) => {
            if (!open && !install.isPending) {
              setInstalling(null);
            }
          }}
          title={t("admin.scanners.confirm.title", {
            name: nameOf(installing),
            version: data.scanners[installing].latest_version ?? "",
          })}
          description={t("admin.scanners.confirm.body")}
          confirmLabel={
            install.isPending
              ? t("admin.scanners.installing")
              : t("admin.scanners.installVersion", { version: data.scanners[installing].latest_version ?? "" })
          }
          danger={false}
          busy={install.isPending}
          error={null}
          onConfirm={() => confirmInstall(installing)}
          returnFocusTo={opener}
        />
      )}

      {rollingBack === null ? null : (
        <Confirm
          open
          onOpenChange={(open) => {
            if (!open && !rollback.isPending) {
              setRollingBack(null);
            }
          }}
          title={t("admin.scanners.rollback.title", {
            name: nameOf(rollingBack),
            version: data.scanners[rollingBack].previous_version ?? "",
          })}
          description={t("admin.scanners.rollback.body")}
          confirmLabel={t("admin.scanners.rollback")}
          danger
          busy={rollback.isPending}
          error={rollbackError}
          onConfirm={() => confirmRollback(rollingBack)}
          returnFocusTo={opener}
        />
      )}
    </>
  );
}
