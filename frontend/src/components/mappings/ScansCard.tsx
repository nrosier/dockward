import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Link } from "react-router";
import { t, type MessageKey } from "../../i18n";
import { ApiError, api } from "../../lib/api";
import type { Mapping, MappingTag, ScannerList, TagScan, TagScanState } from "../../types/api";
import { Time } from "../syncjobs/Time";
import { Button } from "../ui/Button";
import { Pill, type PillKind } from "../ui/Pill";
import { Select } from "../ui/Select";
import { Panel } from "./Panel";
import { LINK, TABLE, TD, TH } from "./styles";
import { TableScroll } from "./TableScroll";

const RESTORE_FAILED_NOTE = "sync.note.restoreFailed";

type ShownState = Exclude<TagScanState, "none">;

const STATE_KEY: Record<ShownState, MessageKey> = {
  queued: "mapping.scan.state.queued",
  running: "mapping.scan.state.running",
  waiting: "mapping.scan.state.waiting",
  ok: "mapping.scan.state.ok",
  failed: "mapping.scan.state.failed",
};

const STATE_PILL: Record<ShownState, PillKind> = {
  queued: "queued",
  running: "running",
  waiting: "running",
  ok: "done",
  failed: "failed",
};

// The fixed `sync.note.*` texts a failed scan can carry. Any other key shows no reason.
const NOTE_KEYS: Record<string, MessageKey> = {
  "sync.note.scannerForbidden": "sync.note.scannerForbidden",
  "sync.note.scanForbidden": "sync.note.scanForbidden",
  "sync.note.scannerGone": "sync.note.scannerGone",
  "sync.note.scannerFailed": "sync.note.scannerFailed",
  "sync.note.restoreFailed": "sync.note.restoreFailed",
  "sync.note.previousScannerGone": "sync.note.previousScannerGone",
  "sync.note.scannerChangedElsewhere": "sync.note.scannerChangedElsewhere",
  "sync.note.scannerUnmatched": "sync.note.scannerUnmatched",
  "sync.note.artifactGone": "sync.note.artifactGone",
};

// Catalog text for a failed start, chosen by status and message. The server text is never
// shown. The two 409 messages are fixed by the spec; the restore one is told apart by its text.
function startError(error: unknown): MessageKey {
  if (error instanceof ApiError) {
    if (error.status === 409) {
      return error.message === t("mapping.scan.restoreWaiting") ? "mapping.scan.restoreWaiting" : "mapping.scan.alreadyRunning";
    }
    if (error.status === 429) {
      return "mapping.scan.cooldown";
    }
  }
  return "errors.generic";
}

const BANNER = "rounded-[10px] border px-4 py-3";

function ScanLine({ scan }: { scan: TagScan }) {
  if (scan.state === "none") {
    return null;
  }
  const note = scan.state === "failed" && scan.note !== null ? NOTE_KEYS[scan.note] : undefined;
  return (
    <li className="flex flex-wrap items-center gap-2">
      <span>{scan.scanner_name}</span>
      <Pill kind={STATE_PILL[scan.state]} label={t(STATE_KEY[scan.state])} />
      {note === undefined ? null : <span className="text-muted">{t(note)}</span>}
    </li>
  );
}

function TagRow({ mapping, tag, lastScan, list }: { mapping: Mapping; tag: string; lastScan: string | null; list: ScannerList }) {
  const queryClient = useQueryClient();
  const base = `/mappings/${encodeURIComponent(mapping.id)}/tags/${encodeURIComponent(tag)}`;
  const [picking, setPicking] = useState(false);
  const [chosen, setChosen] = useState("");
  const [queued, setQueued] = useState(false);

  const scans = useQuery({
    queryKey: ["mapping-tag-scans", mapping.id, tag],
    queryFn: () => api<{ items: TagScan[] }>("GET", `${base}/scans`),
  });

  const start = useMutation({
    mutationFn: (scannerUuid: string | null) =>
      api<{ queued: boolean }>("POST", `${base}/scan`, scannerUuid === null ? undefined : { scanner_uuid: scannerUuid }),
    onSuccess: async () => {
      setQueued(true);
      setPicking(false);
      setChosen("");
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ["mapping-tag-scans", mapping.id, tag] }),
        queryClient.invalidateQueries({ queryKey: ["mapping-scanners", mapping.id] }),
        queryClient.invalidateQueries({ queryKey: ["sync-jobs"] }),
      ]);
    },
  });

  const lines = (scans.data?.items ?? []).filter((scan) => scan.state !== "none");

  function onScan() {
    setQueued(false);
    start.reset();
    if (list.scanner_choice === "available") {
      setPicking(true);
    } else {
      start.mutate(null);
    }
  }

  const options = list.scanners.map((scanner) => ({ value: scanner.uuid, label: scanner.name }));
  return (
    <tr>
      <td className={`${TD} font-mono text-[13px]`}>{tag}</td>
      <td className={TD}>
        <Time iso={lastScan} />
      </td>
      <td className={TD}>
        {scans.isError ? (
          <span className="text-crit-ink">{t("errors.generic")}</span>
        ) : lines.length > 0 ? (
          <ul className="flex flex-col gap-1">
            {lines.map((scan) => (
              <ScanLine key={scan.scanner_uuid} scan={scan} />
            ))}
          </ul>
        ) : scans.isSuccess ? (
          <span className="text-muted">{t("mapping.scan.notScanned")}</span>
        ) : null}
      </td>
      <td className={TD}>
        <div className="flex flex-wrap items-center gap-2">
          {picking ? (
            <>
              <div className="min-w-44">
                <label htmlFor={`scan-scanner-${tag}`} className="sr-only">
                  {t("mapping.scan.tagLabel", { tag })}
                </label>
                <Select
                  id={`scan-scanner-${tag}`}
                  value={chosen}
                  onValueChange={setChosen}
                  options={options}
                  placeholder={t("mapping.scan.chooseScanner")}
                />
              </div>
              <Button variant="primary" disabled={chosen === "" || start.isPending} onClick={() => start.mutate(chosen)}>
                {t("mapping.scan.start")}
              </Button>
            </>
          ) : (
            <Button disabled={start.isPending} onClick={onScan}>
              {t("mapping.scan.button")}
            </Button>
          )}
        </div>
        {queued ? <output className="mt-1.5 block text-ok-ink">{t("mapping.scan.queued")}</output> : null}
        {start.isError ? (
          <p role="alert" className="mt-1.5 text-crit-ink">
            {t(startError(start.error))}
          </p>
        ) : null}
      </td>
    </tr>
  );
}

function SwitchBanners({ list, restoreFailed }: { list: ScannerList; restoreFailed: boolean }) {
  return (
    <>
      {list.switch === null ? null : (
        <output className={`block ${BANNER} border-border bg-surface-2 text-text`}>
          {list.switch.state === "restore_pending"
            ? t("mapping.scan.restorePending")
            : t("mapping.scan.switchActive", { scanner: list.switch.scanner_name })}
        </output>
      )}
      {restoreFailed ? (
        <div role="alert" className={`${BANNER} border-high/50 bg-high/10 text-high-ink`}>
          {t("mapping.scan.restoreFailed")}{" "}
          <Link to="/sync-jobs" className={LINK}>
            {t("mapping.pull.viewSyncJobs")}
          </Link>
        </div>
      ) : null}
    </>
  );
}

// "Scans" card of the mapping page (#224, specs/frontend.md "Tag scans on the mapping page").
// Owner and admins only; the caller decides who sees it. The tags come from
// GET /mappings/:id/tags: the CVE view's tag set, newest scan first, up to 10.
export function ScansCard({ mapping }: { mapping: Mapping }) {
  const id = encodeURIComponent(mapping.id);
  const scanners = useQuery({
    queryKey: ["mapping-scanners", mapping.id],
    queryFn: () => api<ScannerList>("GET", `/mappings/${id}/scanners`),
  });
  const tags = useQuery({
    queryKey: ["mapping-scan-tags", mapping.id],
    queryFn: () => api<{ items: MappingTag[] }>("GET", `/mappings/${id}/tags`),
  });

  const rows = (tags.data?.items ?? []).map((item) => ({ tag: item.image_tag, lastScan: item.last_scan_at }));

  // A failed restore shows on the scan notes of the tags. Read only while a switch exists.
  const restoreFailed = useQuery({
    queryKey: ["mapping-restore-failed", mapping.id, rows.map((row) => row.tag).join(",")],
    enabled: rows.length > 0 && scanners.data?.switch != null,
    queryFn: async () => {
      const all = await Promise.all(
        rows.map((row) => api<{ items: TagScan[] }>("GET", `/mappings/${id}/tags/${encodeURIComponent(row.tag)}/scans`)),
      );
      return all.some((page) => page.items.some((scan) => scan.note === RESTORE_FAILED_NOTE));
    },
  });

  return (
    <Panel aria-labelledby="scans-heading" className="p-5">
      <h2 id="scans-heading" className="text-[15px] font-semibold">
        {t("mapping.scan.title")}
      </h2>
      <div className="mt-3 flex flex-col gap-3">
        {scanners.isError || tags.isError ? (
          <p role="alert" className="text-crit-ink">
            {t("errors.generic")}
          </p>
        ) : null}
        {scanners.data === undefined ? null : (
          <>
            <SwitchBanners list={scanners.data} restoreFailed={restoreFailed.data === true} />
            {scanners.data.scanner_choice === "unavailable" ? (
              <p className="text-muted">{t("mapping.scan.noScannerAccess")}</p>
            ) : null}
            {tags.isSuccess && rows.length === 0 ? <p className="text-muted">{t("mapping.scan.noTags")}</p> : null}
            {rows.length === 0 ? null : (
              <TableScroll label={t("mapping.scan.tableLabel")}>
                <table className={TABLE}>
                  <thead>
                    <tr>
                      <th className={TH}>{t("mapping.scan.col.tag")}</th>
                      <th className={TH}>{t("mapping.scan.col.lastScan")}</th>
                      <th className={TH}>{t("mapping.scan.col.scanners")}</th>
                      <th className={TH}>{t("mapping.scan.col.action")}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {rows.map((row) => (
                      <TagRow key={row.tag} mapping={mapping} tag={row.tag} lastScan={row.lastScan} list={scanners.data} />
                    ))}
                  </tbody>
                </table>
              </TableScroll>
            )}
          </>
        )}
      </div>
    </Panel>
  );
}
