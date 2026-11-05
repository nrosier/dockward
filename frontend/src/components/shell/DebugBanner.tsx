import { t } from "../../i18n";
import { useLogLevel } from "../../lib/appLog";
import { formatDateTime } from "../admin/parts";

// Shown on every admin page while the level is above info, that is whenever
// the backend reports a revert time.
export function DebugBanner() {
  const status = useLogLevel();
  const revertsAt = status.data?.reverts_at ?? null;
  if (revertsAt === null) {
    return null;
  }
  // The minutes left count from the last fetch, which repeats every 30 seconds.
  const now = status.dataUpdatedAt;
  const end = new Date(revertsAt).getTime();
  const minutes = Number.isNaN(end) ? 0 : Math.max(0, Math.ceil((end - now) / 60_000));
  return (
    <output className="block rounded-lg border border-high/45 bg-high/12 px-4 py-3 text-[13px] text-high-ink">
      <strong>{t("adminLog.debugBanner.title")}</strong>{" "}
      <span>{t("adminLog.debugBanner.revertsAt", { time: formatDateTime(revertsAt), minutes })}</span>
    </output>
  );
}
