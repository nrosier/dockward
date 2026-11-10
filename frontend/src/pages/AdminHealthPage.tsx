import { useQuery } from "@tanstack/react-query";
import { Badge, CardHeading, ROW, TD, TH } from "../components/admin/parts";
import { HEALTH_INTERVAL_MS } from "../components/shell/Topbar";
import { Button } from "../components/ui/Button";
import { Card } from "../components/ui/Card";
import { ErrorMessage, LoadingMessage } from "../components/ui/StatusMessage";
import { t } from "../i18n";
import { api } from "../lib/api";
import type { HealthCheck, HealthReport } from "../types/api";

function CheckPill({ check }: { check: HealthCheck }) {
  if (!check.reachable) {
    return <Badge tone="crit">{t("admin.health.unreachable")}</Badge>;
  }
  if (check.missing_permissions.length > 0) {
    return <Badge tone="crit">{t("admin.health.missing", { list: check.missing_permissions.join(", ") })}</Badge>;
  }
  return check.ok ? <Badge tone="ok">{t("admin.health.ok")}</Badge> : <Badge tone="warn">{t("admin.health.check")}</Badge>;
}

function ChecksCard({ id, title, checks }: { id: string; title: string; checks: HealthCheck[] }) {
  return (
    <Card className="flex flex-col gap-3 py-5" aria-labelledby={id}>
      <div className="px-5">
        <CardHeading id={id} title={title} />
      </div>
      {checks.length === 0 ? <p className="px-5 text-muted">{t("admin.health.none")}</p> : null}
      <table className="w-full border-collapse">
        <tbody>
          {checks.map((check) => (
            <tr key={`${check.credential_id}-${check.target ?? ""}`} className={ROW}>
              <td className={TD}>
                <div>{check.target ? `${check.label} · ${check.target}` : check.label}</div>
                <div className="text-xs text-muted">{check.detail}</div>
              </td>
              <td className={`${TD} text-right`}>
                <CheckPill check={check} />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </Card>
  );
}

function ScanPill({ state }: { state: HealthCheck["code_scanning"] }) {
  if (state === "ok") {
    return <Badge tone="ok">{t("admin.health.scan.ok")}</Badge>;
  }
  if (state === "no_analysis_yet") {
    return <Badge tone="neutral">{t("admin.health.scan.none")}</Badge>;
  }
  return <Badge tone="crit">{t("admin.health.scan.unavailable")}</Badge>;
}

export default function AdminHealthPage() {
  // The same key and staleTime as the Topbar, so both share one request.
  const health = useQuery({
    queryKey: ["admin", "health"],
    queryFn: () => api<HealthReport>("GET", "/admin/health"),
    staleTime: HEALTH_INTERVAL_MS,
    refetchInterval: HEALTH_INTERVAL_MS,
  });

  if (health.isPending) {
    return <LoadingMessage />;
  }
  if (health.isError) {
    return <ErrorMessage />;
  }
  const report = health.data;
  const targets = report.github.filter((check) => check.target !== null);

  return (
    <div className="flex flex-col gap-5">
      <div className="flex justify-end">
        <Button disabled={health.isFetching} onClick={() => void health.refetch()}>
          {health.isFetching ? t("admin.health.checking") : t("admin.health.checkNow")}
        </Button>
      </div>
      <div className="grid grid-cols-1 gap-5">
        <ChecksCard id="health-github" title={t("admin.health.github")} checks={report.github} />
      </div>

      <Card className="flex flex-col gap-3 py-5" aria-labelledby="health-scan">
        <div className="px-5">
          <CardHeading id="health-scan" title={t("admin.health.scan.title")} />
        </div>
        <div className="overflow-x-auto">
          <table className="w-full border-collapse">
            <thead>
              <tr>
                <th className={TH}>{t("admin.health.col.repository")}</th>
                <th className={TH}>{t("admin.health.col.state")}</th>
              </tr>
            </thead>
            <tbody>
              {targets.map((check) => (
                <tr key={`${check.credential_id}-${check.target}`} className={ROW}>
                  <td className={`${TD} font-mono text-xs`}>{check.target}</td>
                  <td className={TD}>
                    <ScanPill state={check.code_scanning} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>

      <Card className="flex flex-col gap-3 p-5" aria-labelledby="health-request">
        <CardHeading id="health-request" title={t("admin.health.request")} help={t("admin.health.requestHelp")} />
        <dl className="m-0 grid grid-cols-1 gap-4 sm:grid-cols-2">
          <div className="flex flex-col gap-0.5">
            <dt className="text-xs text-muted">{t("admin.health.clientIp")}</dt>
            <dd className="m-0 font-mono text-[13px]">{report.request.client_ip}</dd>
          </div>
          <div className="flex flex-col gap-0.5">
            <dt className="text-xs text-muted">{t("admin.health.source")}</dt>
            <dd className="m-0 text-[13px]">
              {report.request.source === "peer" ? t("admin.health.source.peer") : t("admin.health.source.xff")}
            </dd>
          </div>
        </dl>
      </Card>
    </div>
  );
}
