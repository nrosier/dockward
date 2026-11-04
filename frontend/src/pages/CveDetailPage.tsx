import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ExternalLink } from "lucide-react";
import { useState } from "react";
import { Link, useParams } from "react-router";
import { AcceptDialog } from "../components/cves/AcceptDialog";
import { CveStatusPill, SeverityPill, issueEligible } from "../components/cves/CvePills";
import { safeHttpsUrl } from "../components/cves/safeUrl";
import { ConfirmDialog } from "../components/mappings/ConfirmDialog";
import { LINK, TABLE, TD, TH } from "../components/mappings/styles";
import { TableScroll } from "../components/mappings/TableScroll";
import { mappingName } from "../components/mappings/useMappings";
import { formatDate } from "../components/syncjobs/dates";
import { Time } from "../components/syncjobs/Time";
import { Button, buttonClass } from "../components/ui/Button";
import { Panel } from "../components/mappings/Panel";
import { Pill } from "../components/ui/Pill";
import { ErrorMessage, LoadingMessage, NotFoundMessage } from "../components/ui/StatusMessage";
import { t } from "../i18n";
import { ApiError, api } from "../lib/api";
import { useMe } from "../lib/session";
import type { CveDetail, Mapping } from "../types/api";

const DT = "text-[11px] leading-none font-semibold tracking-[0.06em] text-muted uppercase";

export default function CveDetailPage() {
  const { id = "" } = useParams();
  const me = useMe();
  const queryClient = useQueryClient();
  const [acceptOpen, setAcceptOpen] = useState(false);
  const [revokeOpen, setRevokeOpen] = useState(false);

  const cveQuery = useQuery({
    queryKey: ["cve", id],
    queryFn: () => api<CveDetail>("GET", `/cves/${encodeURIComponent(id)}`),
  });
  const mappingId = cveQuery.data?.mapping_id;
  const mappingQuery = useQuery({
    queryKey: ["mappings", "one", mappingId],
    queryFn: () => api<Mapping>("GET", `/mappings/${encodeURIComponent(mappingId ?? "")}`),
    enabled: mappingId !== undefined,
  });

  const refresh = async () => {
    await queryClient.invalidateQueries({ queryKey: ["cve", id] });
    await queryClient.invalidateQueries({ queryKey: ["cves"] });
  };

  const createIssue = useMutation({
    mutationFn: () => api("POST", `/cves/${encodeURIComponent(id)}/issue`),
    onSuccess: refresh,
  });
  const revoke = useMutation({
    mutationFn: () => api("POST", `/cves/${encodeURIComponent(id)}/unaccept`),
    onSuccess: async () => {
      setRevokeOpen(false);
      await refresh();
    },
  });

  if (cveQuery.isPending) {
    return <LoadingMessage />;
  }
  if (cveQuery.isError) {
    return cveQuery.error instanceof ApiError && cveQuery.error.status === 404 ? <NotFoundMessage /> : <ErrorMessage />;
  }
  const cve = cveQuery.data;
  const mapping = mappingQuery.data;
  const owner = mapping !== undefined && me.data?.id === mapping.user_id;
  const mappingLabel = mapping === undefined ? "" : mappingName(mapping);
  const issueUrl = safeHttpsUrl(cve.github_issue_url);
  const openIssue = cve.github_issue_status === "open";
  const conflict = createIssue.error instanceof ApiError && createIssue.error.status === 409;
  const acceptance = cve.acceptance;
  const acceptanceUrl = safeHttpsUrl(cve.github_issue_url);

  return (
    <>
      <Panel className="flex flex-col gap-4 px-6 py-[22px]" aria-labelledby="cve-h">
        <Link to="/cves" className={`text-[13px] ${LINK}`}>
          {t("cves.back")}
        </Link>
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div className="flex min-w-0 flex-[1_1_20rem] flex-col gap-2.5">
            <div className="flex flex-wrap items-center gap-3">
              <h1 id="cve-h" className="font-mono text-2xl font-medium tracking-tight">
                {cve.cve_id}
              </h1>
              <SeverityPill severity={cve.severity} />
              <CveStatusPill cve={cve} />
            </div>
            {cve.description === null ? null : <p className="max-w-160 text-text/85">{cve.description}</p>}
          </div>
          <div className="flex flex-wrap items-center gap-2.5">
            {issueUrl === null || cve.github_issue_number === null ? null : (
              <a href={issueUrl} target="_blank" rel="noopener noreferrer" className={buttonClass("default")}>
                <ExternalLink aria-hidden="true" size={14} />
                {t("cves.detail.issueLink", { number: cve.github_issue_number })}
              </a>
            )}
            {owner && issueEligible(cve.severity) ? (
              <Button
                disabled={openIssue || createIssue.isPending}
                title={openIssue ? t("cves.detail.createIssueDisabled") : undefined}
                onClick={() => createIssue.mutate()}
              >
                {t("cves.detail.createIssue")}
              </Button>
            ) : null}
            {owner ? (
              cve.accepted ? (
                <Button onClick={() => setRevokeOpen(true)}>{t("cves.detail.revoke")}</Button>
              ) : (
                <Button variant="primary" onClick={() => setAcceptOpen(true)}>
                  {t("cves.detail.accept")}
                </Button>
              )
            ) : null}
          </div>
        </div>

        {conflict ? (
          <p role="alert" className="text-[13px] text-crit-ink">
            {t("cves.detail.issueConflict")}
            {acceptanceUrl === null ? null : (
              <>
                {" "}
                <a href={acceptanceUrl} target="_blank" rel="noopener noreferrer" className={LINK}>
                  {t("cves.detail.issueConflictLink")}
                </a>
              </>
            )}
          </p>
        ) : createIssue.isError ? (
          <p role="alert" className="text-[13px] text-crit-ink">
            {createIssue.error instanceof ApiError ? createIssue.error.message : t("errors.generic")}
          </p>
        ) : null}

        <dl className="m-0 grid grid-cols-[repeat(auto-fit,minmax(160px,1fr))] gap-4 border-t border-border pt-4">
          <div className="flex flex-col gap-1.5">
            <dt className={DT}>{t("cves.detail.package")}</dt>
            <dd className="m-0">{cve.package}</dd>
          </div>
          <div className="flex flex-col gap-1.5">
            <dt className={DT}>{t("cves.detail.mapping")}</dt>
            <dd className="m-0">
              {mapping === undefined ? null : (
                <>
                  {mappingLabel} → <span className="font-mono">{mapping.github_owner}/{mapping.github_repo}</span>
                </>
              )}
            </dd>
          </div>
          <div className="flex flex-col gap-1.5">
            <dt className={DT}>{t("cves.detail.firstSeen")}</dt>
            <dd className="m-0" title={cve.first_seen_at ?? undefined}>
              {formatDate(cve.first_seen_at)}
            </dd>
          </div>
          <div className="flex flex-col gap-1.5">
            <dt className={DT}>{t("cves.detail.acceptance")}</dt>
            <dd className="m-0">
              {acceptance === null ? (
                <span className="text-muted">{t("cves.detail.notAccepted")}</span>
              ) : (
                <div className="flex flex-col gap-1">
                  <span>{t("cves.detail.acceptedBy", { user: acceptance.created_by })}</span>
                  <span className="text-[12.5px] text-muted">{acceptance.reason}</span>
                  <span className="text-[12.5px] text-muted">
                    {acceptance.expires_at === null
                      ? t("cves.detail.noExpiry")
                      : t("cves.detail.expires", { date: formatDate(acceptance.expires_at) })}
                  </span>
                </div>
              )}
            </dd>
          </div>
        </dl>
      </Panel>

      <Panel aria-labelledby="tags-h">
        <div className="flex flex-wrap items-baseline justify-between gap-2 px-[18px] pt-4 pb-2">
          <h2 id="tags-h" className="text-[15px] font-semibold">
            {t("cves.detail.tags")}
          </h2>
          <span className="text-[12.5px] text-muted">
            {t("cves.detail.tagsNote", { open: cve.open_tags, tracked: cve.tracked_tags })}
          </span>
        </div>
        <TableScroll label={t("cves.detail.tags")}>
          <table className={TABLE}>
            <thead>
              <tr>
                <th className={TH}>{t("cves.detail.col.tag")}</th>
                <th className={TH}>{t("cves.col.status")}</th>
                <th className={TH}>{t("cves.detail.col.lastScan")}</th>
                <th className={TH}>{t("cves.col.fixedIn")}</th>
              </tr>
            </thead>
            <tbody>
              {cve.tags.map((tag) => (
                <tr key={tag.image_tag}>
                  <td className={`${TD} font-mono text-[13px]`}>{tag.image_tag}</td>
                  <td className={TD}>
                    <Pill kind={tag.status === "fixed" ? "fixed" : "open"} />
                  </td>
                  <td className={`${TD} text-muted`}>
                    <Time iso={tag.last_scan_at} />
                  </td>
                  <td className={`${TD} font-mono text-[12.5px]`}>{tag.fixed_in_version ?? t("cves.unknown")}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </TableScroll>
      </Panel>

      {owner ? (
        <>
          <AcceptDialog open={acceptOpen} onOpenChange={setAcceptOpen} cve={cve} mappingLabel={mappingLabel} />
          <ConfirmDialog
            open={revokeOpen}
            onOpenChange={setRevokeOpen}
            title={t("cves.revoke.title", { cve: cve.cve_id })}
            description={t("cves.revoke.body")}
            confirmLabel={t("cves.detail.revoke")}
            onConfirm={() => revoke.mutate()}
            pending={revoke.isPending}
            error={revoke.isError ? t("errors.generic") : null}
          />
        </>
      ) : null}
    </>
  );
}
