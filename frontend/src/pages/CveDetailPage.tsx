import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ExternalLink } from "lucide-react";
import { useState } from "react";
import { Link, useNavigate, useParams, useSearchParams } from "react-router";
import { AcceptDialog } from "../components/cves/AcceptDialog";
import { CreateIssueDialog } from "../components/cves/CreateIssueDialog";
import { CveStatusPill, SeverityPill, issueEligible, scannerLabel } from "../components/cves/CvePills";
import { safeHttpsUrl } from "../components/cves/safeUrl";
import { ConfirmDialog } from "../components/mappings/ConfirmDialog";
import { LINK, TABLE, TD, TH } from "../components/mappings/styles";
import { TableScroll } from "../components/mappings/TableScroll";
import { formatDate } from "../components/jobs/dates";
import { Time } from "../components/jobs/Time";
import { Button, buttonClass } from "../components/ui/Button";
import { Panel } from "../components/mappings/Panel";
import { Pill } from "../components/ui/Pill";
import { ErrorMessage, LoadingMessage, NotFoundMessage } from "../components/ui/StatusMessage";
import { t } from "../i18n";
import { ApiError, api } from "../lib/api";
import { useMe } from "../lib/session";
import type { CveDetail } from "../types/api";
import type { Source } from "../types/sources";

const DT = "text-[11px] leading-none font-semibold tracking-[0.06em] text-muted uppercase";

export default function CveDetailPage() {
  const { id = "" } = useParams();
  const me = useMe();
  const queryClient = useQueryClient();
  const [acceptOpen, setAcceptOpen] = useState(false);
  const [falsePositiveOpen, setFalsePositiveOpen] = useState(false);
  const [revokeOpen, setRevokeOpen] = useState(false);
  const [reopenIssue, setReopenIssue] = useState(false);
  const [createOpen, setCreateOpen] = useState(false);
  const [deleteOpen, setDeleteOpen] = useState(false);
  const navigate = useNavigate();
  // The list's query, carried in `from` by the CVEs list; a direct URL has none.
  const from = useSearchParams()[0].get("from") ?? "";
  const backTo = from === "" ? "/cves" : `/cves?${from}`;

  const cveQuery = useQuery({
    queryKey: ["cve", id],
    queryFn: () => api<CveDetail>("GET", `/cves/${encodeURIComponent(id)}`),
  });
  const sourceId = cveQuery.data?.source_id;
  const sourceQuery = useQuery({
    queryKey: ["image-sources", "one", sourceId],
    queryFn: () => api<Source>("GET", `/image-sources/${encodeURIComponent(sourceId ?? "")}`),
    enabled: sourceId !== undefined,
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
    mutationFn: (reopen: boolean) =>
      api("POST", `/cves/${encodeURIComponent(id)}/unaccept`, reopen ? { reopen_issue: true } : undefined),
    onSuccess: async () => {
      setRevokeOpen(false);
      setReopenIssue(false);
      await refresh();
    },
  });

  const review = useMutation({
    mutationFn: () => api("POST", `/cves/${encodeURIComponent(id)}/review`),
    onSuccess: refresh,
  });

  const remove = useMutation({
    mutationFn: () =>
      api("DELETE", `/admin/image-sources/${encodeURIComponent(sourceId ?? "")}/cves/${encodeURIComponent(cveQuery.data?.cve_id ?? "")}`),
    onSuccess: async () => {
      setDeleteOpen(false);
      await queryClient.invalidateQueries({ queryKey: ["cves"] });
      await navigate("/cves");
    },
  });

  if (cveQuery.isPending) {
    return <LoadingMessage />;
  }
  if (cveQuery.isError) {
    return cveQuery.error instanceof ApiError && cveQuery.error.status === 404 ? <NotFoundMessage /> : <ErrorMessage />;
  }
  const cve = cveQuery.data;
  const source = sourceQuery.data;
  const admin = me.data?.role === "admin" && source !== undefined;
  const owner = source !== undefined && me.data?.id === source.user_id;
  // The owner and any admin can un-accept (#351).
  const canUnaccept = owner || admin;
  // The display name, falling back to the repository when none is set (#323).
  const sourceLabel = source === undefined ? "" : (source.name ?? source.repository);
  // The GitHub repository a new issue goes to, as owner/repo (#323).
  const issueRepository = source === undefined ? "" : `${source.github_owner}/${source.github_repo}`;
  const issueUrl = safeHttpsUrl(cve.github_issue_url);
  const conflict = createIssue.error instanceof ApiError && createIssue.error.status === 409;
  const acceptance = cve.acceptance;
  // Inline notice with the older tags that report the CVE (#196, decision 24).
  const olderTags = cve.older_tags_only
    ? cve.tags.filter((tag) => !tag.newest_digest && tag.status === "open").map((tag) => tag.image_tag)
    : [];
  const acceptanceUrl = safeHttpsUrl(cve.github_issue_url);
  // The API never returns the primary id as an alias; the UI checks too (#337).
  const aliases = (cve.aliases ?? []).filter((alias) => alias !== "" && alias !== cve.cve_id);

  return (
    <>
      <Panel className="flex flex-col gap-4 px-6 py-[22px]" aria-labelledby="cve-h">
        <Link to={backTo} className={`text-[13px] ${LINK}`}>
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
            {cve.id_reason === null ? null : (
              <p data-testid="cve-id-reason" className="text-[12.5px] text-muted">
                {t("cves.idReason")}
              </p>
            )}
            {aliases.length === 0 ? null : (
              <p data-testid="cve-alias-line" className="font-mono text-[12.5px] text-muted">
                {t("cves.detail.aliasOf", { id: cve.cve_id, alias: aliases.join(", ") })}
              </p>
            )}
            {cve.image === null ? null : (
              <p className="font-mono text-[13px] text-muted">{t("cves.detail.image", { image: cve.image })}</p>
            )}
            {olderTags.length === 0 ? null : (
              <p className="text-[13px] text-muted">{t("cves.detail.olderTagsOnly", { tags: olderTags.join(", ") })}</p>
            )}
            {cve.description === null ? null : <p className="max-w-160 text-text/85">{cve.description}</p>}
          </div>
          <div className="flex flex-wrap items-center gap-2.5">
            {cve.github_issue_number !== null ? (
              issueUrl === null ? null : (
                <a href={issueUrl} target="_blank" rel="noopener noreferrer" className={buttonClass("default")}>
                  <ExternalLink aria-hidden="true" size={14} />
                  {t("cves.action.viewIssue")}
                </a>
              )
            ) : owner && issueEligible(cve) ? (
              <Button disabled={createIssue.isPending} onClick={() => setCreateOpen(true)}>
                {t("cves.detail.createIssue")}
              </Button>
            ) : null}
            {cve.accepted && canUnaccept ? (
              <Button onClick={() => setRevokeOpen(true)}>{t("cves.detail.unaccept")}</Button>
            ) : owner && !cve.accepted ? (
              <>
                <Button onClick={() => setFalsePositiveOpen(true)}>{t("cves.detail.falsePositive")}</Button>
                <Button variant="primary" onClick={() => setAcceptOpen(true)}>
                  {t("cves.detail.accept")}
                </Button>
              </>
            ) : null}
            {admin ? (
              <Button variant="danger" onClick={() => setDeleteOpen(true)}>
                {t("cves.detail.delete")}
              </Button>
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
              {source === undefined ? null : (
                <>
                  {sourceLabel} → <span className="font-mono">{source.github_owner}/{source.github_repo}</span>
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
                  {acceptance.changed_at !== null && acceptance.change_reason !== null ? (
                    <section
                      aria-label={t("cves.detail.changed.title")}
                      className="mb-1 flex flex-col gap-1.5 rounded-md border border-crit-ink/30 px-2.5 py-2 text-[12.5px]"
                    >
                      <span className="font-semibold">{t("cves.detail.changed.title")}</span>
                      <span>{t(`cves.detail.changed.${acceptance.change_reason}`)}</span>
                      <span className="text-muted">{t("cves.detail.changed.since", { date: formatDate(acceptance.changed_at) })}</span>
                      {canUnaccept ? (
                        <div>
                          <Button disabled={review.isPending} onClick={() => review.mutate()}>
                            {t("cves.detail.changed.review")}
                          </Button>
                        </div>
                      ) : null}
                    </section>
                  ) : null}
                  <span className="font-semibold">{t(`cves.detail.verdict.${acceptance.kind}`)}</span>
                  <span>{t("cves.detail.acceptedBy", { user: acceptance.created_by })}</span>
                  <span className="text-[12.5px] text-muted">
                    {t("cves.detail.acceptedAt", { date: formatDate(acceptance.created_at) })}
                  </span>
                  <span className={acceptance.reason === "" ? "text-[12.5px] text-muted italic" : "text-[12.5px] break-words whitespace-pre-wrap"}>
                    {acceptance.reason === "" ? t("cves.detail.noNote") : acceptance.reason}
                  </span>
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
        {cve.tags.length === 0 ? (
          <p className="px-[18px] pb-4 text-[13px] text-muted">{t("cves.detail.tagsEmpty")}</p>
        ) : (
          <>
            <TableScroll label={t("cves.detail.tags")}>
              <table className={TABLE}>
                <thead>
                  <tr>
                    <th className={TH}>{t("cves.detail.col.image")}</th>
                    <th className={TH}>{t("cves.detail.col.tag")}</th>
                    <th className={TH}>{t("cves.col.status")}</th>
                    <th className={TH}>{t("cves.detail.col.lastScan")}</th>
                    <th className={TH}>{t("cves.col.fixedIn")}</th>
                    <th className={TH}>{t("cves.col.scanners")}</th>
                  </tr>
                </thead>
                <tbody>
                  {cve.tags.map((tag) => (
                    <tr key={`${tag.image}:${tag.image_tag}`}>
                      <td className={`${TD} font-mono text-[12.5px]`}>{tag.image}</td>
                      <td className={`${TD} font-mono text-[13px]`}>
                        {tag.image_tag}
                        {tag.newest_digest ? null : <span className="ml-2 font-sans text-muted">{t("cves.detail.olderTag")}</span>}
                      </td>
                      <td className={TD}>
                        <Pill kind={tag.status} />
                      </td>
                      <td className={`${TD} text-muted`}>
                        <Time iso={tag.last_scan_at} />
                      </td>
                      <td className={`${TD} font-mono text-[12.5px]`}>{tag.fixed_in_version ?? t("cves.unknown")}</td>
                      <td className={`${TD} whitespace-nowrap`}>{scannerLabel(tag.scanners)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </TableScroll>
            {cve.tags_total > cve.tags.length ? (
              <p className="px-[18px] py-3 text-[12.5px] text-muted">
                {t("cves.detail.tagsShowing", { shown: cve.tags.length, total: cve.tags_total })}
              </p>
            ) : null}
          </>
        )}
      </Panel>

      {admin ? (
        <ConfirmDialog
          open={deleteOpen}
          onOpenChange={setDeleteOpen}
          title={t("cves.delete.title", { cve: cve.cve_id })}
          description={t("cves.delete.body", { cve: cve.cve_id, source: sourceLabel })}
          confirmLabel={t("cves.delete.confirm")}
          onConfirm={() => remove.mutate()}
          pending={remove.isPending}
          danger
          error={remove.isError ? (remove.error instanceof ApiError ? remove.error.message : t("errors.generic")) : null}
        />
      ) : null}

      {owner ? (
        <>
          <AcceptDialog open={acceptOpen} onOpenChange={setAcceptOpen} cve={cve} mappingLabel={sourceLabel} />
          <AcceptDialog
            open={falsePositiveOpen}
            onOpenChange={setFalsePositiveOpen}
            cve={cve}
            mappingLabel={sourceLabel}
            kind="false_positive"
          />
          <CreateIssueDialog
            cve={createOpen ? cve : null}
            repository={issueRepository}
            pending={createIssue.isPending}
            onCancel={() => setCreateOpen(false)}
            onConfirm={() => {
              setCreateOpen(false);
              createIssue.mutate();
            }}
          />
        </>
      ) : null}
      {canUnaccept ? (
        <ConfirmDialog
          open={revokeOpen}
          onOpenChange={setRevokeOpen}
          title={t("cves.unaccept.title", { cve: cve.cve_id })}
          description={t("cves.unaccept.body")}
          confirmLabel={t("cves.detail.unaccept")}
          onConfirm={() => revoke.mutate(cve.github_issue_status === "closed" && reopenIssue)}
          pending={revoke.isPending}
          error={revoke.isError ? t("errors.generic") : null}
        >
          {cve.github_issue_status === "closed" ? (
            <label className="inline-flex cursor-pointer items-center gap-2 text-[13px]">
              <input
                type="checkbox"
                checked={reopenIssue}
                onChange={(event) => setReopenIssue(event.target.checked)}
                className="size-4 cursor-pointer accent-accent"
              />
              {t("cves.unaccept.reopen")}
            </label>
          ) : null}
        </ConfirmDialog>
      ) : null}
    </>
  );
}
