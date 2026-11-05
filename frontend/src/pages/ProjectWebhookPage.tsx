import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Link, useParams, useSearchParams } from "react-router";
import { PageHeader } from "../components/mappings/PageHeader";
import { Panel } from "../components/mappings/Panel";
import { buttonClass, Button } from "../components/ui/Button";
import { TABLE, TD, TH } from "../components/mappings/styles";
import { TableScroll } from "../components/mappings/TableScroll";
import { RotateDialog } from "../components/projectwebhook/RotateDialog";
import { ShownValues } from "../components/projectwebhook/ShownValues";
import { formatDateTime } from "../components/syncjobs/dates";
import { currentPage, Pagination } from "../components/ui/Pagination";
import { Pill } from "../components/ui/Pill";
import { ErrorMessage, LoadingMessage, NotFoundMessage } from "../components/ui/StatusMessage";
import { t } from "../i18n";
import { ApiError, api } from "../lib/api";
import { useMe } from "../lib/session";
import type {
  Page,
  ProjectWebhook,
  ProjectWebhookSecretRotated,
  ProjectWebhookTokenRotated,
  UnmatchedRepository,
} from "../types/api";

const PAGE_SIZE = 50;

// Rotated values live in component state only: never in the query cache, the URL,
// storage, or the console.
interface Shown {
  webhookUrl?: string;
  authSecret?: string;
}

function isForbidden(error: unknown): boolean {
  return error instanceof ApiError && error.status === 403;
}

function Forbidden() {
  return (
    <p role="alert" className="p-8 text-crit-ink">
      {t("projectWebhook.forbidden")}
    </p>
  );
}

function Unmatched({ id }: { id: string }) {
  const [params] = useSearchParams();
  const page = currentPage(params);
  const list = useQuery({
    queryKey: ["project-webhook", id, "unmatched", page],
    queryFn: () =>
      api<Page<UnmatchedRepository>>(
        "GET",
        `/project-webhooks/${encodeURIComponent(id)}/unmatched?page=${page}&page_size=${PAGE_SIZE}&sort=last_seen_at&order=desc`,
      ),
  });
  let body;
  if (list.isPending) {
    body = <LoadingMessage />;
  } else if (list.isError) {
    body = isForbidden(list.error) ? <Forbidden /> : <ErrorMessage />;
  } else if (list.data.items.length === 0) {
    body = <p className="text-muted">{t("projectWebhook.unmatched.empty")}</p>;
  } else {
    body = (
      <>
        <TableScroll label={t("projectWebhook.unmatched.title")}>
          <table className={TABLE}>
            <thead>
              <tr>
                <th className={TH}>{t("projectWebhook.unmatched.repository")}</th>
                <th className={TH}>{t("projectWebhook.unmatched.count")}</th>
                <th className={TH}>{t("projectWebhook.unmatched.lastSeen")}</th>
                <th className={TH}>
                  <span className="sr-only">{t("projectWebhook.unmatched.action")}</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {list.data.items.map((row) => (
                <tr key={row.repository}>
                  <td className={`${TD} font-mono text-[13px]`}>{row.repository}</td>
                  <td className={TD}>{row.count}</td>
                  <td className={`${TD} font-mono text-[13px]`}>
                    <time dateTime={row.last_seen_at} title={row.last_seen_at}>
                      {formatDateTime(row.last_seen_at)}
                    </time>
                  </td>
                  <td className={`${TD} text-right`}>
                    <Link
                      className={buttonClass("small")}
                      to={`/mappings/new?harbor_repository=${encodeURIComponent(row.repository)}`}
                    >
                      {t("projectWebhook.unmatched.createMapping")}
                    </Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </TableScroll>
        <Pagination total={list.data.total} pageSize={PAGE_SIZE} />
      </>
    );
  }
  return (
    <Panel className="flex flex-col gap-3 px-[22px] py-5" aria-labelledby="pw-unmatched">
      <div>
        <h2 id="pw-unmatched" className="text-[15px] font-semibold">
          {t("projectWebhook.unmatched.title")}
        </h2>
        <p className="mt-1 text-muted">{t("projectWebhook.unmatched.intro")}</p>
      </div>
      {body}
    </Panel>
  );
}

export default function ProjectWebhookPage() {
  const { id = "" } = useParams();
  const me = useMe();
  const client = useQueryClient();
  const [dialogOpen, setDialogOpen] = useState(false);
  const [shown, setShown] = useState<Shown | null>(null);
  const [rotateError, setRotateError] = useState<string | null>(null);

  const webhook = useQuery({
    queryKey: ["project-webhook", id],
    queryFn: () => api<ProjectWebhook>("GET", `/project-webhooks/${encodeURIComponent(id)}`),
  });

  const rotate = useMutation({
    mutationFn: async () => {
      const base = `/project-webhooks/${encodeURIComponent(id)}`;
      const values: Shown = {};
      try {
        const token = await api<ProjectWebhookTokenRotated>("POST", `${base}/rotate-token`);
        values.webhookUrl = token.webhook_url;
        const secret = await api<ProjectWebhookSecretRotated>("POST", `${base}/rotate-secret`);
        values.authSecret = secret.auth_secret;
      } catch (error) {
        // Whatever was rotated before the failure must still reach the owner.
        throw Object.assign(error instanceof Error ? error : new Error(), { values });
      }
      return values;
    },
    onSuccess: (values) => {
      setShown(values);
      setRotateError(null);
      setDialogOpen(false);
      void client.invalidateQueries({ queryKey: ["project-webhook", id] });
    },
    onError: (error: Error & { values?: Shown }) => {
      if (error.values !== undefined && (error.values.webhookUrl !== undefined || error.values.authSecret !== undefined)) {
        setShown(error.values);
        setDialogOpen(false);
      }
      setRotateError(isForbidden(error) ? t("projectWebhook.forbidden") : t("projectWebhook.rotate.failed"));
    },
  });

  if (webhook.isPending || me.isPending) {
    return <LoadingMessage />;
  }
  if (webhook.isError) {
    if (isForbidden(webhook.error)) {
      return <Forbidden />;
    }
    return webhook.error instanceof ApiError && webhook.error.status === 404 ? <NotFoundMessage /> : <ErrorMessage />;
  }

  const data = webhook.data;
  const isOwner = me.data?.username === data.owner;
  const title = t("projectWebhook.title");

  if (shown !== null) {
    return (
      <>
        <PageHeader title={title} subtitle={`${data.harbor_base_url} / ${data.harbor_project}`} />
        {rotateError === null ? null : (
          <p role="alert" className="text-[13px] text-crit-ink">
            {rotateError}
          </p>
        )}
        <ShownValues
          webhookUrl={shown.webhookUrl}
          authSecret={shown.authSecret}
          onDone={() => {
            setShown(null);
            setRotateError(null);
          }}
        />
      </>
    );
  }

  return (
    <>
      <PageHeader title={title} subtitle={`${data.harbor_base_url} / ${data.harbor_project}`}>
        <Pill kind="done" label={t("projectWebhook.active")} />
      </PageHeader>

      <Panel className="flex flex-col gap-3 px-[22px] py-5" aria-labelledby="pw-details">
        <div>
          <h2 id="pw-details" className="text-[15px] font-semibold">
            {t("projectWebhook.details.title")}
          </h2>
          <p className="mt-1 text-muted">{t("projectWebhook.details.intro")}</p>
        </div>
        <table className={TABLE}>
          <tbody>
            <tr>
              <th scope="row" className={`${TH} w-[30%]`}>
                {t("projectWebhook.owner")}
              </th>
              <td className={TD}>{isOwner ? `${t("projectWebhook.owner.you")} (${data.owner})` : data.owner}</td>
            </tr>
            <tr>
              <th scope="row" className={TH}>
                {t("projectWebhook.created")}
              </th>
              <td className={`${TD} font-mono text-[13px]`}>{formatDateTime(data.created_at)}</td>
            </tr>
            <tr>
              <th scope="row" className={TH}>
                {t("projectWebhook.rotated")}
              </th>
              <td className={`${TD} font-mono text-[13px]`}>
                {data.rotated_at === null ? t("projectWebhook.rotated.never") : formatDateTime(data.rotated_at)}
              </td>
            </tr>
            <tr>
              <th scope="row" className={TH}>
                {t("projectWebhook.mappingsReceiving")}
              </th>
              <td className={TD}>{data.mappings.length}</td>
            </tr>
          </tbody>
        </table>
        {isOwner ? (
          <div>
            <Button
              onClick={() => {
                setRotateError(null);
                setDialogOpen(true);
              }}
            >
              {t("projectWebhook.action.rotate")}
            </Button>
          </div>
        ) : null}
      </Panel>

      <Unmatched id={id} />

      {isOwner ? (
        <RotateDialog
          open={dialogOpen}
          onOpenChange={setDialogOpen}
          mappings={data.mappings}
          pending={rotate.isPending}
          error={rotateError}
          onConfirm={() => rotate.mutate()}
        />
      ) : null}
    </>
  );
}
