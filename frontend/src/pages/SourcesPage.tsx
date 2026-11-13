import { useSearchParams, Link } from "react-router";
import { useHubs, useSources } from "../components/sources/useSources";
import { PageHeader } from "../components/mappings/PageHeader";
import { INPUT, LINK, TABLE, TD, TH } from "../components/mappings/styles";
import { TableScroll } from "../components/mappings/TableScroll";
import { Time } from "../components/jobs/Time";
import { buttonClass } from "../components/ui/Button";
import { Card } from "../components/ui/Card";
import { ErrorMessage, LoadingMessage } from "../components/ui/StatusMessage";
import { t } from "../i18n";
import { namespaceOf, toIso } from "../lib/sourceValidation";

export default function SourcesPage() {
  const sources = useSources();
  const hubs = useHubs();
  const [params, setParams] = useSearchParams();
  const namespace = params.get("namespace") ?? "";
  const tag = params.get("tag") ?? "";

  function setParam(name: string, value: string) {
    const updated = new URLSearchParams(params);
    if (value === "") {
      updated.delete(name);
    } else {
      updated.set(name, value);
    }
    setParams(updated, { replace: true });
  }

  const header = (
    <PageHeader title={t("page.sources")} subtitle={t("sources.subtitle")}>
      <Link to="/sources/new" className={buttonClass("primary")}>
        {t("sources.add")}
      </Link>
    </PageHeader>
  );

  if (sources.isPending) {
    return (
      <>
        {header}
        <LoadingMessage />
      </>
    );
  }
  if (sources.isError) {
    return (
      <>
        {header}
        <ErrorMessage />
      </>
    );
  }

  const all = sources.data.items;
  const namespaces = Array.from(new Set(all.map((source) => namespaceOf(source.repository)))).sort();
  const hubHost = new Map((hubs.data ?? []).map((hub) => [hub.id, hub.host]));
  const needle = tag.trim().toLowerCase();
  const rows = all.filter(
    (source) =>
      (namespace === "" || namespaceOf(source.repository) === namespace) &&
      (needle === "" || source.tag_value.toLowerCase().includes(needle)),
  );

  return (
    <>
      {header}
      <div className="flex flex-wrap items-center gap-2.5">
        <label htmlFor="sources-namespace" className="sr-only">
          {t("sources.filter.namespace")}
        </label>
        <select
          id="sources-namespace"
          value={namespace}
          onChange={(event) => setParam("namespace", event.target.value)}
          className={`${INPUT} w-auto!`}
        >
          <option value="">{t("sources.filter.allNamespaces")}</option>
          {namespaces.map((name) => (
            <option key={name} value={name}>
              {name}
            </option>
          ))}
        </select>
        <label htmlFor="sources-tag" className="sr-only">
          {t("sources.filter.tag")}
        </label>
        <input
          id="sources-tag"
          type="search"
          value={tag}
          onChange={(event) => setParam("tag", event.target.value)}
          placeholder={t("sources.filter.tagPlaceholder")}
          className={`${INPUT} w-auto!`}
        />
      </div>
      <Card>
        {rows.length === 0 ? (
          <p className="p-5 text-muted">{t("sources.empty")}</p>
        ) : (
          <TableScroll label={t("page.sources")}>
            <table className={TABLE}>
              <thead>
                <tr>
                  <th className={TH}>{t("sources.col.hub")}</th>
                  <th className={TH}>{t("sources.col.repository")}</th>
                  <th className={TH}>{t("sources.col.tag")}</th>
                  <th className={TH}>{t("sources.col.github")}</th>
                  <th className={TH}>{t("sources.col.lastDiscovery")}</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((source) => (
                  <tr key={source.id}>
                    <td className={`${TD} text-muted`}>{hubHost.get(source.hub_id) ?? ""}</td>
                    <td className={TD}>
                      <Link to={`/sources/${source.id}`} className={LINK}>
                        {source.repository}
                      </Link>
                    </td>
                    <td className={`${TD} font-mono text-[12.5px]`}>{source.tag_value}</td>
                    <td className={`${TD} text-muted`}>
                      {source.github_owner}/{source.github_repo}
                    </td>
                    <td className={`${TD} text-muted`}>
                      {toIso(source.last_discovery_at) === null ? (
                        t("sources.neverDiscovered")
                      ) : (
                        <Time iso={toIso(source.last_discovery_at)} />
                      )}
                      {source.discovery_status !== "idle" && (
                        <span className="ml-2">{t(`sources.discovery.${source.discovery_status}`)}</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </TableScroll>
        )}
      </Card>
    </>
  );
}
