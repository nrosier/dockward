import { useQuery } from "@tanstack/react-query";
import { t } from "../../i18n";
import { api } from "../../lib/api";
import { toIso } from "../../lib/sourceValidation";
import type { Page } from "../../types/api";
import type { PlatformState, ScanStatus, SourceImage } from "../../types/sources";
import { TABLE, TD, TH } from "../mappings/styles";
import { TableScroll } from "../mappings/TableScroll";
import { Time } from "../jobs/Time";
import { TagActions } from "./TagActions";
import { Card } from "../ui/Card";
import { Pill, type PillKind } from "../ui/Pill";
import { ErrorMessage, LoadingMessage } from "../ui/StatusMessage";

const STATE_PILL: Record<PlatformState, PillKind> = {
  queued: "queued",
  pulling: "running",
  stored: "done",
  evicting: "running",
  evicted: "queued",
  failed: "failed",
};

const SCAN_PILL: Record<ScanStatus, PillKind> = {
  queued: "queued",
  running: "running",
  done: "done",
  failed: "failed",
};

export function ImagesTable({ sourceId }: { sourceId: string }) {
  const images = useQuery({
    queryKey: ["sources", sourceId, "images"],
    queryFn: () => api<Page<SourceImage> | SourceImage[]>("GET", `/image-sources/${sourceId}/images`),
  });
  if (images.isPending) {
    return <LoadingMessage />;
  }
  if (images.isError) {
    return <ErrorMessage />;
  }
  const items = Array.isArray(images.data) ? images.data : images.data.items;
  const rows = items.flatMap((image) => image.platforms.map((platform, index) => ({ image, platform, first: index === 0 })));
  return (
    <Card aria-labelledby="source-images">
      <h2 id="source-images" className="px-5 pt-5 text-[15px] font-semibold">
        {t("sources.images.title")}
      </h2>
      {rows.length === 0 ? (
        <p className="p-5 text-muted">{t("sources.images.empty")}</p>
      ) : (
        <TableScroll label={t("sources.images.title")}>
          <table className={TABLE}>
            <thead>
              <tr>
                <th className={TH}>{t("sources.images.col.tag")}</th>
                <th className={TH}>{t("sources.images.col.platform")}</th>
                <th className={TH}>{t("sources.images.col.state")}</th>
                <th className={TH}>{t("sources.images.col.pulled")}</th>
                <th className={TH}>{t("sources.images.col.scans")}</th>
                <th className={TH}>{t("sources.images.col.actions")}</th>
              </tr>
            </thead>
            <tbody>
              {rows.map(({ image, platform, first }) => (
                <tr key={platform.id}>
                  <td className={TD}>
                    <span className="font-mono text-[12.5px]">{image.tags.join(", ")}</span>
                  </td>
                  <td className={`${TD} text-muted`}>{platform.platform}</td>
                  <td className={TD}>
                    <Pill kind={STATE_PILL[platform.state]} label={t(`sources.state.${platform.state}`)} />
                  </td>
                  <td className={`${TD} text-muted`}>
                    <Time iso={toIso(platform.pulled_at)} />
                  </td>
                  <td className={TD}>
                    {platform.scans.length === 0 ? (
                      <span className="text-muted">{t("sources.images.noScans")}</span>
                    ) : (
                      <div className="flex flex-wrap items-center gap-x-4 gap-y-1.5">
                        {platform.scans.map((scan) => (
                          <span key={scan.scanner} className="inline-flex items-center gap-2">
                            <span className="text-[12.5px] font-medium">{scan.scanner}</span>
                            <Pill kind={SCAN_PILL[scan.status]} />
                          </span>
                        ))}
                      </div>
                    )}
                  </td>
                  <td className={TD}>
                    {first && image.tags.length > 0 ? <TagActions sourceId={sourceId} tag={image.tags[0]} /> : null}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </TableScroll>
      )}
    </Card>
  );
}
