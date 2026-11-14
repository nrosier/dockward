import { useQuery } from "@tanstack/react-query";
import { useState, type RefObject } from "react";
import { t } from "../../i18n";
import { api } from "../../lib/api";
import grypeLicence from "../../licenses/grype-apache-2.0.txt?raw";
import dockwardLicence from "../../licenses/dockward-mit.txt?raw";
import trivyLicence from "../../licenses/trivy-apache-2.0.txt?raw";
import trivyNotice from "../../licenses/trivy-notice.txt?raw";
import { Button } from "../ui/Button";
import { Dialog } from "../ui/Dialog";

interface About {
  dockward: string;
  trivy: string | null;
  grype: string | null;
}

type Licence = "dockward" | "trivy" | "grype";

// The licence texts ship in the frontend bundle, so the dialog works offline. The Trivy and
// Grype texts are the upstream files of the pinned releases, the same ones the image carries
// under /usr/share/licenses (specs/frontend.md, "About dialog").
const LICENCES: { key: Licence; name: string; label: string; text: string }[] = [
  { key: "dockward", name: "dockward", label: "MIT", text: dockwardLicence },
  { key: "trivy", name: "Trivy", label: "Apache-2.0", text: `${trivyLicence}\n${trivyNotice}` },
  { key: "grype", name: "Grype", label: "Apache-2.0", text: grypeLicence },
];

const TH = "w-[34%] px-2 py-[7px] text-left align-top font-semibold text-muted";
const TD = "px-2 py-[7px] align-top";
const SECTION = "mt-1 text-xs font-semibold tracking-[.04em] text-muted uppercase";

interface AboutDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  // The header version button. Focus returns to it on close.
  returnFocusTo: RefObject<HTMLElement | null>;
}

export function AboutDialog({ open, onOpenChange, returnFocusTo }: AboutDialogProps) {
  const [shown, setShown] = useState<Licence>("dockward");
  const about = useQuery({
    queryKey: ["about"],
    queryFn: () => api<About>("GET", "/about"),
    enabled: open,
    // Read once at startup on the server, so it cannot change while the page is open.
    staleTime: Infinity,
  });
  const value = (version: string | null | undefined) => {
    if (about.isPending) {
      return t("common.loading");
    }
    return version ?? t("about.unknown");
  };
  const unknown = (version: string | null | undefined) =>
    !about.isPending && version == null ? "text-med-ink" : "";
  const current = LICENCES.find((licence) => licence.key === shown) ?? LICENCES[0];

  return (
    <Dialog
      open={open}
      onOpenChange={onOpenChange}
      onCloseAutoFocus={(event) => {
        event.preventDefault();
        returnFocusTo.current?.focus();
      }}
      title={t("about.title")}
      description={t("about.subtitle", { version: about.data?.dockward ?? APP_VERSION })}
    >
      {about.isError ? <p role="alert" className="text-[13px] text-crit-ink">{t("about.loadFailed")}</p> : null}
      <table className="w-full border-collapse text-[13px]">
        <tbody>
          {(
            [
              ["dockward", about.data?.dockward],
              ["trivy", about.data?.trivy],
              ["grype", about.data?.grype],
            ] as const
          ).map(([key, version]) => (
            <tr key={key} className="border-b border-border">
              <th scope="row" className={TH}>
                {t(`about.versions.${key}`)}
              </th>
              <td className={`${TD} font-mono ${unknown(version)}`}>{value(version)}</td>
            </tr>
          ))}
        </tbody>
      </table>

      <h3 className={SECTION}>{t("about.licences.title")}</h3>
      <table className="w-full border-collapse text-[13px]">
        <tbody>
          {LICENCES.map((licence) => (
            <tr key={licence.key} className="border-b border-border">
              <th scope="row" className={TH}>
                {licence.name}
              </th>
              <td className={TD}>
                {t(`about.licences.${licence.key}`)}{" "}
                <button
                  type="button"
                  aria-pressed={shown === licence.key}
                  aria-label={t("about.licences.fullTextFor", { name: licence.name })}
                  onClick={() => setShown(licence.key)}
                  className="font-mono text-accent underline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent"
                >
                  {t("about.licences.fullText")}
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      <h3 className={SECTION}>{t("about.licences.textTitle", { name: current.label })}</h3>
      <textarea
        readOnly
        value={current.text}
        aria-label={t("about.licences.textLabel")}
        className="h-60 w-full resize-none rounded-md border border-border bg-surface-2 p-2.5 font-mono text-xs text-muted focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent"
      />

      <div className="flex justify-end gap-2">
        <Button variant="primary" onClick={() => onOpenChange(false)}>
          {t("common.close")}
        </Button>
      </div>
    </Dialog>
  );
}
