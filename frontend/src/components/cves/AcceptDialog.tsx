import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useState, type FormEvent } from "react";
import { t } from "../../i18n";
import { ApiError, api } from "../../lib/api";
import { INPUT, TEXTAREA } from "../mappings/styles";
import { Button } from "../ui/Button";
import { Dialog } from "../ui/Dialog";
import { Field } from "../ui/Field";
import type { AcceptanceKind, CveDetail } from "../../types/api";

// The end of the chosen day in UTC, as RFC 3339.
export function endOfDayUtc(date: string): string {
  return `${date}T23:59:59Z`;
}

// The text and endpoint of each verdict. A false positive uses the same form as Accept risk.
const VERDICT = {
  accepted: {
    path: "accept",
    title: "cves.accept.title",
    body: "cves.accept.body",
    issueNote: "cves.accept.issueNote",
    submit: "cves.accept.submit",
  },
  false_positive: {
    path: "false-positive",
    title: "cves.falsePositive.title",
    body: "cves.falsePositive.body",
    issueNote: "cves.falsePositive.issueNote",
    submit: "cves.falsePositive.submit",
  },
} as const;

interface AcceptDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  cve: CveDetail;
  mappingLabel: string;
  // Which verdict the dialog records; Accept risk when left out.
  kind?: AcceptanceKind;
}

export function AcceptDialog({ open, onOpenChange, cve, mappingLabel, kind = "accepted" }: AcceptDialogProps) {
  const text = VERDICT[kind];
  const queryClient = useQueryClient();
  const [reason, setReason] = useState("");
  const [expires, setExpires] = useState("");
  const [error, setError] = useState<string | null>(null);

  const accept = useMutation({
    mutationFn: () =>
      api("POST", `/cves/${encodeURIComponent(cve.id)}/${text.path}`, {
        reason: reason.trim(),
        expires_at: expires === "" ? null : endOfDayUtc(expires),
      }),
    onSuccess: async () => {
      onOpenChange(false);
      setReason("");
      setExpires("");
      setError(null);
      await queryClient.invalidateQueries({ queryKey: ["cves"] });
      await queryClient.invalidateQueries({ queryKey: ["cve", cve.id] });
    },
    onError: (failure) => {
      setError(failure instanceof ApiError && failure.status === 422 ? failure.message : t("errors.generic"));
    },
  });

  const issueNote =
    cve.github_issue_status === "open" && cve.github_issue_number !== null
      ? ` ${t(text.issueNote, { number: cve.github_issue_number })}`
      : "";

  function submit(event: FormEvent) {
    event.preventDefault();
    if (accept.isPending) {
      return;
    }
    setError(null);
    accept.mutate();
  }

  return (
    <Dialog
      open={open}
      onOpenChange={onOpenChange}
      title={t(text.title, { cve: cve.cve_id })}
      description={`${t(text.body, { mapping: mappingLabel })}${issueNote}`}
    >
      <form onSubmit={submit} className="flex flex-col gap-4">
        <Field id={`${kind}-reason`} label={t("cves.accept.reason")} help={t("cves.accept.reasonHelp")}>
          <textarea
            id={`${kind}-reason`}
            aria-describedby={`${kind}-reason-help`}
            value={reason}
            onChange={(event) => setReason(event.target.value)}
            className={TEXTAREA}
          />
        </Field>
        <Field id={`${kind}-expires`} label={t("cves.accept.expires")} help={t("cves.accept.expiresHelp")}>
          <input
            id={`${kind}-expires`}
            type="date"
            value={expires}
            onChange={(event) => setExpires(event.target.value)}
            aria-describedby={`${kind}-expires-help`}
            className={INPUT}
          />
        </Field>
        {error === null ? null : (
          <p role="alert" className="text-[13px] text-crit-ink">
            {error}
          </p>
        )}
        <div className="flex flex-wrap justify-end gap-2.5">
          <Button onClick={() => onOpenChange(false)}>{t("mappings.cancel")}</Button>
          <Button type="submit" variant="primary" disabled={accept.isPending}>
            {t(text.submit)}
          </Button>
        </div>
      </form>
    </Dialog>
  );
}
