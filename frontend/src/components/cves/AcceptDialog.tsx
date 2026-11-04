import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useState, type FormEvent } from "react";
import { t } from "../../i18n";
import { ApiError, api } from "../../lib/api";
import { INPUT, TEXTAREA } from "../mappings/styles";
import { Button } from "../ui/Button";
import { Dialog } from "../ui/Dialog";
import { Field } from "../ui/Field";
import type { CveDetail } from "../../types/api";

// The end of the chosen day in UTC, as RFC 3339.
export function endOfDayUtc(date: string): string {
  return `${date}T23:59:59Z`;
}

interface AcceptDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  cve: CveDetail;
  mappingLabel: string;
}

export function AcceptDialog({ open, onOpenChange, cve, mappingLabel }: AcceptDialogProps) {
  const queryClient = useQueryClient();
  const [reason, setReason] = useState("");
  const [expires, setExpires] = useState("");
  const [error, setError] = useState<string | null>(null);

  const accept = useMutation({
    mutationFn: () =>
      api("POST", `/cves/${encodeURIComponent(cve.id)}/accept`, {
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
      ? ` ${t("cves.accept.issueNote", { number: cve.github_issue_number })}`
      : "";

  function submit(event: FormEvent) {
    event.preventDefault();
    if (reason.trim() === "" || accept.isPending) {
      return;
    }
    setError(null);
    accept.mutate();
  }

  return (
    <Dialog
      open={open}
      onOpenChange={onOpenChange}
      title={t("cves.accept.title", { cve: cve.cve_id })}
      description={`${t("cves.accept.body", { mapping: mappingLabel })}${issueNote}`}
    >
      <form onSubmit={submit} className="flex flex-col gap-4">
        <Field id="accept-reason" label={t("cves.accept.reason")}>
          <textarea
            id="accept-reason"
            required
            value={reason}
            onChange={(event) => setReason(event.target.value)}
            className={TEXTAREA}
          />
        </Field>
        <Field id="accept-expires" label={t("cves.accept.expires")} help={t("cves.accept.expiresHelp")}>
          <input
            id="accept-expires"
            type="date"
            value={expires}
            onChange={(event) => setExpires(event.target.value)}
            aria-describedby="accept-expires-help"
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
          <Button type="submit" variant="primary" disabled={reason.trim() === "" || accept.isPending}>
            {t("cves.accept.submit")}
          </Button>
        </div>
      </form>
    </Dialog>
  );
}
