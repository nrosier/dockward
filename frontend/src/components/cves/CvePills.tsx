import { Pill, type PillKind } from "../ui/Pill";
import type { CveSummary, Severity } from "../../types/api";

const SEVERITY: Record<Severity, PillKind> = {
  CRITICAL: "critical",
  HIGH: "high",
  MEDIUM: "medium",
  LOW: "low",
  UNKNOWN: "unknown",
};

export function SeverityPill({ severity }: { severity: Severity }) {
  return <Pill kind={SEVERITY[severity] ?? "unknown"} />;
}

// ACCEPTED when accepted, else OPEN or FIXED.
export function CveStatusPill({ cve }: { cve: Pick<CveSummary, "accepted" | "status"> }) {
  if (cve.accepted) {
    return <Pill kind="accepted" />;
  }
  return <Pill kind={cve.status === "fixed" ? "fixed" : "open"} />;
}

// A CVE can get an issue while at least one tag reports it open (#129).
// open_severity is null when every tag is fixed.
export function issueEligible(cve: Pick<CveSummary, "open_severity">): boolean {
  return cve.open_severity !== null;
}
