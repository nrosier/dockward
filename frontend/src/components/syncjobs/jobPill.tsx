import { Pill } from "../ui/Pill";
import type { JobStatus } from "../../types/api";

export function JobStatusPill({ status, label }: { status: JobStatus; label?: string }) {
  return <Pill kind={status} label={label} />;
}
