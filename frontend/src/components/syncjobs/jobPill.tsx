import { Pill } from "../ui/Pill";
import type { JobStatus } from "../../types/api";

export function JobStatusPill({ status }: { status: JobStatus }) {
  return <Pill kind={status} />;
}
