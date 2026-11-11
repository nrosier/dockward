import { ShaBadge } from "../ui/ShaBadge";
import type { Job } from "../../types/api";

// The image of a job: `repo:tag` and the digest badge. All values come from
// the job payload, so they are rendered as escaped text only.
export function ImageCell({ job, showError = false }: { job: Job; showError?: boolean }) {
  const image = job.image;
  return (
    <div className="flex flex-col items-start gap-1">
      <div className="font-medium">
        {image.repo_full_name}
        {image.tag === null ? null : <span className="text-muted">:{image.tag}</span>}
      </div>
      {image.digest === null ? null : <ShaBadge digest={image.digest} />}
      {showError && job.status === "failed" && job.last_error !== null ? (
        <div className="mt-1 text-[12.5px] text-crit-ink">{job.last_error}</div>
      ) : null}
    </div>
  );
}
