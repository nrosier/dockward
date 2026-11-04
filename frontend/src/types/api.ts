// Response types for the routes the Dashboard, Mappings, CVEs and Sync jobs
// pages call. Field names are exactly those of specs/api.md.

export interface Page<T> {
  items: T[];
  page: number;
  page_size: number;
  total: number;
}

export type IssueSeverity = "CRITICAL" | "HIGH";

export interface Mapping {
  id: string;
  user_id: string;
  harbor_cred_id: string;
  github_cred_id: string;
  harbor_base_url: string;
  harbor_project: string;
  harbor_repository: string;
  github_owner: string;
  github_repo: string;
  default_branch: string;
  auto_create_issues: boolean;
  min_issue_severity: IssueSeverity;
  created_at: string | null;
}

export interface OpenCves {
  critical: number;
  high: number;
}

export type JobStatus = "queued" | "running" | "done" | "failed";

export interface LastSync {
  status: JobStatus;
  updated_at: string | null;
}

export interface MappingListItem extends Mapping {
  open_cves: OpenCves;
  last_sync: LastSync | null;
}

export interface Credential {
  id: string;
  service_type: "harbor" | "github";
  label: string;
  base_url: string | null;
  username: string | null;
  expires_at: string | null;
  created_at: string | null;
}

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "UNKNOWN";

export interface CveSummary {
  id: string;
  mapping_id: string;
  cve_id: string;
  severity: Severity;
  status: "open" | "fixed";
  package: string | null;
  first_seen_at: string | null;
  last_seen_at: string | null;
  github_issue_url: string | null;
  accepted: boolean;
  fixed_in_version: string | null;
  open_tags: number;
  tracked_tags: number;
  github_issue_number: number | null;
  github_issue_status: "open" | "closed" | null;
}

export interface CveTag {
  image_tag: string;
  status: "open" | "fixed";
  last_scan_at: string | null;
  fixed_in_version: string | null;
}

export interface Acceptance {
  id: string;
  mapping_id: string;
  cve_id: string;
  reason: string;
  created_by: string;
  created_at: string | null;
  expires_at: string | null;
}

export interface CveDetail extends CveSummary {
  tags: CveTag[];
  acceptance: Acceptance | null;
  description: string | null;
}

export interface SyncReport {
  image_tag: string;
  image_digest: string;
  commit_sha: string | null;
  vulnerability_summary: unknown;
  sarif_status: "pending" | "success" | "failed";
  synced_at: string | null;
}

export interface SyncJob {
  id: string;
  mapping_id: string;
  status: JobStatus;
  attempts: number;
  next_attempt_at: string | null;
  last_error: string | null;
  created_at: string | null;
  updated_at: string | null;
  trigger: "webhook" | "poll";
  image: {
    repo_full_name: string | null;
    tag: string | null;
    digest: string | null;
  };
  report: SyncReport | null;
}

export interface DashboardSummary {
  open_cves: OpenCves;
  fixed_cves: number;
  open_issues: number;
  failed_syncs: number;
  recent_syncs: SyncJob[];
}

export interface MappingCreated {
  mapping: Mapping;
  webhook_url: string;
  auth_secret: string;
}
