// Response types for the routes the Dashboard, Mappings, CVEs and Jobs
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
  github_cred_id: string;
  harbor_project: string;
  harbor_repository: string;
  github_owner: string;
  github_repo: string;
  default_branch: string;
  auto_create_issues: boolean;
  min_issue_severity: IssueSeverity;
  created_at: string | null;
}

// Open CVEs per severity, and their sum (#129).
export interface OpenCves {
  critical: number;
  high: number;
  medium: number;
  low: number;
  unknown: number;
  total: number;
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
  service_type: "github";
  label: string;
  base_url: string | null;
  username: string | null;
  expires_at: string | null;
  created_at: string | null;
  // Only the list route returns it (specs/api.md, Credentials).
  mapping_count?: number;
}

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "UNKNOWN";

export interface CveSummary {
  id: string;
  mapping_id: string;
  cve_id: string;
  severity: Severity;
  // Highest severity across the open tags, or null when every tag is fixed.
  open_severity: Severity | null;
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
  // True for a tag of the mapping's newest scanned digest (#196).
  newest_digest: boolean;
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
  // No newest-digest row is open, but a row on an older tag is (#196).
  older_tags_only: boolean;
}

export interface SyncReport {
  image_tag: string;
  image_digest: string;
  commit_sha: string | null;
  vulnerability_summary: unknown;
  sarif_status: "pending" | "success" | "failed";
  synced_at: string | null;
  // CVE ids a scheduled scan found that were not in the last result for the digest (#191).
  // Null for other triggers; empty when nothing is new.
  new_cve_ids: string[] | null;
}

export interface Job {
  id: string;
  mapping_id: string;
  status: JobStatus;
  attempts: number;
  next_attempt_at: string | null;
  last_error: string | null;
  created_at: string | null;
  updated_at: string | null;
  // The trigger the job was queued by, from its payload. Null when the payload has none.
  trigger: string | null;
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
  accepted_cves: number;
  open_issues: number;
  failed_syncs: number;
  recent_syncs: Job[];
}

// One item of GET /mappings/:id/tags: the CVE view's tag set.
export interface MappingTag {
  image_tag: string;
  last_scan_at: string;
  open_cves: number;
}

export interface CheckResult {
  name: string;
  ok: boolean;
  detail: string;
  warning?: string;
}

export interface TestResult {
  ok: boolean;
  repository?: string | null;
  checks: CheckResult[];
}

export interface HousekeepingRun {
  id: string;
  job_kind: "poll" | "cleanup" | "retention";
  started_at: string;
  finished_at: string | null;
  status: "done" | "failed";
  processed_count: number;
  error_summary: string | null;
}

export interface AuditEntry {
  id: string;
  actor_user_id: string | null;
  actor_username: string;
  action: string;
  target: string;
  created_at: number | string | null;
  details: unknown;
}

export interface HealthCheck {
  credential_id: string;
  label: string;
  ok: boolean;
  reachable: boolean;
  missing_permissions: string[];
  code_scanning: "ok" | "no_analysis_yet" | "unavailable" | null;
  target: string | null;
  detail: string;
}

export interface HealthReport {
  github: HealthCheck[];
  request: { client_ip: string; source: "peer" | "x-forwarded-for" };
}

export interface OidcSettings {
  issuer_url: string | null;
  client_id: string | null;
  role_claim: string | null;
  admin_group: string | null;
  user_group: string | null;
  client_secret_set: boolean;
  oidc_only_users: boolean;
}

export interface GithubUrlSettings {
  api_base_url: string;
  web_url: string;
}

export interface AlertChannel {
  id: string;
  kind: "smtp" | "webhook";
  enabled: boolean;
  created_at: string;
  updated_at: string;
}

// Mapping pickers (specs/api.md, "Pickers"). Names only: no token, no URL
// with credentials.
export interface PickerList<T> extends Page<T> {
  // True when the upstream list was cut at the 1,000-item fetch cap.
  truncated: boolean;
}

export interface GitHubRepository {
  owner: string;
  repo: string;
  full_name: string;
  private: boolean;
  archived: boolean;
}
