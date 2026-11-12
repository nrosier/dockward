// Response types for the Sources and Images screens. The shapes follow
// specs/spinoff-local-scan.md, sections 9 and 10.

import type { IssueSeverity } from "./api";

export interface Hub {
  id: string;
  host: string;
  pull_endpoint: string | null;
  kind: "default" | "custom";
}

export interface Source {
  id: string;
  user_id: string;
  hub_id: string;
  repository: string;
  // The display name (#323). Null until one is set; the UI then shows the repository.
  name: string | null;
  tag_value: string;
  github_cred_id: string;
  github_owner: string;
  github_repo: string;
  default_branch: string;
  auto_create_issues: boolean;
  min_issue_severity: IssueSeverity;
  has_credential: boolean;
  // Unix seconds or an RFC 3339 string; null before the first discovery.
  last_discovery_at: number | string | null;
}

export type PlatformState = "queued" | "pulling" | "stored" | "evicting" | "evicted" | "failed";
export type ScanStatus = "queued" | "running" | "done" | "failed";

export interface ScannerRun {
  scanner: string;
  status: ScanStatus;
  version: string | null;
  error: string | null;
  db_built_at: number | string | null;
}

export interface ImagePlatform {
  id: string;
  // For example "linux/amd64".
  platform: string;
  state: PlatformState;
  size_bytes: number | null;
  pulled_at: number | string | null;
  scans: ScannerRun[];
}

export interface SourceImage {
  id: string;
  digest: string;
  // The tags of the source that point at this image.
  tags: string[];
  platforms: ImagePlatform[];
}

export interface ScanQueued {
  queued: number;
}
