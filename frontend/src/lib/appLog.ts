import { useQuery } from "@tanstack/react-query";
import { api } from "./api";

export type LogLevel = "error" | "warn" | "info" | "debug" | "trace";

export interface LevelStatus {
  level: LogLevel;
  reverts_at: string | null;
}

export interface LogLine {
  seq: number;
  timestamp: string;
  level: LogLevel;
  target: string;
  message: string;
}

export interface LogsView extends LevelStatus {
  items: LogLine[];
}

// The backend ends a line cut at 1000 characters with this marker.
export const TRUNCATED_MARKER = "… [truncated]";

export const LEVEL_KEY = ["admin", "log-level"] as const;

export function useLogLevel() {
  return useQuery({
    queryKey: LEVEL_KEY,
    queryFn: () => api<LevelStatus>("GET", "/admin/log-level"),
    refetchInterval: 30_000,
  });
}
