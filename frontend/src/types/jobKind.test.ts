import { describe, expect, it } from "vitest";
import type { HousekeepingRun } from "./api";

describe("HousekeepingRun job_kind", () => {
  it("is the backend's run kinds and no longer contains poll", () => {
    const kinds: HousekeepingRun["job_kind"][] = ["cleanup", "retention", "discover", "db_update"];
    expect(kinds).toHaveLength(4);
    // @ts-expect-error "poll" is not a run kind any more.
    const poll: HousekeepingRun["job_kind"] = "poll";
    expect(kinds).not.toContain(poll);
  });
});
