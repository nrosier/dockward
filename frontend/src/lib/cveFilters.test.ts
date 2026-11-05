import { describe, expect, it } from "vitest";
import { activeFilters, parseFilters, toApiQuery, toUrlParams } from "./cveFilters";

describe("cveFilters", () => {
  it("defaults to every severity and open status, with no active filter", () => {
    const state = parseFilters(new URLSearchParams());
    expect(state.severities).toEqual(["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]);
    expect(state.statuses).toEqual(["open"]);
    expect(activeFilters(state)).toEqual([]);
    expect(toApiQuery(state)).toEqual({ status: "open", accepted: "false" });
  });

  it("turns filter state into the comma-separated query string", () => {
    const state = parseFilters(
      new URLSearchParams(
        "severity=LOW,CRITICAL&status=fixed,accepted&package=openssl&tag=1.42.0&harbor_project=platform&harbor_repository=api&mapping_id=m1",
      ),
    );
    expect(state.severities).toEqual(["CRITICAL", "LOW"]);
    expect(toApiQuery(state)).toEqual({
      severity: "CRITICAL,LOW",
      status: "fixed,accepted",
      package: "openssl",
      tag: "1.42.0",
      harbor_project: "platform",
      harbor_repository: "api",
      mapping_id: "m1",
    });
  });

  it("leaves the defaults out of the page URL and drops unknown values", () => {
    const state = parseFilters(new URLSearchParams("severity=BOGUS&status=nope"));
    expect(toUrlParams(state)).toEqual({});
    expect(activeFilters(parseFilters(new URLSearchParams("status=open,fixed"))).map((f) => f.key)).toEqual(["status"]);
  });
});
