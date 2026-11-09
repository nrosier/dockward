import { describe, expect, it } from "vitest";
import { parseFilters, toApiQuery, toUrlParams } from "./cveFilters";

describe("cveFilters", () => {
  it("defaults to every severity and the Open status, with nothing in the URL", () => {
    const state = parseFilters(new URLSearchParams());
    expect(state.severities).toEqual([]);
    expect(state.statuses).toEqual(["open"]);
    expect(toUrlParams(state)).toEqual({});
    expect(toApiQuery(state)).toEqual({ status: "open" });
  });

  it("round-trips every control through the URL", () => {
    const params = new URLSearchParams(
      "q=glibc&severity=LOW,CRITICAL&status=fixed,accepted&has_issue=false&fix=none,available&project=platform&repository=api&tag=1.42.0&mapping=m1",
    );
    const state = parseFilters(params);
    expect(state.severities).toEqual(["CRITICAL", "LOW"]);
    expect(toUrlParams(state)).toEqual({
      q: "glibc",
      severity: "CRITICAL,LOW",
      status: "fixed,accepted",
      has_issue: "false",
      fix: "available,none",
      project: "platform",
      repository: "api",
      tag: "1.42.0",
      mapping: "m1",
    });
    expect(toApiQuery(state)).toEqual(toUrlParams(state));
  });

  it("drops unknown values", () => {
    const state = parseFilters(new URLSearchParams("severity=BOGUS&status=nope&has_issue=maybe&fix=maybe"));
    expect(toUrlParams(state)).toEqual({});
  });

  it("keeps old links working (decision 9)", () => {
    expect(parseFilters(new URLSearchParams("accepted=true")).statuses).toEqual(["accepted"]);
    expect(parseFilters(new URLSearchParams("accepted=false&status=open")).statuses).toEqual(["open"]);
    expect(parseFilters(new URLSearchParams("status=all")).statuses).toEqual(["open", "fixed", "accepted"]);
    const old = parseFilters(new URLSearchParams("harbor_project=platform&harbor_repository=api&mapping_id=m1"));
    expect([old.project, old.repository, old.mapping]).toEqual(["platform", "api", "m1"]);
    // The new name wins when both are present.
    const both = parseFilters(new URLSearchParams("project=new&harbor_project=old&mapping=m2&mapping_id=m1"));
    expect([both.project, both.mapping]).toEqual(["new", "m2"]);
  });
});
