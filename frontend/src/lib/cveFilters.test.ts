import { describe, expect, it } from "vitest";
import { namespaceOf, parseFilters, toApiQuery, toUrlParams } from "./cveFilters";

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
      "q=glibc&severity=LOW,CRITICAL&status=fixed,accepted&has_issue=false&fix=none,available&namespace=platform&repository=platform/api&tag=1.42.0&mapping=m1",
    );
    const state = parseFilters(params);
    expect(state.severities).toEqual(["CRITICAL", "LOW"]);
    expect(toUrlParams(state)).toEqual({
      q: "glibc",
      severity: "CRITICAL,LOW",
      status: "fixed,accepted",
      has_issue: "false",
      fix: "available,none",
      namespace: "platform",
      repository: "platform/api",
      tag: "1.42.0",
      mapping: "m1",
    });
    // The Mapping filter is a source (#323): the API reads it as `source_id`, never `mapping`.
    expect(toApiQuery(state)).toEqual({
      q: "glibc",
      severity: "CRITICAL,LOW",
      status: "fixed,accepted",
      has_issue: "false",
      fix: "available,none",
      namespace: "platform",
      repository: "platform/api",
      tag: "1.42.0",
      source_id: "m1",
    });
  });

  it("sends the Mapping filter to the API as source_id, and never as mapping (#323 follow-up)", () => {
    const query = toApiQuery(parseFilters(new URLSearchParams("mapping=m1")));
    expect(query.source_id).toBe("m1");
    expect(query).not.toHaveProperty("mapping");
  });

  it("drops unknown values", () => {
    const state = parseFilters(new URLSearchParams("severity=BOGUS&status=nope&has_issue=maybe&fix=maybe"));
    expect(toUrlParams(state)).toEqual({});
  });

  it("keeps old links working (decision 9)", () => {
    expect(parseFilters(new URLSearchParams("accepted=true")).statuses).toEqual(["accepted"]);
    expect(parseFilters(new URLSearchParams("accepted=false&status=open")).statuses).toEqual(["open"]);
    expect(parseFilters(new URLSearchParams("status=all")).statuses).toEqual(["open", "fixed", "accepted"]);
    const old = parseFilters(new URLSearchParams("mapping_id=m1"));
    expect(old.mapping).toEqual("m1");
    // The new name wins when both are present.
    const both = parseFilters(new URLSearchParams("mapping=m2&mapping_id=m1"));
    expect(both.mapping).toEqual("m2");
  });

  it("does not read the removed Harbor parameters", () => {
    const state = parseFilters(new URLSearchParams("project=p&harbor_project=p&harbor_repository=r"));
    expect(state.namespace).toBe("");
    expect(state.repository).toBe("");
    expect(toUrlParams(state)).toEqual({});
  });
});

describe("namespaceOf", () => {
  it("is the first path segment of the repository", () => {
    expect(namespaceOf("nrosier/walley")).toBe("nrosier");
    expect(namespaceOf("nrosier/team/app")).toBe("nrosier");
    expect(namespaceOf("alpine")).toBe("alpine");
  });
});
