import { describe, expect, it } from "vitest";
import { isValidRepository, namespaceOf, tagValueKind, toIso } from "./sourceValidation";

describe("isValidRepository", () => {
  it("accepts OCI repository names", () => {
    for (const name of ["nginx", "nrosier/walley", "a.b/c_d/e__f/g--h"]) {
      expect(isValidRepository(name)).toBe(true);
    }
  });

  it("refuses ':' and '@', uppercase, and bad separators", () => {
    for (const name of ["", "nginx:latest", "nginx@sha256:abc", "Nginx", "a//b", "/a", "a/", "a-", "-a", "a___b", "a b"]) {
      expect(isValidRepository(name)).toBe(false);
    }
    expect(isValidRepository("a".repeat(256))).toBe(false);
  });
});

describe("tagValueKind", () => {
  it("classifies exact tags and globs", () => {
    expect(tagValueKind("1.2.3")).toBe("exact");
    expect(tagValueKind("_x-1")).toBe("exact");
    expect(tagValueKind("v1.*")).toBe("pattern");
    expect(tagValueKind("1.?.?")).toBe("pattern");
    expect(tagValueKind("")).toBe("empty");
  });

  it("refuses everything outside exact tags and * ? globs", () => {
    for (const value of ["-x", ".x", "a:b", "a@b", "v[1-2]*", "!v*", "a b", "v{1,2}", "re.*+"]) {
      expect(tagValueKind(value)).toBe("invalid");
    }
    expect(tagValueKind("a".repeat(129))).toBe("invalid");
  });
});

describe("helpers", () => {
  it("namespace is the first path segment", () => {
    expect(namespaceOf("nrosier/walley")).toBe("nrosier");
    expect(namespaceOf("nginx")).toBe("nginx");
  });

  it("toIso accepts seconds and strings", () => {
    expect(toIso(0)).toBe("1970-01-01T00:00:00.000Z");
    expect(toIso("2026-11-03T09:00:00Z")).toBe("2026-11-03T09:00:00.000Z");
    expect(toIso(null)).toBeNull();
    expect(toIso("nope")).toBeNull();
  });
});
