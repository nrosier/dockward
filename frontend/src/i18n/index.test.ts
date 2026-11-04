import { describe, expect, it } from "vitest";
import { t, type MessageKey } from "./index";

describe("t", () => {
  it("replaces placeholders", () => {
    expect(t("pagination.range", { from: 1, to: 8, total: 56 })).toBe("1–8 of 56");
  });

  it("returns the key when it is missing", () => {
    expect(t("no.such.key" as MessageKey)).toBe("no.such.key");
  });
});
