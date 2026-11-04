import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { getTheme, setTheme } from "./preferences";

describe("preferences", () => {
  beforeEach(() => {
    window.localStorage.clear();
    delete document.documentElement.dataset.theme;
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("defaults to dark", () => {
    expect(getTheme()).toBe("dark");
  });

  it("stores the theme and sets the data attribute", () => {
    setTheme("light");
    expect(getTheme()).toBe("light");
    expect(document.documentElement.dataset.theme).toBe("light");
  });

  it("falls back to dark when storage throws", () => {
    vi.spyOn(Storage.prototype, "getItem").mockImplementation(() => {
      throw new Error("storage blocked");
    });
    vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => {
      throw new Error("storage blocked");
    });
    expect(getTheme()).toBe("dark");
    expect(() => setTheme("light")).not.toThrow();
    expect(document.documentElement.dataset.theme).toBe("light");
  });
});
