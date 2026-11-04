import { describe, expect, it } from "vitest";
import { hardcodedText, usedKeys } from "../test/catalogScan";
import en from "./en.json";

// Every non-test source file under src/, read as text. Vite's glob import
// reads the files at transform time, so the test needs no Node typings.
const modules = import.meta.glob(["../**/*.ts", "../**/*.tsx", "!../**/*.test.ts", "!../**/*.test.tsx", "!../test/**"], {
  query: "?raw",
  import: "default",
  eager: true,
}) as Record<string, string>;

const files = Object.entries(modules);
const tsx = files.filter(([path]) => path.endsWith(".tsx"));

describe("catalog", () => {
  it("every t() key used in src exists in en.json", () => {
    const known = new Set(Object.keys(en));
    const missing: string[] = [];
    let seen = 0;
    for (const [path, source] of files) {
      for (const key of usedKeys(source)) {
        seen += 1;
        if (!known.has(key)) {
          missing.push(`${path}: ${key}`);
        }
      }
    }
    // The scan must actually find keys, or it proves nothing.
    expect(seen).toBeGreaterThan(20);
    expect(missing).toEqual([]);
  });

  it("no component has hard-coded JSX text or text attributes", () => {
    expect(tsx.length).toBeGreaterThan(20);
    const offenders = tsx.flatMap(([path, source]) => hardcodedText(source).map((hit) => `${path}: ${hit}`));
    expect(offenders).toEqual([]);
  });
});

describe("catalog scanners", () => {
  it("flag hard-coded JSX text and text attributes", () => {
    const source = [
      "const a = <p>Sign out</p>;",
      "const b = (",
      "  <span>",
      "    Signed in as",
      "  </span>",
      ");",
      'const c = <button aria-label="Close" />;',
      "const d = <img alt={'Logo'} />;",
      'const e = <input placeholder="Search" title="Find" />;',
    ].join("\n");
    expect(hardcodedText(source)).toEqual([
      'text "Sign out"',
      'text "Signed in as"',
      'aria-label="Close"',
      'alt="Logo"',
      'placeholder="Search"',
      'title="Find"',
    ]);
  });

  it("pass catalog strings, generics, and arrows", () => {
    const source = [
      "const f = (x: Promise<User>) => x;",
      'const g = <p title={t("a.b")}>{t("a.c")}</p>;',
      'const h = <span aria-hidden="true" className="x" />;',
      "const i = useState<boolean>(false);",
      "// a comment with <b>Bold</b> is ignored",
    ].join("\n");
    expect(hardcodedText(source)).toEqual([]);
    expect(usedKeys(source)).toEqual(["a.b", "a.c"]);
  });
});
