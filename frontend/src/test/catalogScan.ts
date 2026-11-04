// Source scanners for the string catalog tests. TypeScript 7 has no JS parser
// API, so these are regex-based, as the #36 brief specifies.

// Keys passed to t("…") as a string literal.
export function usedKeys(source: string): string[] {
  return Array.from(source.matchAll(/\bt\(\s*"([^"]+)"/g), (match) => match[1]);
}

function stripComments(source: string): string {
  return source.replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|[^:"'`])\/\/.*$/gm, "$1");
}

// Hard-coded user-visible text in a .tsx source:
// - JSX text with a letter between a closing `>` and the next `<`;
// - aria-label, title, placeholder, or alt set to a string literal with a letter.
export function hardcodedText(source: string): string[] {
  const code = stripComments(source);
  const found: string[] = [];
  for (const match of code.matchAll(/(^|[^=-])>([^<>]*)</g)) {
    const inner = match[2];
    // Code between a `>` and a `<` (generics, comparisons) has these; JSX text
    // between tags does not, because expressions sit inside braces.
    if (/[{};=()]/.test(inner) || !/[A-Za-z]/.test(inner)) {
      continue;
    }
    found.push(`text "${inner.trim()}"`);
  }
  for (const match of code.matchAll(/\b(aria-label|title|placeholder|alt)=(?:"([^"]*)"|'([^']*)'|\{\s*["'`]([^"'`]*)["'`]\s*\})/g)) {
    const value = match[2] ?? match[3] ?? match[4] ?? "";
    if (/[A-Za-z]/.test(value)) {
      found.push(`${match[1]}="${value}"`);
    }
  }
  return found;
}
