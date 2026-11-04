import en from "./en.json";

export type MessageKey = keyof typeof en;

const catalog: Record<string, string> = en;

// Looks up a catalog string and fills `{name}` placeholders. A missing key
// returns the key itself, so a gap is visible instead of blank.
export function t(key: MessageKey, vars?: Record<string, string | number>): string {
  const template = Object.prototype.hasOwnProperty.call(catalog, key) ? catalog[key] : key;
  if (vars === undefined) {
    return template;
  }
  return template.replace(/\{(\w+)\}/g, (match, name: string) =>
    Object.prototype.hasOwnProperty.call(vars, name) ? String(vars[name]) : match,
  );
}
