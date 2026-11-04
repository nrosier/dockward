// Browser-only preferences (specs/frontend.md, "Page map"). Only theme,
// language, and the rail state are ever written to localStorage.

export type Theme = "dark" | "light";
export type Language = "en";

const THEME_KEY = "hg.theme";
const LANG_KEY = "hg.lang";
const RAIL_KEY = "hg.rail";

function read(key: string): string | null {
  try {
    return window.localStorage.getItem(key);
  } catch {
    return null;
  }
}

function write(key: string, value: string): void {
  try {
    window.localStorage.setItem(key, value);
  } catch {
    // Storage can be unavailable (private mode, quota). The preference then
    // lasts only for this page view.
  }
}

export function getTheme(): Theme {
  return read(THEME_KEY) === "light" ? "light" : "dark";
}

export function applyTheme(t: Theme): void {
  document.documentElement.dataset.theme = t;
}

export function setTheme(t: Theme): void {
  write(THEME_KEY, t);
  applyTheme(t);
}

export function getLanguage(): Language {
  // English is the only catalog in v1, so every stored value resolves to "en".
  // A future language adds its code here.
  const supported: readonly Language[] = ["en"];
  const stored = read(LANG_KEY);
  return supported.find((l) => l === stored) ?? "en";
}

export function setLanguage(l: Language): void {
  write(LANG_KEY, l);
}

export function getRailCollapsed(): boolean {
  return read(RAIL_KEY) === "collapsed";
}

export function setRailCollapsed(collapsed: boolean): void {
  write(RAIL_KEY, collapsed ? "collapsed" : "expanded");
}
