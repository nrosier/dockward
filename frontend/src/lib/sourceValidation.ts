// Client-side checks that mirror the backend grammars
// (backend/src/services/registry/grammar.rs and services/discovery/glob.rs).
// The server stays the authority; these give the user an answer before a save.

const MAX_REPOSITORY = 255;
const MAX_TAG = 128;
const COMPONENT = "[a-z0-9]+(?:(?:\\.|_|__|-+)[a-z0-9]+)*";
const REPOSITORY = new RegExp(`^${COMPONENT}(?:/${COMPONENT})*$`);
const EXACT_TAG = /^[A-Za-z0-9_][A-Za-z0-9._-]*$/;
const GLOB_TAG = /^[A-Za-z0-9._*?-]+$/;

// OCI repository grammar. A name with ':' or '@' fails it.
export function isValidRepository(name: string): boolean {
  return name.length > 0 && name.length <= MAX_REPOSITORY && REPOSITORY.test(name);
}

export type TagValueKind = "exact" | "pattern" | "invalid" | "empty";

// An exact tag, or a pattern with '*' and '?' only (decision 15).
export function tagValueKind(value: string): TagValueKind {
  if (value === "") {
    return "empty";
  }
  if (value.length > MAX_TAG) {
    return "invalid";
  }
  if (/[*?]/.test(value)) {
    return GLOB_TAG.test(value) ? "pattern" : "invalid";
  }
  return EXACT_TAG.test(value) ? "exact" : "invalid";
}

// The namespace is the first path segment of the repository (decision 38).
export function namespaceOf(repository: string): string {
  return repository.split("/")[0] ?? repository;
}

// Unix seconds or an RFC 3339 string, as an RFC 3339 string.
export function toIso(value: number | string | null | undefined): string | null {
  if (value === null || value === undefined) {
    return null;
  }
  const date = typeof value === "number" ? new Date(value * 1000) : new Date(value);
  return Number.isNaN(date.getTime()) ? null : date.toISOString();
}
