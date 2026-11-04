// GitHub-supplied URLs become links only when the scheme is https, so a
// `javascript:` or `data:` value can never reach an href.
export function safeHttpsUrl(value: string | null): string | null {
  if (value === null) {
    return null;
  }
  try {
    const url = new URL(value);
    return url.protocol === "https:" ? url.href : null;
  } catch {
    return null;
  }
}
