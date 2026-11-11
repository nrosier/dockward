// The one HTTP client for the backend API. It never logs a request or a
// response body: either can hold a one-time secret.

export type Method = "GET" | "POST" | "PUT" | "DELETE";

const BASE = "/api/v1";
const CSRF_COOKIE = "__Host-dockward_csrf";

export class ApiError extends Error {
  status: number;
  code: string;
  // Seconds from a `Retry-After` header, when the response had a valid one.
  retryAfter?: number;
  // The envelope's `detail` code (picker 422 answers and the mapping duplicate 409),
  // e.g. `robot_scope` or `harbor_repository_mapped`.
  detail?: string;

  constructor(status: number, code: string, message: string, retryAfter?: number, detail?: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
    this.retryAfter = retryAfter;
    this.detail = detail;
  }
}

export function readCookie(name: string): string | undefined {
  const prefix = `${name}=`;
  for (const part of document.cookie.split(";")) {
    const item = part.trim();
    if (item.startsWith(prefix)) {
      return decodeURIComponent(item.slice(prefix.length));
    }
  }
  return undefined;
}

function isEnvelope(value: unknown): value is { error: { code: string; message: string } } {
  if (typeof value !== "object" || value === null || !("error" in value)) {
    return false;
  }
  const error = (value as { error: unknown }).error;
  return (
    typeof error === "object" &&
    error !== null &&
    typeof (error as { code?: unknown }).code === "string" &&
    typeof (error as { message?: unknown }).message === "string"
  );
}

function retryAfterOf(response: Response): number | undefined {
  const raw = response.headers.get("Retry-After");
  const seconds = raw === null ? Number.NaN : Number(raw);
  return Number.isInteger(seconds) && seconds >= 0 ? seconds : undefined;
}

async function toApiError(response: Response): Promise<ApiError> {
  const retryAfter = retryAfterOf(response);
  let parsed: unknown = undefined;
  try {
    parsed = await response.json();
  } catch {
    parsed = undefined;
  }
  if (isEnvelope(parsed)) {
    const detail = (parsed.error as { detail?: unknown }).detail;
    return new ApiError(
      response.status,
      parsed.error.code,
      parsed.error.message,
      retryAfter,
      typeof detail === "string" ? detail : undefined,
    );
  }
  return new ApiError(response.status, "internal_error", response.statusText, retryAfter);
}

export async function api<T>(method: Method, path: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = { Accept: "application/json" };
  if (body !== undefined) {
    headers["Content-Type"] = "application/json";
  }
  if (method !== "GET") {
    const token = readCookie(CSRF_COOKIE);
    if (token !== undefined) {
      headers["X-CSRF-Token"] = token;
    }
  }
  const response = await fetch(`${BASE}${path}`, {
    method,
    credentials: "same-origin",
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (!response.ok) {
    throw await toApiError(response);
  }
  if (response.status === 204) {
    return undefined as T;
  }
  return (await response.json()) as T;
}
