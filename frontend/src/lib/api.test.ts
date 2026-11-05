import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ApiError, api } from "./api";

// The API is mocked by stubbing fetch. No test makes a network call.
function stubFetch(response: Response) {
  const fetchMock = vi.fn().mockResolvedValue(response);
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

function sentHeaders(fetchMock: ReturnType<typeof vi.fn>): Headers {
  const init = fetchMock.mock.calls[0][1] as RequestInit;
  return new Headers(init.headers);
}

describe("api", () => {
  beforeEach(() => {
    // jsdom drops a `__Host-` cookie over http, so the getter is stubbed.
    vi.spyOn(document, "cookie", "get").mockReturnValue("theme=x; __Host-harborgate_csrf=csrf-test-value");
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it("sends X-CSRF-Token from the cookie on POST", async () => {
    const fetchMock = stubFetch(new Response(JSON.stringify({ ok: true }), { status: 200 }));
    await api("POST", "/mappings", { name: "x" });
    const headers = sentHeaders(fetchMock);
    expect(headers.get("X-CSRF-Token")).toBe("csrf-test-value");
    expect(headers.get("Content-Type")).toBe("application/json");
    expect(fetchMock.mock.calls[0][0]).toBe("/api/v1/mappings");
    expect((fetchMock.mock.calls[0][1] as RequestInit).credentials).toBe("same-origin");
  });

  it("sends no X-CSRF-Token on GET", async () => {
    const fetchMock = stubFetch(new Response(JSON.stringify({ ok: true }), { status: 200 }));
    await api("GET", "/account/me");
    expect(sentHeaders(fetchMock).has("X-CSRF-Token")).toBe(false);
  });

  it("turns the error envelope into ApiError", async () => {
    stubFetch(
      new Response(JSON.stringify({ error: { code: "conflict", message: "Already used." } }), { status: 409 }),
    );
    const failure = await api("POST", "/mappings", {}).catch((error: unknown) => error);
    expect(failure).toBeInstanceOf(ApiError);
    expect((failure as ApiError).status).toBe(409);
    expect((failure as ApiError).code).toBe("conflict");
    expect((failure as ApiError).message).toBe("Already used.");
  });

  it("carries Retry-After seconds and the detail code on ApiError", async () => {
    stubFetch(
      new Response(JSON.stringify({ error: { code: "rate_limited", message: "Slow down.", detail: "robot_scope" } }), {
        status: 429,
        headers: { "Retry-After": "900" },
      }),
    );
    const failure = (await api("GET", "/x").catch((error: unknown) => error)) as ApiError;
    expect(failure.retryAfter).toBe(900);
    expect(failure.detail).toBe("robot_scope");
  });

  it("returns undefined on 204", async () => {
    stubFetch(new Response(null, { status: 204 }));
    await expect(api("POST", "/auth/logout")).resolves.toBeUndefined();
  });
});
