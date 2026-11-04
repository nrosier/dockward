import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render } from "@testing-library/react";
import type { ReactElement } from "react";
import { RouterProvider, createMemoryRouter, type RouteObject } from "react-router";
import { vi } from "vitest";
import type { User } from "../lib/session";

export function testQueryClient(): QueryClient {
  return new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
}

export function user(role: User["role"]): User {
  return {
    id: "u1",
    username: role === "admin" ? "ops-admin" : "dev",
    email: "u@example.test",
    role,
    auth_provider: "local",
    created_at: "2026-11-03T09:00:00Z",
  };
}

type Route = (path: string, init?: RequestInit) => Response | undefined;

// Stubs fetch with a router of path handlers. Unhandled paths return 404.
// Returns the mock so tests can assert which requests were made.
export function stubApi(route: Route) {
  const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const path = String(input);
    return (
      route(path, init) ??
      new Response(JSON.stringify({ error: { code: "not_found", message: "Not found." } }), { status: 404 })
    );
  });
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

export function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

export function renderWithRoutes(routes: RouteObject[], initialEntry: string, client = testQueryClient()) {
  const router = createMemoryRouter(routes, { initialEntries: [initialEntry] });
  const result = render(
    <QueryClientProvider client={client}>
      <RouterProvider router={router} />
    </QueryClientProvider>,
  );
  return { ...result, router, client };
}

export function renderAt(element: ReactElement, path = "/", client = testQueryClient()) {
  return renderWithRoutes([{ path: "*", element }], path, client);
}
