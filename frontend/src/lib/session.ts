import { createElement } from "react";
import { useQuery } from "@tanstack/react-query";
import { Navigate, Outlet, useLocation } from "react-router";
import { ApiError, api } from "./api";
import { ErrorMessage, LoadingMessage, NotFoundMessage } from "../components/ui/StatusMessage";

export type Role = "admin" | "user";

export interface User {
  id: string;
  username: string;
  email: string;
  role: Role;
  auth_provider: "local" | "oidc";
  created_at: string;
}

export interface SetupStatus {
  setup_required: boolean;
  oidc_enabled: boolean;
}

export const ME_QUERY_KEY = ["me"] as const;

// The signed-in user, or `null` when there is no valid session.
export function useMe() {
  return useQuery({
    queryKey: ME_QUERY_KEY,
    queryFn: async (): Promise<User | null> => {
      try {
        const body = await api<{ user: User }>("GET", "/account/me");
        return body.user;
      } catch (error) {
        if (error instanceof ApiError && error.status === 401) {
          return null;
        }
        throw error;
      }
    },
    staleTime: 60_000,
  });
}

export function useSetupStatus(enabled = true) {
  return useQuery({
    queryKey: ["setup-status"],
    queryFn: () => api<SetupStatus>("GET", "/auth/setup-status"),
    enabled,
  });
}

// Renders the child routes for a signed-in user. A signed-out visitor goes to
// /setup while setup is required, else to /login. The query string is kept, so
// an OIDC error (`/?oidc_error=x`) reaches the login page.
export function RequireAuth() {
  const me = useMe();
  const location = useLocation();
  const signedOut = me.isSuccess && me.data === null;
  const setup = useSetupStatus(signedOut);

  if (me.isPending || (signedOut && setup.isPending)) {
    return createElement(LoadingMessage);
  }
  if (me.isError || (signedOut && setup.isError)) {
    return createElement(ErrorMessage);
  }
  if (me.data) {
    return createElement(Outlet);
  }
  const pathname = setup.data?.setup_required ? "/setup" : "/login";
  return createElement(Navigate, { to: { pathname, search: location.search }, replace: true });
}

// Renders the child routes for admins. Others see a not-found message, so the
// admin area is not revealed.
export function RequireAdmin() {
  const me = useMe();
  if (me.data?.role === "admin") {
    return createElement(Outlet);
  }
  return createElement(NotFoundMessage);
}
