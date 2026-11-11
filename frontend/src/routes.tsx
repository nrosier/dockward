import { Navigate, createBrowserRouter, type RouteObject } from "react-router";
import { AdminLayout } from "./components/shell/AdminLayout";
import { AppShell } from "./components/shell/AppShell";
import { NotFoundMessage } from "./components/ui/StatusMessage";
import { RequireAdmin, RequireAuth } from "./lib/session";
import { ProfileTab } from "./pages/ProfileTab";
import { AppearanceTab } from "./pages/AppearanceTab";
import CredentialsTab from "./pages/CredentialsTab";
import { AccountLayout } from "./components/shell/AccountLayout";
import AdminAlertsPage from "./pages/AdminAlertsPage";
import AdminAuditPage from "./pages/AdminAuditPage";
import AdminBackupPage from "./pages/AdminBackupPage";
import AdminFailedPage from "./pages/AdminFailedPage";
import AdminHealthPage from "./pages/AdminHealthPage";
import AdminLogPage from "./pages/AdminLogPage";
import AdminJobsPage from "./pages/AdminJobsPage";
import AdminGithubPage from "./pages/AdminGithubPage";
import AdminOidcPage from "./pages/AdminOidcPage";
import AdminUsersPage from "./pages/AdminUsersPage";
import CredentialFormPage from "./pages/CredentialFormPage";
import CveDetailPage from "./pages/CveDetailPage";
import CvesPage from "./pages/CvesPage";
import DashboardPage from "./pages/DashboardPage";
import LoginPage from "./pages/LoginPage";
import SourceFormPage from "./pages/SourceFormPage";
import SourcesPage from "./pages/SourcesPage";
import SetupPage from "./pages/SetupPage";
import JobsPage from "./pages/JobsPage";

// The route table from specs/frontend.md ("Screen designs"), plus the edit
// screens for mappings and credentials.
export const routes: RouteObject[] = [
  { path: "/login", element: <LoginPage /> },
  { path: "/setup", element: <SetupPage /> },
  {
    element: <RequireAuth />,
    children: [
      {
        element: <AppShell />,
        children: [
          { index: true, element: <DashboardPage /> },
          { path: "sources", element: <SourcesPage /> },
          { path: "sources/new", element: <SourceFormPage /> },
          { path: "sources/:id", element: <SourceFormPage /> },
          { path: "cves", element: <CvesPage /> },
          { path: "cves/:id", element: <CveDetailPage /> },
          { path: "jobs", element: <JobsPage /> },
          {
            path: "account",
            element: <AccountLayout />,
            children: [
              { index: true, element: <Navigate to="/account/profile" replace /> },
              { path: "profile", element: <ProfileTab /> },
              { path: "appearance", element: <AppearanceTab /> },
              { path: "credentials", element: <CredentialsTab /> },
            ],
          },
          { path: "account/credentials/new", element: <CredentialFormPage /> },
          { path: "account/credentials/:id", element: <CredentialFormPage /> },
          {
            path: "admin",
            element: <RequireAdmin />,
            children: [
              { index: true, element: <Navigate to="/admin/jobs" replace /> },
              {
                element: <AdminLayout />,
                children: [
                  { path: "jobs", element: <AdminJobsPage /> },
                  { path: "failed", element: <AdminFailedPage /> },
                  { path: "audit", element: <AdminAuditPage /> },
                  { path: "health", element: <AdminHealthPage /> },
                  { path: "log", element: <AdminLogPage /> },
                  { path: "settings", element: <Navigate to="/admin/settings/oidc" replace /> },
                  { path: "settings/oidc", element: <AdminOidcPage /> },
                  { path: "settings/users", element: <AdminUsersPage /> },
                  { path: "settings/alerts", element: <AdminAlertsPage /> },
                  { path: "settings/github", element: <AdminGithubPage /> },
                  { path: "settings/backup", element: <AdminBackupPage /> },
                ],
              },
            ],
          },
          { path: "*", element: <NotFoundMessage /> },
        ],
      },
    ],
  },
];

export function createRouter() {
  return createBrowserRouter(routes);
}
