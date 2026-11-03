# Frontend

Purpose: app shell, page map, screen designs, visual direction, status pills, i18n, and the house style rules.

## Process rules

- Design before build. Every screen's design is proposed and approved by the user before it is implemented.
- Frontend stack: React 19, TypeScript, Vite, Tailwind CSS v4, Radix UI Primitives, Lucide React, TanStack Query v5, Recharts.
- CSP (Decided (2026-11-03, delegated), details in [security.md](security.md), "Security headers"): `vite.config.ts` sets `html.cspNonce` to the placeholder and `build.assetsInlineLimit: 0`. At startup the app reads the nonce from `<meta property="csp-nonce">` through the element's `nonce` property, calls `setNonce` from `get-nonce` before the first render, and passes `nonce` to every Radix Select and ScrollArea viewport. No inline `<style>` or `style` attribute in markup. Styles come from Tailwind classes or the React `style` prop.
- Layout proportions not yet decided (for example any 60/40 split) must be confirmed with the user before the frontend is built.

## Screen designs (approved 2026-11-03)

- Approved (2026-11-03, user, #35): every v1 screen below. The approved artboards are in [designs/](designs/) as static HTML. The live canvas is the private artifact "HarborGate v1 screens" (https://claude.ai/artifact/2obq8cfJ1X4GmDEuLPV2o6).
- The artboards set layout, copy, states, and which controls exist. Their sample data is illustrative. Their inline `style` attributes are drawing aids only: the build uses Tailwind classes and the theme tokens, because the CSP forbids inline styles in markup (see "Process rules").
- Approved screens, with their artboard and route:

| Screen | Artboard | Route |
| --- | --- | --- |
| Login | `Login.dc.html` | `/login` |
| First-run setup | `Setup.dc.html` | `/setup` |
| Dashboard | `Main.dc.html` | `/` |
| Mappings list | `Mappings.dc.html` | `/mappings` |
| New mapping (duplicate-target error state) | `MappingNew.dc.html` | `/mappings/new` |
| Mapping created (shown-once values) | `MappingCreated.dc.html` | shown in place after create; not a URL |
| CVE list | `Cves.dc.html` | `/cves` |
| Per-CVE view | `CveDetail.dc.html` | `/cves/:id` |
| Accept risk dialog | `CveAccept.dc.html` | modal on `/cves/:id` |
| Sync jobs | `SyncJobs.dc.html` | `/sync-jobs` |
| Account | `Account.dc.html` | `/account` |
| Add credential | `CredentialNew.dc.html` | `/account/credentials/new` |
| Admin: Jobs | `AdminJobs.dc.html` | `/admin/jobs` |
| Admin: Failed syncs | `AdminFailed.dc.html` | `/admin/failed` |
| Admin: Audit log | `AdminAudit.dc.html` | `/admin/audit` |
| Admin: Health | `AdminHealth.dc.html` | `/admin/health` |
| Admin: Settings > OIDC | `AdminOidc.dc.html` | `/admin/settings/oidc` |
| Admin: Settings > Users | `AdminUsers.dc.html` | `/admin/settings/users` |
| Admin: Settings > Alerts | `AdminAlerts.dc.html` | `/admin/settings/alerts` |
| Admin: Settings > Backup and restore | `AdminBackup.dc.html` | `/admin/settings/backup` |
| Shell parts: rail, sticky header, Admin tabs | `Rail.dc.html`, `Topbar.dc.html`, `AdminTabs.dc.html` | every page |

- Decisions approved with the designs (2026-11-03, user):
  - Cards and forms span the full content width (64rem). No card has its own narrower limit.
  - Mapping form: the GitHub target section also holds a GitHub credential select, because `POST /mappings` needs `github_cred_id`. The Harbor source section holds the Harbor credential select.
  - Mappings has a list page with the columns Harbor source, GitHub target, Issues, Open CVEs (CRITICAL and HIGH), Last sync, and Actions.
  - Admins see a "My mappings / All mappings" toggle on Dashboard, Mappings, CVEs, and Sync jobs. "All mappings" sends `scope=all`. Regular users do not see it.
  - Admin Settings shows its four sections as a row of pill links under the tabs. Each section has its own URL.
  - Alert channels: saved config is never returned, so editing a channel means entering its whole config again. The edit form says so.
  - Per-CVE view: "Create issue" shows only for CRITICAL and HIGH, and is disabled while an open issue exists. CVE status uses an OPEN pill (neutral) and an ACCEPTED pill (accent).
  - Accept risk is a modal dialog (Radix Dialog).
  - Add credential: the primary button is "Save and test". It saves the credential, then calls `POST /credentials/:id/test` and shows the check results on the same page, with "Test again" and "Done". The API has no route that tests an unsaved credential.
  - Sync job Trigger shows `webhook` or `poll` ([api.md](api.md), Sync jobs). A retry keeps the job's trigger.
  - Light theme uses the same layouts with the light tokens. It is not drawn separately.
  - On narrow screens the rail becomes a drawer behind a menu button in the sticky header. It is not drawn separately.
- Decided (2026-11-03, delegated): details the designs leave open.
  - Sticky header: the environment badges (Harbor reachable, GitHub reachable, robot account expiry within 14 days) are shown to admins only. They come from `GET /api/v1/admin/health`, fetched at most once every 10 minutes, because that route makes outbound calls. Regular users see no badges. The header also shows the app version (from `frontend/package.json`, injected at build time) and Sign out.
  - Edit mapping (`/mappings/:id`) reuses the approved New mapping form, filled in. Below the form, a "Webhook" card has "Rotate webhook URL" and "Rotate auth secret". Each rotation asks for confirmation in a dialog and then shows the new value in the approved shown-once panel. A "Delete mapping" button opens a confirmation dialog that says open GitHub issues stay open. Edit credential reuses the Add credential form with the token field empty ("Leave empty to keep it"). These screens are built from approved parts and were not drawn separately.
  - Shown-once values live only in component state. They are never written to `localStorage`, the URL, the TanStack Query cache, or logs. Leaving the screen discards them.
  - Routing uses `react-router` (declarative `createBrowserRouter`). Signed-out visitors go to `/login`, or to `/setup` while `setup_required` is true.

## House style and precedence

- House style is shared with the Astraya project. It is not a copy of Astraya. Astraya is inspiration and a starting point.
- Improve on Astraya where that serves HarborGate users better, and document each intentional difference and its reason in this file.
- Adapt, do not transfer. Astraya's domain-specific UI decisions (astrology charts, persons, element and aspect colours, tone names, chart pages) are not carried over. Keep the underlying principle and re-decide the concrete choice for HarborGate: CVE findings, Harbor repositories, GitHub targets, sync jobs, admin and audit views.
- Astraya concrete values (colours, shell items, page names) may be reused only where they fit HarborGate's domain, and each reuse is justified here.
- Precedence: where Astraya's UI style conflicts with this spec, this spec wins. If a conflict cannot be resolved that way, ask the user which takes precedence before building that part.

## App shell (decided)

- Collapsible left rail. Adapted from Astraya's documented target shell.
- Top rail items, in order: Dashboard, Mappings, CVEs, Sync jobs.
- Bottom rail items: Admin (admins only), Account.
- Content header holds the page title and the primary action.
- Sticky header with environment status badges.
- Content width capped at 64rem.
- On narrow screens the rail becomes a drawer.
- Reason for the adaptation: HarborGate's core objects are mappings, CVE findings, and sync jobs, and Admin is role-gated.

## Page map (decided)

- Dashboard: summary and recent syncs.
- Mappings: create and edit. Decided (2026-11-03): the webhook URL and the auth secret are shown once, after create or rotation, with a copy button. They cannot be shown again; the user rotates to get a new one.
- CVEs: list, and a per-CVE view.
- Sync jobs: sync history and failures. Replaces a separate Logs page.
- Admin (admins only): five tabs, see below.
- Account: profile, credentials, theme, language. Replaces a separate Settings page.
- Decided (2026-11-03): theme and language preferences are stored in the browser (`localStorage`), not on the server. No server route or `users` column holds them.
- Login: outside the shell, shown before authentication.
- Scope: all pages above are in the first release.

## Dashboard (decided)

- Summary counts: open CVEs by severity (CRITICAL, HIGH), fixed CVEs, open GitHub issues, failed syncs.
- Below the counts: recent syncs with status and time. Failed rows have a retry action.

## Mapping form (decided)

- One page. Stacked, grouped sections in this order:
  - Harbor source: Harbor project, Harbor repository, credential.
  - GitHub target: GitHub owner, GitHub repository, default branch.
  - Issues: auto-create issues on or off, minimum severity.
- Actions: Cancel and Save mapping.
- Duplicate target: shows an inline error under the GitHub repository field: "Already used by mapping <name>. Choose another repository." Save is blocked until the target changes.
- The app never moves a target from one mapping to another.

## Settings rows (decided)

- Stacked layout: label, then optional help text, then the control, in one column.
- Do not use the Astraya 60/40 two-column grid for HarborGate forms.
- Multi-field forms (mappings, credentials) use the same stacked pattern.

## Per-CVE view (decided)

- A detail page for one CVE, linkable by URL.
- Header: CVE id, severity pill, status pill, package, first seen date, link to the GitHub issue, and an "Accept risk" action.
- Decided (2026-11-03): the manual-issue button sits in this header, next to the GitHub issue link. It calls `POST /api/v1/cves/{id}/issue`.
- Below the header: a table with one row per tracked tag (up to 10). Columns: tag, status, last scan date, fixed-in version when known.

## Admin (decided)

- One Admin entry in the rail, shown to admins only.
- Five tabs:
  - Jobs: housekeeping and sync jobs, with counts and errors. Includes cleanup and retention runs and polling runs.
  - Failed syncs: error message and a retry action.
  - Audit log: admin actions such as user create and delete, role changes, OIDC config changes, credential rotation.
  - Health: Harbor and GitHub reachability, token expiry, missing scopes, robot account expiry date with a warning 14 days before it lapses (Decided 2026-11-03, see [integrations.md](integrations.md)). Decided (2026-11-03, delegated): it also shows the code scanning state of each GitHub target (ready, no analysis yet, or unavailable), and the client IP HarborGate sees for the admin's own request, with its source ([api.md](api.md), "Health").
  - Settings (OIDC, Users, Alerts, Backup and restore): sections for the OIDC, Users, Alerts, and Backup and restore screens.
- Decided (2026-11-03): Settings is the fifth tab, after Health. It holds the OIDC, Users, Alerts, and Backup and restore screens. Admin stays a single rail entry.
- Settings > OIDC (decided 2026-11-03): OIDC settings and the toggle that restricts regular users to OIDC are managed here, stored encrypted (client secret AES-256-GCM), and every change is audited as `oidc.config_change`. Admin break-glass is always available. The "OIDC only for regular users" toggle restricts regular users to OIDC sign-in (Decided 2026-11-03, see [security.md](security.md)). See [security.md](security.md).
- Settings > Users (decided 2026-11-03): an admin can create a local user (username, email, password, role; the password must be at least 15 characters and at most 64), change a user's role, and delete a user. Decided (2026-11-03): role changes are for local users only. An OIDC user's role comes from the group claim and is shown read-only. OIDC users appear in the list after their first login. They are not created from this screen.
- Setup page (first-run, not a Settings screen): shown only while no users exist. Its design was approved on 2026-11-03 (`Setup.dc.html`).
- Design before build: the screen designs for the four Settings sections and the Setup page were approved on 2026-11-03 (see "Screen designs").

## Visual direction (decided)

- House style, dark-first. Dark is the default theme. Light is a full peer theme, with every token defined.
- Dark: background `#0b0c18`, surface `#15162a`, text `#eceafa`, accent `#a390fb`.
- Light: background `#fbfaff`, surface `#f3f1fa`, text `#16152b`, accent `#5b3fd4`.
- Focus: a visible 2px ring in the accent colour.
- Status colours come from the list below, not from Astraya's element or aspect colours.

## Status colours

- Critical: `#ef4444`
- High: `#f97316`
- Medium: `#eab308`
- Low: `#3b82f6`
- Success: `#10b981`

## Status pills (decided)

- Tables show every severity and status as a coloured pill with a text label, for example CRITICAL, HIGH, OPEN, FIXED.
- Colour is never the only signal.

## Components

- Collapsible left sidebar.
- Sticky header with environment status badges.
- Dense tables with inline status pills.
- Copyable SHA badges in `font-mono`.

## i18n

- English only in v1.
- All user-visible text lives in a string catalog file. Strings are never hard-coded in components.
- Decided (2026-11-03): the catalog is one English file, `frontend/src/i18n/en.json`. A future language is a sibling file (for example `frontend/src/i18n/nl.json`). No per-area catalog folders.
- Adding a language later is a translation task.
