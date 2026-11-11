# Frontend

Purpose: app shell, page map, screen designs, visual direction, status pills, i18n, and the house style rules for dockward 0.2.0.

## Process rules

- Design before build. Every screen's design is proposed and approved by the user before it is implemented.
- Frontend stack: React 19, TypeScript, Vite, Tailwind CSS v4, Radix UI Primitives, Lucide React, TanStack Query v5, Recharts.
- CSP (Decided (2026-11-03, delegated), details in [security.md](security.md), "Security headers"): `vite.config.ts` sets `html.cspNonce` to the placeholder and `build.assetsInlineLimit: 0`. At startup the app reads the nonce from `<meta property="csp-nonce">` through the element's `nonce` property, calls `setNonce` from `get-nonce` before the first render, and passes `nonce` to every Radix Select and ScrollArea viewport. No inline `<style>` or `style` attribute in markup. Styles come from Tailwind classes or the React `style` prop.
- Layout proportions not yet decided (for example any 60/40 split) must be confirmed with the user before the frontend is built.

## Screen designs (approved 2026-11-03)

- Approved (2026-11-03, user, #35): every v1 screen below. The approved artboards are in [designs/](designs/) as static HTML. The live canvas is the private artifact "dockward v1 screens" (https://claude.ai/artifact/2obq8cfJ1X4GmDEuLPV2o6).
- The artboards set layout, copy, states, and which controls exist. Their sample data is illustrative. Their inline `style` attributes are drawing aids only: the build uses Tailwind classes and the theme tokens, because the CSP forbids inline styles in markup (see "Process rules").
- Approved screens, with their artboard and route:

| Screen | Artboard | Route |
| --- | --- | --- |
| Login | `Login.dc.html` | `/login` |
| First-run setup | `Setup.dc.html` | `/setup` |
| Dashboard | `Main.dc.html` | `/` |
| Sources list (was Mappings) | `Mappings.dc.html` | `/sources` (design approved for Harbor mappings; reused, see 'Sources and Images') |
| New source (was New mapping) | `MappingNew.dc.html` | `/sources/new` |
| CVE list | `Cves.dc.html` | `/cves` |
| Per-CVE view | `CveDetail.dc.html` | `/cves/:id` |
| Accept risk dialog | `CveAccept.dc.html` | modal on `/cves/:id` |
| Jobs (was Sync jobs) | `SyncJobs.dc.html` | `/jobs` |
| Account | `Account.dc.html` | `/account` |
| Add credential | `CredentialNew.dc.html` | `/account/credentials/new` |
| Admin: Jobs | `AdminJobs.dc.html` | `/admin/jobs` |
| Admin: Failed jobs (was Failed syncs) | `AdminFailed.dc.html` | `/admin/failed` |
| Admin: Audit log | `AdminAudit.dc.html` | `/admin/audit` |
| Admin: Health | `AdminHealth.dc.html` | `/admin/health` |
| Admin: Settings > OIDC | `AdminOidc.dc.html` | `/admin/settings/oidc` |
| Admin: Settings > Users | `AdminUsers.dc.html` | `/admin/settings/users` |
| Admin: Settings > Alerts | `AdminAlerts.dc.html` | `/admin/settings/alerts` |
| Admin: Settings > Backup and restore | `AdminBackup.dc.html` | `/admin/settings/backup` |
| Admin: Settings > GitHub | (no artboard; minimal) | `/admin/settings/github` |
| Shell parts: rail, sticky header, Admin tabs | `Rail.dc.html`, `Topbar.dc.html`, `AdminTabs.dc.html` | every page |

- Decisions approved with the designs (2026-11-03, user):
  - Cards and forms span the full content width (64rem). No card has its own narrower limit.
  - Removed (dockward 0.2.0, decision 1): the Harbor-era approval note for this screen no longer applies. The reused parts are listed under "Sources and Images".
  - Removed (dockward 0.2.0, decision 1): the Harbor-era approval note for this screen no longer applies. The reused parts are listed under "Sources and Images".
  - Removed (dockward 0.2.0, decision 1): the Harbor-era approval note for this screen no longer applies. The reused parts are listed under "Sources and Images".
  - Admin Settings shows its four sections as a row of pill links under the tabs. Each section has its own URL.
  - Alert channels: saved config is never returned, so editing a channel means entering its whole config again. The edit form says so.
  - Removed (dockward 0.2.0, decision 1): the Harbor-era approval note for this screen no longer applies. The reused parts are listed under "Sources and Images".
  - CVE list (Decided 2026-11-05, user, #129): the default view shows every severity. CVE status uses an OPEN pill (neutral) and an ACCEPTED pill (accent). Decided (2026-11-07, user, #196, decisions 21 and 22): the list shows the CVEs of the newest scanned digest of each mapping only. A CVE that is open only on an older tag is not listed. The `tag` filter offers the newest-digest tags only. Rules: [cve-lifecycle.md](cve-lifecycle.md), "Tracking per tag". The filter header is replaced by the control bar in "CVE list control bar" below (2026-11-08, user, #257).
  - Accept risk is a modal dialog (Radix Dialog).
  - Removed (dockward 0.2.0, decision 1): the Harbor-era approval note for this screen no longer applies. The reused parts are listed under "Sources and Images".
  - Removed (dockward 0.2.0, decision 1): the Harbor-era approval note for this screen no longer applies. The reused parts are listed under "Sources and Images".
  - Light theme uses the same layouts with the light tokens. It is not drawn separately.
  - On narrow screens the rail becomes a drawer behind a menu button in the sticky header. It is not drawn separately.
- Decided (2026-11-03, delegated): details the designs leave open.
  - Sticky header: the environment badges (registry reachable, GitHub reachable) are shown to admins only. They come from `GET /api/v1/admin/health`, fetched at most once every 10 minutes, because that route makes outbound calls. Regular users see no badges. The header also shows the app version (from `frontend/package.json`, injected at build time) and Sign out.
  - Edit source (`/sources/:id`) reuses the source form, filled in. A "Delete source" button opens a confirmation dialog that says open GitHub issues stay open. Edit credential reuses the Add credential form with the token field empty ("Leave empty to keep it").
  - Shown-once values live only in component state. They are never written to `localStorage`, the URL, the TanStack Query cache, or logs. Leaving the screen discards them.
  - Routing uses `react-router` (declarative `createBrowserRouter`). Signed-out visitors go to `/login`, or to `/setup` while `setup_required` is true.

## House style and precedence

- House style is shared with the Astraya project. It is not a copy of Astraya. Astraya is inspiration and a starting point.
- Improve on Astraya where that serves dockward users better, and document each intentional difference and its reason in this file.
- Adapt, do not transfer. Astraya's domain-specific UI decisions (astrology charts, persons, element and aspect colours, tone names, chart pages) are not carried over. Keep the underlying principle and re-decide the concrete choice for dockward: CVE findings, Harbor repositories, GitHub targets, sync jobs, admin and audit views.
- Astraya concrete values (colours, shell items, page names) may be reused only where they fit dockward's domain, and each reuse is justified here.
- Precedence: where Astraya's UI style conflicts with this spec, this spec wins. If a conflict cannot be resolved that way, ask the user which takes precedence before building that part.

## App shell (decided)

- Collapsible left rail. Adapted from Astraya's documented target shell.
- Top rail items, in order (`frontend/src/components/shell/Rail.tsx`): Dashboard, Sources, Images, CVEs, Jobs. Images is in the rail design of the spinoff (spinoff section 11) but has no page in the router yet; see the Images note below.
- Bottom rail items: Admin (admins only), Account.
- Content header holds the page title and the primary action.
- Sticky header with environment status badges.
- Content width capped at 64rem.
- On narrow screens the rail becomes a drawer.
- Reason for the adaptation: dockward's core objects are image sources, CVE findings, and jobs, and Admin is role-gated.

## Page map (decided)

The routes are in `frontend/src/routes.tsx`. This is the built map:

- `/` Dashboard: summary and recent jobs.
- `/sources` and `/sources/new`, `/sources/:id`: list, create, and edit an image source (hub, repository, tag value, GitHub target, registry credential, issue settings). See "Sources and Images".
- `/cves` and `/cves/:id`: the CVE list and the per-CVE view.
- `/jobs`: job history and failures, with retry and purge.
- `/account` (profile, appearance, credentials) and `/account/credentials/new`, `/account/credentials/:id`.
- `/admin`: five tabs, see "Admin".
- `/login` and `/setup`: outside the shell, shown before authentication.
- Not built: `/images` (the Images page in the spinoff design) and the Hubs and Scan-settings screens of spinoff section 11. Each needs design approval before it is built (decision 51).
- Theme and language preferences are stored in the browser (`localStorage`), not on the server. No server route or `users` column holds them (Decided 2026-11-03).
- Scope: all pages above are in the first release. Pages not listed here are not built.

## Dashboard (decided)

- Summary counts: open CVEs by severity (CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN; every severity since 2026-11-05, user, #129), fixed CVEs, accepted CVEs, open GitHub issues, failed jobs.
- Decided (2026-11-07, user, #196, decisions 21 and 22): the CVE counts (open by severity, fixed) follow the newest scanned digest of each mapping, the same view as the CVE list. A CVE open only on an older tag adds nothing to them. Decided (2026-11-07, user, #196, decision 23): the fixed count follows the newest digest only too, so a CVE that only an older digest reported as fixed adds nothing to it. The same holds for the Open CVEs column of the mapping list. Rules: [cve-lifecycle.md](cve-lifecycle.md), "Dashboard counts". No layout changes, so no new design is needed.
- Decided (2026-11-08, user, #247): the summary shows an accepted-CVE card between the Fixed card and the Issues card. It shows the number of CVEs with an active acceptance in the same scope as the other counts (newest-digest view; the admin `scope=all` toggle applies). Accepted is its own count and is not mixed into open; the open count is unchanged. The card is display only and changes no acceptance. Its text is catalog keys. The two astraya Medium acceptances stay as they are.
- Below the counts: recent jobs with status and time. Failed rows have a retry action.

## Sources and Images (spinoff, decided by decision 51)

- The Sources list and form reuse the approved mapping list and form parts. Stacked sections in this order: Image source (hub select, repository, tag value with a live exact-or-pattern hint and a preview), GitHub target (owner, repository, default branch), Issues (auto-create on or off, minimum severity), Registry credential (optional on `docker.io`; a note when none is set; on `ghcr.io` a hint that only a classic token with `read:packages` works).
- Actions: Cancel and Save source. Duplicate (hub, repository, tag value): an inline error; a `409` from the save shows the catalog text for that case.
- Source detail: an images table (tag, platform, state, pulled time, per-scanner scan state, database date) and a Scan now button.
- Images page (spinoff section 11): stored images, size, and which is evicted next. Not built; needs design approval.
- Hubs and Scan settings (Admin > Settings): hubs are listed by host alone. Not built; needs design approval.
- Status: the Sources list and form are built (`frontend/src/pages/SourcesPage.tsx`, `SourceFormPage.tsx`). The design is the Harbor mapping design, reused with no new visual, as decision 51 allows. The user reviews and approves it in the browser before release.
- Removed (spinoff, decision 1): the Harbor project and repository pickers, the project webhook proposal, the scheduled scan card, the Scans card and its scanner switch states, and the Harbor source columns.

## Jobs page: purge failed jobs (#243)

Decided (2026-11-08, user, #243, decisions 1 to 4; spinoff decision 58 renamed the page): the Jobs page has a "Purge failed jobs" button that deletes every failed job in one action, after a confirmation that shows the count. Rules: [api.md](api.md), "Purge failed jobs" (the route is `/api/v1/jobs/purge-failed`).

- Placement: in the page header, on the right, next to the "My sources / All sources" toggle. It is a secondary button with the destructive text colour. It is visible to every signed-in user.
- Count: the page reads `GET /api/v1/jobs/failed-count` with the same `scope` as the list.
- Disabled state: with a count of zero, the button is disabled. While the count loads, or if it failed to load, the button is also disabled. A failed count load shows `syncJobs.purge.countFailed` next to the button.
- Confirmation dialog (Radix Dialog, modal): the title names the action, the body shows the count and states that the delete is permanent, and there are two buttons, Cancel (focused by default) and a destructive confirm button. Escape and Cancel close it without any request.
- Success: the dialog closes, the list and the count are refetched, and a status line (`role="status"`) shows `syncJobs.purge.success` with the `deleted` value from the response. A job kept because it holds the scanner lock stays in the list as a failed row.
- Failure: the dialog stays open and shows `syncJobs.purge.failed` inline. Nothing is deleted.
- Catalog keys (all in `frontend/src/i18n/en.json`): `syncJobs.purge.button`, `syncJobs.purge.title`, `syncJobs.purge.body`, `syncJobs.purge.confirm`, `syncJobs.purge.cancel`, `syncJobs.purge.success`, `syncJobs.purge.failed`, `syncJobs.purge.countFailed`. The keys keep their names; the spinoff does not rename catalog keys. The `syncJobs.purge.body` text says "CVE findings, reports, GitHub issues, and alerts are not changed."
- Status: built in `frontend/src/pages/JobsPage.tsx`; the design needs user approval before the next change.

## Tag scans (removed, decision 1)

Removed with Harbor. The per-tag Scan button, the scanner picker, the scanner switch and restore states, and the Scans card on the mapping page belonged to Harbor's scanner switch. dockward 0.2.0 has no Harbor scanner. Its scans are run by the app itself on every stored platform image (spinoff section 6). The catalog keys `mapping.scan.*` and the Harbor `sync.note.*` keys are removed with the feature. `sync.note.scanForbidden` and the other keys that name Harbor are removed as well.

## Settings rows (decided)

- Stacked layout: label, then optional help text, then the control, in one column.
- Do not use the Astraya 60/40 two-column grid for dockward forms.
- Multi-field forms (sources, credentials) use the same stacked pattern.

## CVE list control bar (decided)

Decided 2026-11-08 (user, #257, decisions 1 to 13), with the Fix available group (user, #265, decisions 1 to 4). Spinoff section 11 changes the filter row (decision 38): the Harbor Project filter is replaced by a Namespace filter. The layout below is the approved design. The spinoff changes are listed under it.

- Layout, top to bottom, in one card under the page title:
  1. One search field, full width, with an inline Clear button that empties it. It matches the CVE id, the package, the Harbor project and the Harbor repository as a case-insensitive substring (a `LIKE %q%` match). `%` and `_` in the text are literal characters, never wildcards. The URL and the request update 300 ms after the last keystroke.
  2. Three pill groups on one wrapping row: Severity (CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN), Status (Open, Fixed, Accepted) and GitHub issue (Has issue, No issue). Severity and Status are multi-select. Has issue and No issue are one group and exclusive: pressing the pressed one clears it. A pill is an outline when off and filled with its tone when on, and carries a dot that is hollow when off and solid when on, so state is not colour alone. Each is a button with `aria-pressed`, in a group with an accessible name. Fix available (Decided 2026-11-09, user, issue #265, decisions 1 to 4): a fourth pill group, labelled "Fix available", sits after the GitHub issue group with two pills, Fix available and No fix. Like Severity and Status it is multi-select, with the same pill style, `aria-pressed` and accessible group name. Both pills on, or both off, filter nothing. The rule is the Fixed in column's value (decision 1): a CVE is Fix available exactly when its Fixed in column shows a version, and No fix exactly when it shows Unknown (decision 3), so the filter and the column always agree and Fix available never lists an Unknown row. With several scanners (#224, decision 2) the column value is the merged one, the first scanner in the merged order that reports a fixed version, so a CVE is Fix available when at least one scanner reports a fixed version.
  3. One row of four comboboxes: Namespace, Repository, Tag, Mapping. Each takes one choice. Each is searchable and keyboard operable (ARIA combobox: Down opens, Up and Down move, Enter selects, Escape closes), and its first option clears it ("All namespaces", "All repositories", "All tags", "All mappings"). Mapping is last and is the only scope control: there is no My Mappings / All Mappings toggle on this page. For an admin, All mappings covers every tenant's mappings (the page sends `scope=all`); for anyone else it covers their own. Selecting a namespace narrows the Repository options to that project's repositories, and a chosen repository that no longer fits is cleared. The Tag options are the tracked tags of the mapping in view (`GET /mappings/:id/tags`) when one Mapping is chosen; with All mappings the Tag combobox accepts a typed tag name.
- Combine rule (decisions 7 and 8): values within one group are OR, and groups are AND. Status: Open shows only open CVEs without an active acceptance; Accepted shows only CVEs with an active acceptance; Fixed shows fixed CVEs. Open and Accepted together show both sets. With no Status pill on, the page applies Open (the last Status pill stays on). With no Severity pill on, every severity shows. Namespace, Repository, Tag and Mapping are AND-ed with the groups.
- URL sync: every control is in the query string and is restored on load: `q`, `severity` (comma list), `status` (comma list, lowercase), `has_issue` (`true` or `false`), `fix` (comma list of `available` and `none`; Decided 2026-11-09, user, #265), `project`, `repository`, `tag`, `mapping`, plus `page` and `order`. A default is left out. Old links keep working (decision 9): `accepted=true` selects the Accepted pill, `accepted=false` with `status=open` selects Open, and `harbor_project`, `harbor_repository` and `mapping_id` are read as `project`, `repository` and `mapping`. The new name wins when both are present. Dashboard cards link here: the Accepted card opens `accepted=true` and the Issues card opens `has_issue=true`.
- Table columns: CVE, Severity, Status, Package, Fixed in, Mapping, Tags (n of m), Issue, Action. Tags n of m (decisions 5 and 11): n is the number of image tags of the mapped repository that currently contain the CVE (`open_tags`). The count is the tags on the newest scanned digest, capped at 10. A tag the registry no longer lists still counts until its source is deleted; no removal path is built yet. Decision 11 reworded 2026-11-11 (#257): the Harbor framing is removed; the count follows the code. The table scrolls horizontally when it is wider than the card.
- Issue and Action columns (decisions 10 and 12): the Issue column shows `#number` linking to the issue, with the text `closed` beside it when the issue is closed, or `None` when there is none. The Action column does not change with the filters. A row with an issue (open or closed) shows View issue, a link to the issue; it never offers Create issue. A row without an issue, open on at least one tag and owned by the signed-in user, shows Create issue: disabled while an active acceptance exists, otherwise it opens a confirmation dialog that names the GitHub repository (`owner/repo`) and the CVE (with its package and severity) and states that nothing is created until Confirm. Confirm calls `POST /cves/:id/issue`; Cancel, Escape and the close button create nothing. This confirmation applies to every severity on the list; the per-CVE view keeps its own rule.
- Layout (decision 13): at 1280px the bar and the first table rows are visible without scrolling. Below 1024px the pill groups stack and wrap, the four comboboxes stack one per row, and the table keeps its horizontal scroll.
- Empty and error states are unchanged (`cves.empty`, the shared error message). A failed issue creation shows the server message in an alert above the table.
- Catalog keys (all in `frontend/src/i18n/en.json`, English only): `cves.filter.group`, `cves.filter.search`, `cves.filter.searchPlaceholder`, `cves.filter.clear`, `cves.filter.severity`, `cves.filter.status`, `cves.filter.issue`, `cves.filter.hasIssue`, `cves.filter.noIssue`, `cves.filter.fix`, `cves.filter.fixAvailable`, `cves.filter.noFix`, `cves.filter.namespace`, `cves.filter.repository`, `cves.filter.tag`, `cves.filter.mapping`, `cves.filter.allNamespaces`, `cves.filter.allRepositories`, `cves.filter.allTags`, `cves.filter.allMappings`, `cves.combo.noMatch`, `cves.combo.useValue`, `cves.col.tags`, `cves.tags`, `cves.action.viewIssue`, `cves.action.createIssue`, `cves.createDialog.title`, `cves.createDialog.body`, `cves.createDialog.repo`, `cves.createDialog.cve`, `cves.createDialog.package`, `cves.createDialog.confirm`. Keys of the removed controls (chips, exact-match inputs) are deleted.

## Per-CVE view (decided)

- A detail page for one CVE, linkable by URL. `{id}` is `<source_id>:<cve_id>`, URL-encoded.
- Header: CVE id, severity pill, status pill, package, first seen date, link to the GitHub issue, and an "Accept risk" action.
- The manual-issue button sits in this header, next to the GitHub issue link. It calls `POST /api/v1/cves/{id}/issue`.
- Below the header: a table with one row per tracked tag that reports this CVE (up to 10). Columns: tag, status, last scan date, fixed-in version when known.
- A row for a tag of the newest scanned digest has no marker. A row for any other tag shows the plain text `cves.detail.olderTag`.
- The page is reached by its URL; the CVE list does not link to it.
- Catalog keys: `cves.detail.olderTag` ("Older tag, not counted"), `cves.detail.olderTagsOnly` ("Open on older tags only: {tags}").

## Admin (decided)

- One Admin entry in the rail, shown to admins only.
- Five tabs (`frontend/src/components/shell/AdminTabs.tsx`):
  - Jobs: housekeeping and job runs, with counts and errors (`job_runs` and the jobs queue).
  - Failed jobs: error message and a retry action. The tab also has the "Purge failed jobs" action, always with `scope=all`.
  - Audit log: admin actions such as user create and delete, role changes, OIDC config changes, credential rotation.
  - Health: registry reachability, GitHub token state, missing scopes, and the client IP dockward sees for the admin's own request ([api.md](api.md), "Health"). Spinoff: the Harbor rows and the robot account expiry are removed, and per-hub reachability, pinned scanner versions, and free disk are added (spinoff section 10).
  - Settings: OIDC, Users, Alerts, GitHub, and Backup and restore. Each is a URL (`/admin/settings/oidc`, `/users`, `/alerts`, `/github`, `/backup`). Hubs and Scan settings are not built yet.
- Settings > GitHub: an admin sets the instance GitHub API base URL and web URL. Two optional text fields, a save button, and a discard button; empty means github.com. An invalid value shows `settings.github_url_invalid`. Rules: [security.md](security.md), "GitHub base URL".
- Settings > OIDC: OIDC settings and the toggle that restricts regular users to OIDC sign-in. Every change is audited as `oidc.config_change`. Admin break-glass is always available.
- Settings > Users: an admin can create a local user, change a user's role, and delete a user. The password must be at least 15 characters and at most 64. An OIDC user's role comes from the group claim and is shown read-only.
- Settings > Alerts: alert channels. Saved config is never returned, so editing a channel means entering its whole config again. The edit form says so.
- Settings > Backup and restore: creates a backup. Restore is a CLI command, not in this screen ([security.md](security.md)).
- Setup page (first run, not a Settings screen): shown only while no users exist.

## Visual direction (decided)

- House style, dark-first. Dark is the default theme. Light is a full peer theme, with every token defined.
- Dark: background `#0b0c18`, surface `#15162a`, text `#eceafa`, accent `#a390fb`.
- Light: background `#fbfaff`, surface `#f3f1fa`, text `#16152b`, accent `#5b3fd4`.
- Dark `surface-2` is `#1b1c34`, border `#25264a`, muted text `#9b98b8` (values from the approved artboards).
- Light `surface-2`, border and muted text (Decided (2026-11-04, user, #36): derived from the existing palette, for the user's review before merge): `surface-2` `#e9e6f4`, border `#d9d5ea`, muted `#5d5a7a`. Muted is the dark muted hue, darkened until it reaches WCAG 2.x contrast of at least 4.5:1 (SC 1.4.3) on both light backgrounds. The artboards are dark only, so these have no artboard.
- Contrast ratios (WCAG 2.x relative luminance, computed 2026-11-04):

| Pair | Dark | Light |
| --- | --- | --- |
| Muted on background | 7.02 | 6.30 |
| Muted on surface | 6.42 | 5.85 |
| Muted on surface-2 | 6.00 | 5.33 |
| Text on background | 16.40 | 17.19 |
| Accent on background | 7.35 | 6.51 |
| Accent on surface | 6.73 | 6.04 |

- The text colour on a primary button (`on-accent`) is `#0b0c18` in dark and `#ffffff` in light.
- Focus: a visible 2px ring in the accent colour.
- Status colours come from the list below, not from Astraya's element or aspect colours.

## Status colours

- Critical: `#ef4444`
- High: `#f97316`
- Medium: `#ca8a04` (Decided (2026-11-04, user, #36): was `#eab308`, adjusted because its pill text failed contrast on light; see below)
- Low: `#3b82f6`
- Success: `#10b981`
- One set for both themes (Decided (2026-11-04, user, #36)). The five values above are the dots, borders and tinted fills of a pill. The pill text is a lighter tint in dark and a darker shade in light, so the text keeps its contrast on the tinted fill. Colour is never the only signal (see "Status pills").
- Pill text on its tinted fill, WCAG 2.x contrast (computed 2026-11-04; fill is the status colour at 12% over the page background, 10% for Medium, as in the artboards; each cell is "on background / on surface"):

| Status | Dark text | Dark | Light text | Light |
| --- | --- | --- | --- | --- |
| Critical | `#fca5a5` | 9.27 / 8.37 | `#8d2f39` | 6.66 / 6.22 |
| High | `#fdba74` | 10.08 / 9.04 | `#93491f` | 5.60 / 5.23 |
| Medium | `#fde047` | 13.24 / 11.90 | `#795516` | 5.87 / 5.47 |
| Low | `#93c5fd` | 9.55 / 8.55 | `#2a519b` | 6.44 / 6.01 |
| Success | `#6ee7b7` | 10.97 / 9.80 | `#136f5a` | 5.24 / 4.89 |

- The light text is the status colour mixed 55% with the light text colour. Every pair is at least 4.5:1. With the original Medium `#eab308` the light text reached only 4.47 / 4.18 on background / surface, which fails, so only Medium was changed. The other four values are unchanged.

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
