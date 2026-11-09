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
  - Mappings has a list page with the columns Harbor source, GitHub target, Issues, Open CVEs, and Last sync. Changed (2026-11-09, user, issue #263, decisions 1 and 2): the row opens the mapping (`/mappings/:id`) on click or Enter, there is no Edit button, and the mapping name in the first column is a link to the same page. Inner controls (links, buttons) keep their own action; only clicks on the rest of the row open the mapping. Rows have a pointer cursor, a hover state, and a visible focus style. Only the owner's rows are clickable and linked, as the edit page was before. Changed (2026-11-05, user, #129): Open CVEs shows every severity with a breakdown (CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN), not only CRITICAL and HIGH. The changed column needs design approval before it is built.
  - Admins see a "My mappings / All mappings" toggle on Dashboard, Mappings, and Sync jobs. "All mappings" sends `scope=all`. Regular users do not see it. Changed (2026-11-08, user, #257, decision 2): the CVE page has no toggle; its Mapping combobox is the scope control (see "CVE list control bar").
  - Admin Settings shows its four sections as a row of pill links under the tabs. Each section has its own URL.
  - Alert channels: saved config is never returned, so editing a channel means entering its whole config again. The edit form says so.
  - Per-CVE view: "Create issue" shows for a CVE of any severity that is open on at least one tag (Changed 2026-11-05, user, #129; until then CRITICAL and HIGH only), and is disabled while an open issue exists or an active acceptance exists. When `open_severity` is LOW or UNKNOWN, the button first asks for confirmation in a dialog; CRITICAL and HIGH stay one click (MEDIUM too, see [integrations.md](integrations.md)). A GitHub rate limit shows one clear message and is not retried in a loop. The changed button needs design approval before it is built.
  - CVE list (Decided 2026-11-05, user, #129): the default view shows every severity. CVE status uses an OPEN pill (neutral) and an ACCEPTED pill (accent). Decided (2026-11-07, user, #196, decisions 21 and 22): the list shows the CVEs of the newest scanned digest of each mapping only. A CVE that is open only on an older tag is not listed. The `tag` filter offers the newest-digest tags only. Rules: [cve-lifecycle.md](cve-lifecycle.md), "Tracking per tag". The filter header is replaced by the control bar in "CVE list control bar" below (2026-11-08, user, #257).
  - Accept risk is a modal dialog (Radix Dialog).
  - Add credential: the primary button is "Save and test". It saves the credential, then calls `POST /credentials/:id/test` and shows the check results on the same page, with "Test again" and "Done". The API has no route that tests an unsaved credential.
  - Sync job Trigger shows `webhook` or `poll` ([api.md](api.md), Sync jobs). A retry keeps the job's trigger. Decided (2026-11-07, #191): `schedule` shows "Schedule". A finished scheduled sync shows, under its image, "New vulnerabilities: <ids>" or "No new vulnerabilities" (catalog keys `syncJobs.newVulns`, `syncJobs.noNewVulns`), from `report.new_cve_ids`. The fixed scan notes and the Scan refusal show as catalog text (`sync.note.noTaggedImage`, `sync.note.scanAlreadyRunning`, `sync.note.scanForbidden`).
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

- Summary counts: open CVEs by severity (CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN; every severity since 2026-11-05, user, #129), fixed CVEs, open GitHub issues, failed syncs.
- Decided (2026-11-07, user, #196, decisions 21 and 22): the CVE counts (open by severity, fixed) follow the newest scanned digest of each mapping, the same view as the CVE list. A CVE open only on an older tag adds nothing to them. Decided (2026-11-07, user, #196, decision 23): the fixed count follows the newest digest only too, so a CVE that only an older digest reported as fixed adds nothing to it. The same holds for the Open CVEs column of the mapping list. Rules: [cve-lifecycle.md](cve-lifecycle.md), "Dashboard counts". No layout changes, so no new design is needed.
- Decided (2026-11-08, user, #247): the summary shows an accepted-CVE card between the Fixed card and the Issues card. It shows the number of CVEs with an active acceptance in the same scope as the other counts (newest-digest view; the admin `scope=all` toggle applies). Accepted is its own count and is not mixed into open; the open count is unchanged. The card is display only and changes no acceptance. Its text is catalog keys. The two astraya Medium acceptances stay as they are.
- Below the counts: recent syncs with status and time. Failed rows have a retry action.

## Mapping form (decided)

- One page. Stacked, grouped sections in this order:
  - Harbor source: Harbor project, Harbor repository, credential.
  - GitHub target: GitHub owner, GitHub repository, default branch.
  - Issues: auto-create issues on or off, minimum severity.
  - Scheduled scan (#191): a card below Issues, built from the existing parts (Card, Segmented, Field, select, time input), no new visual. Schedule is a segmented control Off, Daily, Weekly, Off by default. Daily shows "Time (UTC)"; Weekly shows "Day" (Monday to Sunday) and "Time (UTC)". Off shows neither. The help text says the robot needs the Scan permission. Catalog keys `mappings.form.scan*` and `mappings.form.weekday1` to `weekday7`. Decided (2026-11-07, delegated, #191): a new mapping's time defaults to 02:00 UTC in the form (the API default is 00:00) so a first daily run does not fall at midnight; reason: a quiet hour, and the user can change it.
- Actions: Cancel and Save mapping.
- Duplicate Harbor repository: shows an inline error on the Harbor repository field when the same Harbor repository is already mapped. Save is blocked until it changes. A GitHub repository already used by another mapping is not an error (Decided 2026-11-06, user, #185), and the form shows no warning for it. When the save itself returns `409 conflict` with detail `harbor_repository_mapped` (for example, a mapping owned by another user, which the form cannot see), the form shows the catalog text `mappings.form.harborRepositoryMapped` ("This Harbor repository is already mapped on this instance. Choose another repository."), which names no other user, mapping, or id (Decided 2026-11-06, user, #180). Every other save error keeps the fixed generic text.
- The app never moves a target from one mapping to another.
- Project webhook proposal (Decided 2026-11-06, user, #179): after Save mapping succeeds, the form proposes creating the project webhook only when the response has `project_webhook_exists: false`. Catalog keys: `mapping.projectWebhook.propose` ("Harbor project {project} has no project webhook yet. One webhook covers every repository in this project.") and `mapping.projectWebhook.create` ("Create project webhook"). It names the Harbor project and no repository. When `project_webhook_exists` is `true`, no proposal is shown. Decided (2026-11-06, user, #179): the proposal is an inline banner on the saved-mapping result, with the "Create project webhook" button. It is not a modal and does not block the user; the user can dismiss it. Placement (2026-11-07, delegated, #179): after a create, the banner is at the top of the mapping-created screen, above the shown-once values; after an edit save, it is below the form actions, and the edit page stays open instead of returning to the list. With `project_webhook_exists: true`, an edit save returns to the list as before.

## Sync jobs page: purge failed jobs (#243)

Decided (2026-11-08, user, #243, decisions 1 to 4): the Sync jobs page has a "Purge failed jobs" button that deletes every failed job in one action, after a confirmation that shows the count. Rules: [api.md](api.md), "Purge failed jobs". The button and dialog need design approval before they are built.

- Placement (Decided (2026-11-08, spec author, #243)): in the page header, on the right, next to the "My mappings / All mappings" toggle. It is a secondary button with the destructive text colour, built from the existing Button and Radix Dialog parts. It is visible to every signed-in user, because every user can purge their own mappings' jobs. Reason: the Accept risk dialog and the Delete mapping dialog use the same parts.
- Count: the page reads `GET /api/v1/sync-jobs/failed-count` with the same `scope` as the list (`scope=all` when an admin's toggle is on). The count is refetched after a retry, a purge, and when the toggle changes. On the Admin Failed syncs tab it is always `scope=all`.
- Disabled state: with a count of zero, the button is disabled and cannot open the dialog. While the count loads, or if it failed to load, the button is also disabled. A failed count load shows `syncJobs.purge.countFailed` next to the button.
- Confirmation dialog (Radix Dialog, modal, the destructive-action pattern of Delete mapping): the title names the action, the body shows the count and states the consequence, and there are two buttons, Cancel (focused by default) and a destructive confirm button that repeats the action and the count. Escape and Cancel close it without any request. The count is read when the dialog opens. While the purge request runs, both buttons are disabled.
- No undo: the delete is permanent (decision 2), so the dialog is the only safeguard. The body says it is permanent and says what is not changed (decision 3).
- Success: the dialog closes, the list and the count are refetched, and a status line above the table (`role="status"`) shows `syncJobs.purge.success` with the `deleted` value from the response, not the count shown in the dialog. A job kept because it holds the scanner lock stays in the list as a failed row.
- Failure: the dialog stays open and shows `syncJobs.purge.failed` inline. Nothing is deleted. Cancel and a second attempt both work. No server text is shown, only the catalog text.
- Catalog keys (all in `frontend/src/i18n/en.json`, parity kept; English text Decided (2026-11-08, spec author, #243)):

  | Key | English text |
  | --- | --- |
  | `syncJobs.purge.button` | Purge failed jobs |
  | `syncJobs.purge.title` | Purge failed jobs? |
  | `syncJobs.purge.body` | {count, plural, one {This permanently deletes 1 failed sync job.} other {This permanently deletes # failed sync jobs.}} CVE findings, reports, GitHub issues, and alerts are not changed. |
  | `syncJobs.purge.confirm` | {count, plural, one {Delete 1 failed job} other {Delete # failed jobs}} |
  | `syncJobs.purge.cancel` | Cancel |
  | `syncJobs.purge.success` | {count, plural, one {Deleted 1 failed job.} other {Deleted # failed jobs.}} |
  | `syncJobs.purge.failed` | Purge failed. Try again. |
  | `syncJobs.purge.countFailed` | Could not load the number of failed jobs. |

## Tag scans on the mapping page (#224)

Decided (2026-11-07, user, #224 d1, d8, d12): each tag has a Scan button on the mapping page, and a scanner picker appears there only when Harbor has more than one enabled scanner. The picker lists scanners by name. Nothing is stored as a default scanner.

- Placement (Decided 2026-11-07, delegated, #224): a "Scans" card on the mapping edit page (`/mappings/:id`), below Scheduled scan, with one row per tracked tag (the tag set of the CVE view, up to 10). Reason: the user said "the mapping page, per tag", and the edit page is the mapping's page today. Decided (2026-11-07, user, #224, dialogue): the design is approved as specified here and is built as written; no further approval is needed. The parts are existing ones (Card, table row, select, button), no new visual.
- Row: tag, last scan date, and one line per scanner that has a report for the tag's digest: scanner name, state pill (queued, running, waiting for report, ok, failed) and the reason when failed. A tag whose digest has no report shows "Not scanned".
- Scan button: with `scanner_choice` `available`, the button opens the scanner picker (a select, no preselected value, the button stays disabled until one is chosen, which is the "user must choose" rule). With `single`, one click starts the scan with no prompt. With `unavailable`, one click starts a scan with the project's current scanner, and the card shows `mapping.scan.noScannerAccess`.
- Switch notice (Decided 2026-11-07, delegated, #224): while `switch` is not null, a banner on the card shows `mapping.scan.switchActive`, and `mapping.scan.restorePending` while the restore is waiting. A failed restore shows `mapping.scan.restoreFailed` with a link to the Sync jobs page. Reason: other Harbor users of the project are affected, so the state must be visible.
- Errors from the start route use catalog text chosen by `code`: `409` shows `mapping.scan.alreadyRunning` or `mapping.scan.restoreWaiting`; `429` shows `mapping.scan.cooldown`. Any other error shows the fixed generic text.
- CVE list and per-CVE view: a column "Found by" shows the scanner count and names (`cves.scanners.count`: "{count, plural, one {1 scanner} other {# scanners}}", and the names joined by ", "), with a filter by scanner. A finding from one scanner shows "1 scanner" and its name. The per-CVE tag table adds the scanner names per tag.
- Sync jobs page: the `scanner_scan` and `scanner_restore` kinds show their scanner name and the fixed notes ([integrations.md](integrations.md)).
- Catalog keys (all in `frontend/src/i18n/en.json`, parity kept; Decided 2026-11-07, user, #224, English text delegated):

  | Key | English text |
  | --- | --- |
  | `mapping.scan.title` | Scans |
  | `mapping.scan.button` | Scan |
  | `mapping.scan.chooseScanner` | Choose a scanner |
  | `mapping.scan.start` | Start scan |
  | `mapping.scan.notScanned` | Not scanned |
  | `mapping.scan.noScannerAccess` | HarborGate cannot list the Harbor scanners. Grant the robot account Scanner Read and Scanner Create to choose one. The scan uses the project's current scanner. |
  | `mapping.scan.queued` | Scan queued |
  | `mapping.scan.state.queued` | Queued |
  | `mapping.scan.state.running` | Running |
  | `mapping.scan.state.waiting` | Waiting for the report |
  | `mapping.scan.state.ok` | Done |
  | `mapping.scan.state.failed` | Failed |
  | `mapping.scan.switchActive` | The Harbor project scanner is set to {scanner} for a scan. It is restored when the scan ends. |
  | `mapping.scan.restorePending` | Waiting to restore the Harbor project scanner. |
  | `mapping.scan.restoreFailed` | The Harbor project scanner could not be restored. Check the Sync jobs page. |
  | `mapping.scan.alreadyRunning` | A scan with this scanner is already in progress. |
  | `mapping.scan.restoreWaiting` | The Harbor project scanner is waiting to be restored. Try again when it has been. |
  | `mapping.scan.cooldown` | A scan was started a moment ago. Try again in a few minutes. |
  | `cves.scanners.count` | {count, plural, one {1 scanner} other {# scanners}} |
  | `cves.scanners.foundBy` | Found by |
  | `cves.scanner.unknown` | Unknown scanner |
  | `cves.scanner.filter` | Scanner |
  | `sync.note.scannerForbidden` | Harbor refused to switch the project scanner. Grant the robot account Scanner Read and Scanner Create. |
  | `sync.note.scannerGone` | The scanner is no longer in Harbor. |
  | `sync.note.scannerFailed` | The scanner failed the scan. |
  | `sync.note.restoreFailed` | The Harbor project scanner could not be restored. |
  | `sync.note.previousScannerGone` | The previous scanner is no longer in Harbor. |
  | `sync.note.scannerChangedElsewhere` | The project scanner was changed by someone else, so it was left as it is. |
  | `sync.note.scannerUnmatched` | The scanner is not recognised. |

  `sync.note.scanForbidden` is existing ([integrations.md](integrations.md)). The Sync jobs page and the mapping card show the same text for the same note.

## Settings rows (decided)

- Stacked layout: label, then optional help text, then the control, in one column.
- Do not use the Astraya 60/40 two-column grid for HarborGate forms.
- Multi-field forms (mappings, credentials) use the same stacked pattern.

## CVE list control bar (decided)

Decided 2026-11-08. Source: user, issue #257, decisions 1 to 13 and the design approval (Lavish mockup, approved 2026-11-08). It supersedes #256 and replaces the earlier multi-row filter header (separate exact-match inputs for package, project, repository and tag, and the filter chips).

- Layout, top to bottom, in one card under the page title:
  1. One search field, full width, with an inline Clear button that empties it. It matches the CVE id, the package, the Harbor project and the Harbor repository as a case-insensitive substring (a `LIKE %q%` match). `%` and `_` in the text are literal characters, never wildcards. The URL and the request update 300 ms after the last keystroke.
  2. Three pill groups on one wrapping row: Severity (CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN), Status (Open, Fixed, Accepted) and GitHub issue (Has issue, No issue). Severity and Status are multi-select. Has issue and No issue are one group and exclusive: pressing the pressed one clears it. A pill is an outline when off and filled with its tone when on, and carries a dot that is hollow when off and solid when on, so state is not colour alone. Each is a button with `aria-pressed`, in a group with an accessible name. Fix available (Decided 2026-11-09, user, issue #265, decisions 1 to 4): a fourth pill group, labelled "Fix available", sits after the GitHub issue group with two pills, Fix available and No fix. Like Severity and Status it is multi-select, with the same pill style, `aria-pressed` and accessible group name. Both pills on, or both off, filter nothing. The rule is the Fixed in column's value (decision 1): a CVE is Fix available exactly when its Fixed in column shows a version, and No fix exactly when it shows Unknown (decision 3), so the filter and the column always agree and Fix available never lists an Unknown row. With several scanners (#224, decision 2) the column value is the merged one, the first scanner in the merged order that reports a fixed version, so a CVE is Fix available when at least one scanner reports a fixed version.
  3. One row of four comboboxes: Project, Repository, Tag, Mapping. Each takes one choice. Each is searchable and keyboard operable (ARIA combobox: Down opens, Up and Down move, Enter selects, Escape closes), and its first option clears it ("All projects", "All repositories", "All tags", "All mappings"). Mapping is last and is the only scope control: there is no My Mappings / All Mappings toggle on this page. For an admin, All mappings covers every tenant's mappings (the page sends `scope=all`); for anyone else it covers their own. Selecting a project narrows the Repository options to that project's repositories, and a chosen repository that no longer fits is cleared. The Tag options are the tracked tags of the mapping in view (`GET /mappings/:id/tags`) when one Mapping is chosen; with All mappings the Tag combobox accepts a typed tag name.
- Combine rule (decisions 7 and 8): values within one group are OR, and groups are AND. Status: Open shows only open CVEs without an active acceptance; Accepted shows only CVEs with an active acceptance; Fixed shows fixed CVEs. Open and Accepted together show both sets. With no Status pill on, the page applies Open (the last Status pill stays on). With no Severity pill on, every severity shows. Project, Repository, Tag and Mapping are AND-ed with the groups.
- URL sync: every control is in the query string and is restored on load: `q`, `severity` (comma list), `status` (comma list, lowercase), `has_issue` (`true` or `false`), `fix` (comma list of `available` and `none`; Decided 2026-11-09, user, #265), `project`, `repository`, `tag`, `mapping`, plus `page` and `order`. A default is left out. Old links keep working (decision 9): `accepted=true` selects the Accepted pill, `accepted=false` with `status=open` selects Open, and `harbor_project`, `harbor_repository` and `mapping_id` are read as `project`, `repository` and `mapping`. The new name wins when both are present. Dashboard cards link here: the Accepted card opens `accepted=true` and the Issues card opens `has_issue=true`.
- Table columns: CVE, Severity, Status, Package, Fixed in, Mapping, Tags (n of m), Issue, Action. Tags n of m (decisions 5 and 11): n is the number of image tags of the mapped repository that currently contain the CVE (`open_tags`), and m is every tag the mapping tracks (`tracked_tags`), as the CVE view counts it. A tag removed from Harbor counts until its data is removed (#249). The table scrolls horizontally when it is wider than the card.
- Issue and Action columns (decisions 10 and 12): the Issue column shows `#number` linking to the issue, with the text `closed` beside it when the issue is closed, or `None` when there is none. The Action column does not change with the filters. A row with an issue (open or closed) shows View issue, a link to the issue; it never offers Create issue. A row without an issue, open on at least one tag and owned by the signed-in user, shows Create issue: disabled while an active acceptance exists, otherwise it opens a confirmation dialog that names the GitHub repository (`owner/repo`) and the CVE (with its package and severity) and states that nothing is created until Confirm. Confirm calls `POST /cves/:id/issue`; Cancel, Escape and the close button create nothing. This confirmation applies to every severity on the list; the per-CVE view keeps its own rule.
- Layout (decision 13): at 1280px the bar and the first table rows are visible without scrolling. Below 1024px the pill groups stack and wrap, the four comboboxes stack one per row, and the table keeps its horizontal scroll.
- Empty and error states are unchanged (`cves.empty`, the shared error message). A failed issue creation shows the server message in an alert above the table.
- Catalog keys (all in `frontend/src/i18n/en.json`, English only): `cves.filter.group`, `cves.filter.search`, `cves.filter.searchPlaceholder`, `cves.filter.clear`, `cves.filter.severity`, `cves.filter.status`, `cves.filter.issue`, `cves.filter.hasIssue`, `cves.filter.noIssue`, `cves.filter.fix`, `cves.filter.fixAvailable`, `cves.filter.noFix`, `cves.filter.project`, `cves.filter.repository`, `cves.filter.tag`, `cves.filter.mapping`, `cves.filter.allProjects`, `cves.filter.allRepositories`, `cves.filter.allTags`, `cves.filter.allMappings`, `cves.combo.noMatch`, `cves.combo.useValue`, `cves.col.tags`, `cves.tags`, `cves.action.viewIssue`, `cves.action.createIssue`, `cves.createDialog.title`, `cves.createDialog.body`, `cves.createDialog.repo`, `cves.createDialog.cve`, `cves.createDialog.package`, `cves.createDialog.confirm`. Keys of the removed controls (chips, exact-match inputs) are deleted.

## Per-CVE view (decided)

- A detail page for one CVE, linkable by URL.
- Header: CVE id, severity pill, status pill, package, first seen date, link to the GitHub issue, and an "Accept risk" action.
- Decided (2026-11-03): the manual-issue button sits in this header, next to the GitHub issue link. It calls `POST /api/v1/cves/{id}/issue`.
- Below the header: a table with one row per tracked tag that reports this CVE (up to 10). Columns: tag, status, last scan date, fixed-in version when known.
- Decided (2026-11-07, user, #196, decisions 21 and 22): this table is where the rows of older tags stay visible. A row for a tag of the newest scanned digest has no marker. A row for any other tag shows the plain text `cves.detail.olderTag`, not a badge. The header status is the status in the newest-digest view, so a CVE that only older tags report shows `fixed`. In that case the CVE row in the header carries the inline text `cves.detail.olderTagsOnly` with the names of the older tags that report it (the `tags[]` entries with `newest_digest` false and status `open`). It is plain inline text: no badge and no separate panel (Approved by the user 2026-11-07, issue #196, decision 24). The Accept risk action and the manual-issue button follow the rules they already have ([api.md](api.md), CVEs). The page is reached by its URL; the CVE list does not link to it.
- Catalog keys for this change (Decided 2026-11-07, English text delegated, #196; parity kept in `frontend/src/i18n/en.json`):

  | Key | English text |
  | --- | --- |
  | `cves.detail.olderTag` | Older tag, not counted |
  | `cves.detail.olderTagsOnly` | Open on older tags only: {tags} |

- Design approval (2026-11-07, user, #196, decision 24): the older-tag notice is approved as inline text in the CVE row, for example "open on older tags only" with the tag names. No badge and no separate panel. The design needs no further approval.

## Admin (decided)

- One Admin entry in the rail, shown to admins only.
- Five tabs:
  - Jobs: housekeeping and sync jobs, with counts and errors. Includes cleanup and retention runs and polling runs.
  - Failed syncs: error message and a retry action. Decided (2026-11-08, user, #243, decisions 1 to 4): the tab also has the "Purge failed jobs" action below, always with `scope=all`.
  - Audit log: admin actions such as user create and delete, role changes, OIDC config changes, credential rotation.
  - Health: Harbor and GitHub reachability, token expiry, missing scopes, robot account expiry date with a warning 14 days before it lapses (Decided 2026-11-03, see [integrations.md](integrations.md)). Decided (2026-11-03, delegated): it also shows the code scanning state of each GitHub target (ready, no analysis yet, or unavailable), and the client IP HarborGate sees for the admin's own request, with its source ([api.md](api.md), "Health").
  - Settings (OIDC, Users, Alerts, Backup and restore): sections for the OIDC, Users, Alerts, and Backup and restore screens.
- Settings > GitHub (Decided 2026-11-06, user, #184; added 2026-11-07): an admin sets the instance GitHub API base URL and web URL here. Two optional text fields, a save button, and a discard button; empty means github.com. An invalid value shows the catalog text `settings.github_url_invalid`. The stored values are shown in the fields. Rules: [integrations.md](integrations.md), "GitHub base URL". The design is minimal (the existing Settings card, field, and button patterns); no new visual design was approved for it, so the user may ask for changes.
- Decided (2026-11-03): Settings is the fifth tab, after Health. It holds the OIDC, Users, Alerts, and Backup and restore screens. Admin stays a single rail entry.
- Settings > OIDC (decided 2026-11-03): OIDC settings and the toggle that restricts regular users to OIDC are managed here, stored encrypted (client secret AES-256-GCM), and every change is audited as `oidc.config_change`. Admin break-glass is always available. The "OIDC only for regular users" toggle restricts regular users to OIDC sign-in (Decided 2026-11-03, see [security.md](security.md)). See [security.md](security.md).
- Settings > Users (decided 2026-11-03): an admin can create a local user (username, email, password, role; the password must be at least 15 characters and at most 64), change a user's role, and delete a user. Decided (2026-11-03): role changes are for local users only. An OIDC user's role comes from the group claim and is shown read-only. OIDC users appear in the list after their first login. They are not created from this screen.
- Setup page (first-run, not a Settings screen): shown only while no users exist. Its design was approved on 2026-11-03 (`Setup.dc.html`).
- Design before build: the screen designs for the four Settings sections and the Setup page were approved on 2026-11-03 (see "Screen designs").

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
