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
  - Mappings has a list page with the columns Harbor source, GitHub target, Issues, Open CVEs, Last sync, and Actions. Changed (2026-11-05, user, #129): Open CVEs shows every severity with a breakdown (CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN), not only CRITICAL and HIGH. The changed column needs design approval before it is built.
  - Admins see a "My mappings / All mappings" toggle on Dashboard, Mappings, and Sync jobs (removed from CVEs 2026-11-08, user, #257, decision 2; the CVE list scopes by its Mapping combobox, see "CVE list control bar (#257)", open question 1). "All mappings" sends `scope=all`. Regular users do not see it.
  - Admin Settings shows its four sections as a row of pill links under the tabs. Each section has its own URL.
  - Alert channels: saved config is never returned, so editing a channel means entering its whole config again. The edit form says so.
  - Per-CVE view: "Create issue" shows for a CVE of any severity that is open on at least one tag (Changed 2026-11-05, user, #129; until then CRITICAL and HIGH only), and is disabled while an open issue exists or an active acceptance exists. When `open_severity` is LOW or UNKNOWN, the button first asks for confirmation in a dialog; CRITICAL and HIGH stay one click (MEDIUM too, see [integrations.md](integrations.md)). A GitHub rate limit shows one clear message and is not retried in a loop. The changed button needs design approval before it is built.
  - CVE list (Decided 2026-11-05, user, #129): the default view shows every severity. Changed (2026-11-08, user, issue #257, decisions 1 to 13): the filter header (separate severity, status, package, tag, project, repository and search controls) is replaced by the single-view control bar in "CVE list control bar (#257)" below, and its parameters are in [api.md](api.md), CVEs, "CVE list filters". The new bar needs the mockup approval in that section before it is built. CVE status uses an OPEN pill (neutral) and an ACCEPTED pill (accent). Decided (2026-11-07, user, #196, decisions 21 and 22): the list shows the CVEs of the newest scanned digest of each mapping only. A CVE that is open only on an older tag is not listed. The `tag` filter offers the newest-digest tags only. Rules: [cve-lifecycle.md](cve-lifecycle.md), "Tracking per tag".
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
- Decided (2026-11-08, user, #247): the summary shows an accepted-CVE card between the Fixed card and the Issues card. It shows the number of CVEs with an active acceptance in the same scope as the other counts (newest-digest view; the admin `scope=all` toggle applies). Accepted is its own count and is not mixed into open; the open count is unchanged. The card changes no acceptance. Changed (2026-11-08, user, #257, decision 1): it is a link to the CVE list, see "CVE list control bar (#257)", "Dashboard card links". Its text is catalog keys. The two astraya Medium acceptances stay as they are.
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

## CVE list control bar (#257)

Decided (2026-11-08, user, issue #257, decisions 1 to 13): the filter header of the CVE list (`/cves`) becomes one control bar. It replaces the separate text inputs (package, project, repository, tag, search), the separate severity, status and accepted controls, the active-filter chip row, and the My mappings / All mappings toggle on this page. #256 is superseded and its Has issue filter and card links are carried here (decision 1). What the list holds (newest scanned digest of each mapping) is unchanged: [cve-lifecycle.md](cve-lifecycle.md), "Tracking per tag". The query parameters are in [api.md](api.md), CVEs, "CVE list filters".

- Build gate (decision 6): a Lavish mockup of this bar is reviewed first. The build does not start until the user approves the mockup, recorded as a comment on #257. `designs/Cves.dc.html` shows the old header and is superseded for the header when the mockup is approved.
- Default view (carried over from the current page; Decided (2026-11-08, spec author, #257)): with no URL parameters, the Open pill is lit, no severity is lit (every severity is listed), and nothing else is set.

### Layout

Top to bottom, inside one bar above the table:

1. Search row: the search field, full width.
2. Pill row: the Severity group, the Status group, and the GitHub issue group, each with a visible group label.
3. Combobox row: Project, Repository, Tag, Mapping, on one row, each with a visible label.

- Search field: one text field with the accessible name `cves.filter.search`. The server matches the text against the CVE id, the package, the Harbor project and the Harbor repository, with a case-insensitive `LIKE %q%` in which `%`, `_` and the escape character in the user's text are escaped, so they match themselves ([api.md](api.md), `q`). The text is sent to the server as typed. An inline Clear button (`cves.filter.clearSearch`) shows inside the field only while it holds text; it empties the field, removes `q` from the URL, and returns focus to the field. The field reports its value 300 ms after the last keystroke and replaces the history entry instead of adding one (both are the current page's behaviour, kept).
- Severity pills: CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN. Multi-select. With no pill lit, no severity filter applies (every severity is listed, as decided 2026-11-05, #129). The pills use the severity colours and text labels of "Status pills".
- Status pills: Open, Fixed, Accepted. Multi-select (decision 4). Open lists only CVEs that are open and have no active acceptance. Accepted lists only CVEs with an active acceptance. Fixed lists CVEs whose status is fixed. Lighting two pills shows both sets, so Open and Accepted together show the open unaccepted CVEs and the accepted CVEs (decision 7). At least one status pill stays lit: the last lit pill cannot be turned off (the current page's rule, kept; Decided (2026-11-08, spec author, #257); reason: an empty status group has no meaning, and lighting all three shows every CVE).
- GitHub issue group: two pills, Has issue and No issue (decision 8: one group). At most one is lit: pressing the unlit pill lights it and unlights the other, and pressing the lit pill clears the group (Decided (2026-11-08, spec author, #257); reason: the API takes one value, and "both" would be the same as "neither"). Has issue includes a CVE whose issue is closed.
- Comboboxes: Project, Repository, Tag, Mapping. Each takes one choice (decision 3 for Tag and Mapping; Project and Repository follow the same rule, Decided (2026-11-08, spec author, #257)) and is searchable (the text typed in the combobox filters its option list; this is the issue's "Searchable"). Each has an empty first option that clears it: "All projects", "All repositories", "All tags", and for Mapping "All mappings".
  - Mapping is the only scope control (decision 2). Its first option is "All mappings". Its options are the mappings in the caller's scope, named `<harbor project>/<harbor repository>` (the name the page uses today).
  - Selecting a project narrows the Repository options to the repositories of the mappings in that project. If the chosen repository is not in the new project, Repository is cleared. No other combobox narrows another (Decided (2026-11-08, spec author, #257); reason: only the project-to-repository rule is stated).
  - Project and Repository options come from the mapping list the page already loads (`GET /api/v1/mappings`, `page_size` 200, the existing lookup). The Tag options: see "Open questions".
- Combine rule (decision 8): inside one group the lit values are OR; between groups they are AND. The groups are: search, severity, status, GitHub issue, project, repository, tag, mapping. Severity and Status narrow each other. Example: `severity=CRITICAL,HIGH&status=open,accepted` is (CRITICAL or HIGH) and (open-unaccepted or accepted).
- Active filters are visible in the controls themselves, so there is no chip row. Exception: a link with the exact `package` parameter (see URL state) shows one removable chip `cves.filter.chip.package`, because no control carries it. A "Clear all" button (`cves.filter.clearAll`, kept) shows when any parameter differs from the default view; it removes every filter parameter and keeps `scope`.

### Table

- Columns, in order: CVE, Severity, Status, Package, Fixed in, Mapping, Tags, Action. The separate Issue column is removed; the issue number moves into the Action column (Decided (2026-11-08, spec author, #257); reason: the Action column now shows the issue).
- Status cell: the OPEN or FIXED pill, and the ACCEPTED pill beside it when the CVE has an active acceptance (unchanged).
- TAGS column (decision 5, decision 11): shows `n of m` (`cves.tags`, "{open} of {tracked}"). `n` is the CVE's `open_tags`: the image tags of the mapped repository that currently contain the CVE as open. `m` is `tracked_tags`: all tags the mapping tracks, as the CVE view counts them today (the mapping's newest-digest tags, at most 10, [api.md](api.md), CVEs). A tag removed from Harbor counts in `m` until its data is removed (#249). Both fields already exist in `CveSummary` ([api.md](api.md)); nothing is added. Each cell has a text alternative (`cves.tags.aria`).
- Action column, one control per row, and it does not change with the filters:
  - The CVE has a GitHub issue (`github_issue_number` is set): a View issue link. It shows the issue number (`#12`), opens `github_issue_url` in a new tab with `rel="noopener noreferrer"`, and only when the URL passes the existing https check (`safeUrl.ts`); otherwise the number shows as plain text. When `github_issue_status` is `closed`, the text `cves.issue.closed` shows beside the number, and the row does not offer Create issue (decision 12). The link's accessible name is `cves.action.viewIssueNamed`.
  - The CVE has no issue: a Create issue button. Pressing it opens the confirmation dialog below. It never creates an issue on the press itself (decision 10), for any severity.
  - Create issue is disabled, with its reason as visible text tied to the button by `aria-describedby`, when the API would refuse it (Decided (2026-11-08, spec author, #257); reason: [api.md](api.md) refuses these cases, and the current page hides the button without saying why): the CVE has an active acceptance (`409`, `cves.action.createIssue.accepted`); `open_severity` is null, so no tag has it open (`422`, `cves.action.createIssue.fixed`); or the caller does not own the mapping, as for an admin reading another user's mapping (`cves.action.createIssue.notOwner`).
- Create issue confirmation dialog (decision 10; Radix Dialog, modal, built from the existing `ConfirmDialog`):
  - Title `cves.confirm.title` with the CVE id. Body `cves.confirm.body` names the CVE and the GitHub repository, as `<github_owner>/<github_repo>` of the row's mapping (from the mapping lookup the page already holds). For a CVE whose `open_severity` is LOW or UNKNOWN, the body adds `cves.confirm.lowSeverity` (the existing rule that these are never created automatically).
  - Two buttons: Cancel (`cves.confirm.cancel`) and Create issue (`cves.confirm.create`). Escape and Cancel close it with no request.
  - Only the confirm button calls `POST /api/v1/cves/{id}/issue` (the existing route, [api.md](api.md); `{id}` is `<mapping_id>:<cve_id>`, URL-encoded; mapping owner; CSRF header like every state-changing route). While it runs, both buttons are disabled.
  - Success (`201`): the dialog closes, the list is refetched, and the row shows View issue. Failure: the dialog stays open and shows the route's fixed message, or `cves.issue.failed` when none. A GitHub rate limit shows its one message and is not retried (the existing rule).
  - This replaces, for the list, the rule that CRITICAL, HIGH and MEDIUM create in one click. The Per-CVE view button is unchanged.

### URL state

All filter state lives in the URL and is read on load. The page and the API use the same names. Defaults are left out of the URL.

| Parameter | Value | Default (omitted) |
| --- | --- | --- |
| `q` | search text | empty |
| `severity` | comma list of `CRITICAL,HIGH,MEDIUM,LOW,UNKNOWN`, canonical order | none |
| `status` | comma list of `open,fixed,accepted`, canonical order (legacy `all` = all three) | `open` |
| `has_issue` | `true` or `false` | none |
| `project` | Harbor project, exact | none |
| `repository` | Harbor repository, exact | none |
| `tag` | image tag, exact | none |
| `mapping` | mapping id | none |
| `scope` | `all` (admin only), kept as given; the page has no control for it | none |
| `package` | exact package (old links only) | none |
| `page`, `order` | unchanged | page 1, `desc` |

- Any filter change resets `page`. The back button returns to the previous page (the dashboard, when the user came from a card). Changing the search text replaces the entry; other changes add one.
- Old links keep working (decision 9, and the same for the other renamed names; Decided (2026-11-08, spec author, #257) for the renames). On load the page reads the old names, sets the matching controls, and rewrites the URL to the new names with `replace`, so back still returns to the previous page:

  | Old | New |
  | --- | --- |
  | `accepted=true`, no `status` | `status=accepted` (Accepted pill only) |
  | `accepted=false` with `status=open` | `status=open` (Open pill) |
  | `accepted=false`, no `status` | `status=open,fixed` (Open and Fixed pills; the old meaning, every CVE that is not accepted) |
  | `accepted` with any other `status` | `status` wins and `accepted` is dropped (a pill group cannot express the AND) |
  | `harbor_project`, `harbor_repository`, `mapping_id` | `project`, `repository`, `mapping`; if both an old and a new name are present, the new one wins |

- Unknown values (a severity that is not one of the five, a bad `has_issue`) are dropped on load. A `mapping` that is not among the caller's mappings (the API answers `404` for it) shows "All mappings": the page does not send it and rewrites the URL without it.

### Narrow screens

Decided (2026-11-08, user, #257, decision 13): below 1024px (Tailwind's default `lg` breakpoint, 64rem, [Tailwind docs, Responsive design](https://tailwindcss.com/docs/responsive-design)) the pills wrap onto further lines and the four comboboxes stack one per row. The table keeps scrolling horizontally inside `TableScroll`, as today. At 1024px and above the layout above applies.

### Above the fold at 1280px

At a window 1280px wide, the whole bar (three rows) and the table header with the first data row are fully visible without scrolling. The issue gives the width only; the height is the height of the reviewer's browser window, and the check passes when the sticky header, the bar, the table header and the first row all fit (Decided (2026-11-08, spec author, #257); reason: no height is stated, and inventing one would be a magic number). The bar must not wrap at 1280px: that is why the pills share one row and the four comboboxes share one.

### Keyboard and accessibility

- Every control is operable by keyboard alone, with the visible 2px accent focus ring ("Visual direction").
- Each pill group is a labelled group (`role="group"` with the group label as its name). Each pill is a toggle button with `aria-pressed`, operated with Space and Enter. Tab moves between pills.
- Each combobox follows the WAI-ARIA Authoring Practices combobox pattern (https://www.w3.org/WAI/ARIA/apg/patterns/combobox/, read 2026-11-08): the input has `role="combobox"` with `aria-expanded`, `aria-controls` and `aria-activedescendant`; the popup is a `listbox` of `option`s; Down Arrow opens the popup and moves into it, Enter picks the active option, Escape closes the popup without changing the value. The accessible name is the visible label. The project does not ship a combobox part (`@radix-ui/react-select` is not searchable); the build may use one new part or a new dependency, and this spec does not choose.
- The Create issue dialog traps focus, restores it to the Create issue button on close, and closes on Escape (Radix Dialog).
- A result change is announced: a visually hidden `role="status"` line gives the result count (`cves.results`), so a screen reader hears the effect of a filter.
- Every accessible name and visible string is a catalog key.

### Catalog keys

All in `frontend/src/i18n/en.json`, parity kept. English text Decided (2026-11-08, spec author, #257). Existing keys that stay: `cves.filter.group`, `cves.filter.search`, `cves.filter.severity`, `cves.filter.status`, `cves.filter.clearAll`, `cves.filter.chip.package`, `cves.filter.remove`, `cves.status.open|fixed|accepted`, `cves.tags`, `cves.issue.closed`, `cves.issue.failed`, `cves.action.createIssue`, `cves.confirm.title`, `cves.confirm.create`, `cves.col.*` (without `cves.col.issue`). New or changed:

| Key | English text |
| --- | --- |
| `cves.filter.searchPlaceholder` | CVE id, package, project or repository |
| `cves.filter.clearSearch` | Clear search |
| `cves.filter.issue` | GitHub issue |
| `cves.filter.hasIssue` | Has issue |
| `cves.filter.noIssue` | No issue |
| `cves.filter.project` | Project |
| `cves.filter.repository` | Repository |
| `cves.filter.tag` | Tag |
| `cves.filter.mapping` | Mapping |
| `cves.filter.allProjects` | All projects |
| `cves.filter.allRepositories` | All repositories |
| `cves.filter.allTags` | All tags |
| `cves.filter.allMappings` | All mappings |
| `cves.filter.comboHint` | Type to filter |
| `cves.filter.comboEmpty` | No matches |
| `cves.results` | {count, plural, one {1 CVE} other {# CVEs}} |
| `cves.tags.aria` | Open on {open} of {tracked} tracked tags |
| `cves.action.viewIssue` | View issue |
| `cves.action.viewIssueNamed` | View issue #{number} on GitHub (opens in a new tab) |
| `cves.action.createIssue.accepted` | Accepted CVEs do not get an issue. |
| `cves.action.createIssue.fixed` | No tag has this CVE open. |
| `cves.action.createIssue.notOwner` | Only the mapping owner can create an issue. |
| `cves.confirm.body` | This creates a GitHub issue for {cve} in {repository}. |
| `cves.confirm.lowSeverity` | This CVE is {severity} at its highest open severity. A GitHub issue is not created for it automatically. |
| `cves.confirm.cancel` | Cancel |
| `dashboard.link.accepted` | Show accepted CVEs |
| `dashboard.link.issues` | Show CVEs with a GitHub issue |

Keys no longer used are removed in the same change so parity holds: `cves.filter.package`, `cves.filter.packagePlaceholder`, `cves.filter.tagPlaceholder`, `cves.filter.projectPlaceholder`, `cves.filter.repositoryPlaceholder`, `cves.filter.active`, `cves.filter.allSeverities`, `cves.filter.allStatuses`, `cves.filter.chip.severity|status|tag|harbor_project|harbor_repository|q|mapping_id`, `cves.col.issue`, `cves.issue.none`, `cves.issue.notEligible`, and `mappings.filter.*` if no other page uses them.

### Dashboard card links

Decided (2026-11-08, user, #257, decision 1, carrying #256): the Accepted card and the Issues card on the Dashboard are links to the CVE list. They keep the dashboard's scope: an admin's `scope=all` is added, as for the other cards. Each is a keyboard-reachable link with an accessible name from a catalog key (`dashboard.link.accepted`, `dashboard.link.issues`) and changes no acceptance or issue. Browser back returns to the Dashboard.

- Accepted card: `/cves?accepted=true`. On load the page maps it to `status=accepted` (table above), so only the Accepted pill is lit.
- Issues card: `/cves?has_issue=true`. The status group keeps its default, so Open is lit and the list shows CVEs with an issue that are open and unaccepted. Lighting other status pills widens it by the combine rule.
- This changes the line "The card is display only" in "Dashboard (decided)": the Accepted card is now a link, and still display-only for acceptance.

### Open questions

Each is OPEN: the user's decisions do not cover it, and the spec does not decide it.

1. OPEN: Scope for admins. The My mappings / All mappings toggle is removed from the CVE list (decision 2), and `scope=all` is today set only by that toggle (the dashboard cards still send it). How does an admin choose between their own mappings and every user's mappings on the CVE list? Until this is answered, the page keeps `scope=all` from the URL, lists the Mapping options of that scope, and has no control to set it.
2. OPEN: Tag options. The Tag combobox must offer the newest-digest tags ([cve-lifecycle.md](cve-lifecycle.md)) across the mappings in view. No route returns that across mappings: `GET /mappings/:id/tags` is per mapping. Which source feeds the Tag options: a new route that returns the distinct newest-digest tags of the mappings in the caller's scope, or a per-mapping tag list that appears only after a mapping is chosen?
3. OPEN: Dashboard card counts versus the list. The Issues card counts open GitHub issues (`open_issues`, one per issue row), but the list shows one row per CVE and mapping, Has issue also includes closed issues, and the default Open pill narrows it further. The Accepted card counts accepted CVEs that are open on the newest digest, but the Accepted pill also lists accepted CVEs that are fixed. Is a card count that differs from the number of rows after the click acceptable, or must the link also set filters so the two match? The #256 criterion "the count on the card matches the number of rows the filter shows" cannot hold for the Issues card without that.
4. OPEN: Scanner filter and Found-by column. The "Tag scans" section above says the CVE list has a Found by column and a filter by scanner (#224). The current page has neither, and the control bar in the decisions has no Scanner control. Does the control bar carry a Scanner control and the Found by column, or are they dropped from the list? Until answered, the `scanner` API parameter stays and the page has no control for it.

### Acceptance criteria and checks

The 14 checkboxes of the #257 body (the work request said 10; the body has 14), none ticked here. "Testable" means the spec fixes the expected result.

| # | Criterion (short) | Testable from this spec | Check |
| --- | --- | --- | --- |
| 1 | Design approved before implementation, recorded on the issue | Process, not a test | A comment on #257 with the user's approval of the Lavish mockup exists before the first frontend commit (decision 6). |
| 2 | `specs/frontend.md` records layout, pills, comboboxes, action column, URL state, dated with source | Yes | This section. Read check: each of the five is present and carries the date and source. |
| 3 | `specs/api.md` lists `q`, `severity`, `status`, `has_issue`, `project`, `repository`, `tag`, `mapping` | Yes | [api.md](api.md), "CVE list filters". Read check. |
| 4 | Search matches CVE id, package, project, repository; escapes wildcards | Yes | API test: `q` matches by each of the four fields; `q=%` and `q=_` match only a field holding a literal `%` or `_`, not everything; `q=\` does not error; `total` equals the item count. |
| 5 | Severity and status multi-select; groups combine as stated | Yes | API test: `severity=CRITICAL,HIGH`; `status=open,accepted`; `status=open` excludes an accepted open CVE; groups AND (`severity=HIGH&status=accepted`). UI test: lighting two pills sends the comma list. |
| 6 | GitHub issue toggle isolates Has issue or No issue | Yes | API test: `has_issue=true` returns only CVEs with an issue (open or closed), `false` only those without; a bad value is `400`. UI test: lighting one pill unlights the other. |
| 7 | Selecting a project narrows the repository combobox | Yes | UI test with mappings in two projects: after choosing project A, Repository lists only A's repositories; a repository outside A is cleared. |
| 8 | Action column: View issue with an issue, Create issue otherwise | Yes | UI test: open issue shows View issue with the number; closed issue shows View issue with `cves.issue.closed` and no Create issue; no issue shows Create issue; Create issue opens the dialog naming the GitHub repository and the CVE, and calls `POST /cves/{id}/issue` only on confirm (Cancel and Escape send nothing). |
| 9 | Filter state in the URL, restored on load | Yes | UI test: set filters, reload, same controls and rows; old links (`accepted=true`, `accepted=false&status=open`, `harbor_project`, `harbor_repository`, `mapping_id`) land on the matching controls and rewrite the URL; the dashboard card links land on the right view. |
| 10 | At 1280px the bar and first rows are visible without scrolling | Yes | Browser check at width 1280 (see "Above the fold at 1280px"); and below 1024px the pills wrap, comboboxes stack, the table scrolls sideways. |
| 11 | Pills and comboboxes keyboard operable, accessible names from catalog keys | Yes | UI test: every control reached by Tab and operated by Space, Enter, arrows, Escape; `getByRole` queries by the catalog names succeed. |
| 12 | Every user-visible string is a catalog key, parity kept | Yes | The existing parity test for `en.json`; no literal string in the changed components. |
| 13 | Gates exit 0: `npm test`, `npm run lint`, `npm run build`, `oxlint` | Process | Run the four commands; each exits 0. Backend changes also need `cargo test`. |
| 14 | Browser check at 1280px: each combination returns the expected rows and the URL reproduces the view | Yes | Browser check against real data: for each group alone and in pairs, row set equals the API's for the same query string; reload reproduces it. |

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
