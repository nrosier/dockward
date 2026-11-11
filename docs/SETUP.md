# Dockward Setup Guide

This guide explains how an operator configures Dockward, its image registries, and GitHub so that scan results flow to GitHub Code Scanning and, optionally, to GitHub Issues.

## 1. Overview

Dockward is a local-first security relay. It discovers the images you configure in container registries, pulls them into local OCI layouts (no Docker daemon is needed), and scans them with pinned Trivy and Grype binaries that ship in the image. It converts the results to SARIF 2.1.0, uploads the SARIF to the GitHub code-scanning API for the repository you map to each image, and can open GitHub issues for `CRITICAL` and `HIGH` findings.

Discovery runs once an hour for each configured repository. A new or moved tag queues one pull, then a scan, then a publish. A daily job refreshes the scanner vulnerability databases and rescans stored images when a database is newer.

The flow is:

```text
Hub (ghcr.io, docker.io, or custom) -> discover (hourly) -> pull to OCI layout
  -> Trivy and Grype scan -> SARIF 2.1.0 conversion -> GitHub code-scanning upload
                                                    -> optional issues
```

## 2. Before You Start

### Prerequisites

- **Docker Engine 25.0 or later.** On Engine 25.0 and later, health checks run every `start_interval` (5 seconds by default) during the healthcheck's `start_period`, so Traefik routes to Dockward within seconds of start. On an older Engine the first check runs only after the 30-second `interval`, and Traefik does not route to Dockward until then (see [specs/deployment.md](../specs/deployment.md), Health).
- **No shell in the container.** The image is built `FROM scratch`: it holds the Dockward binary, the pinned scanner binaries, the CA bundle, `/data` and `/tmp`, with no shell or package manager. The health check runs `dockward healthcheck` (a `GET /healthz` to `127.0.0.1:8080` that exits 0 on `200`). To run it by hand, use `docker exec <container> /usr/local/bin/dockward healthcheck`. `docker exec <container> sh` does not work. `restore` and `rotate-key` run through `docker compose run --rm dockward <command>`, because they are subcommands of the same binary.
- **A public HTTPS hostname** for Dockward. You set it as `DOCKWARD_PUBLIC_URL` below.
- **Your reverse proxy addresses**, if Traefik or another proxy sits in front of Dockward. You set them as `DOCKWARD_TRUSTED_PROXIES` below.

### Encryption key

Dockward needs an encryption key in the environment variable `DOCKWARD_ENCRYPTION_KEY`. This is required.

- The value is the base64 encoding of exactly 32 random bytes. The app refuses to start if the value is missing or does not decode to 32 bytes.
- It encrypts stored credentials (registry passwords and tokens, GitHub tokens, the OIDC client secret, alert settings) with AES-256-GCM. Session, CSRF and backup keys are derived from it.
- If you lose the key, the stored credentials cannot be recovered. You must re-enter every credential.
- Store the key in a password manager or secrets store. Do not commit it to git or put it in an image.

To generate a random value, run this once and paste the output into your secrets store. The value shown here is only an example of the command, not a key to use:

```bash
openssl rand -base64 32
```

Set the result as `DOCKWARD_ENCRYPTION_KEY` in your deployment environment (for example, a `.env` file that is kept out of git).

### Data location

Dockward keeps its SQLite database at `<DOCKWARD_DATA_DIR>/dockward.db` (default `/data/dockward.db`). Scanner caches live in `<DOCKWARD_DATA_DIR>/scanner-cache`. Keep the data directory on a persistent volume.

Dockward 0.2 starts from a fresh database. It does not migrate a HarborGate database: if it finds an older database that holds the `repo_mappings` table, it refuses to start and reports the error. There is no import path from HarborGate.

### Public URL and trusted proxies

Set these in the same `.env` file. Both are described in [specs/deployment.md](../specs/deployment.md), Configuration.

- **`DOCKWARD_PUBLIC_URL`** (required). The external origin that users open, for example `https://dockward.example.com`. It must use `https://`. For local development only, `http://localhost` with any port is also accepted. Dockward builds the OIDC redirect URI and the login origin check from this value. It never reads the host from the request, so a wrong value breaks sign-in. Dockward refuses to start without it.
- **`DOCKWARD_TRUSTED_PROXIES`** (optional, default empty). A comma-separated list of CIDRs for the reverse proxies whose `X-Forwarded-For` header Dockward trusts. Write a single address as `/32` (IPv4) or `/128` (IPv6). Each entry must have no host bits set. With the default empty list, Dockward ignores `X-Forwarded-For`, so every visitor behind a proxy shares one client IP for rate limits. In the reference setup (Cloudflare tunnel, then Traefik), list Traefik's address on the `proxy` network and the address cloudflared connects to Traefik from.

The addresses differ per host, so follow [specs/deployment.md](../specs/deployment.md), "Client IP behind Cloudflare and Traefik", to find them and to set Traefik's `forwardedHeaders.trustedIPs`. Use the narrowest ranges that work. Trusting the whole `proxy` subnet lets any container on that network send its own `X-Forwarded-For`. After you start Dockward, check Admin > Health: it must show your public IP as the client IP, with source `x-forwarded-for`.

### Verify the image signature

Every published image is signed by the release workflow with keyless cosign. No key is needed: the signature is tied to the GitHub Actions identity of the workflow that built the image. Install [cosign](https://docs.sigstore.dev/cosign/system_config/installation/), then run this for the tag you pull (replace `<TAG>`):

```bash
cosign verify \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github.com/nrosier/dockward/\.github/workflows/docker\.yml@refs/(heads/main|tags/v[0-9].*)$' \
  ghcr.io/nrosier/dockward:<TAG>
```

A successful run prints the checks it made and a JSON record for the signature. Look for:

- **Issuer:** `https://token.actions.githubusercontent.com`, the GitHub Actions OIDC issuer.
- **Subject:** the signing identity, `https://github.com/nrosier/dockward/.github/workflows/docker.yml@refs/...`. It names the repository, the workflow path, and the ref (`refs/heads/main` or `refs/tags/v<version>`).
- **Rekor record:** the signature is recorded in the Rekor transparency log, and cosign confirms that record.

If the command fails, do not run the image.

## 3. Registries and Hubs

A **hub** is a container registry that Dockward reads from. Two hubs exist by default:

- `ghcr.io` (GitHub Container Registry)
- `docker.io` (Docker Hub)

An admin can add **custom hubs** for other registries. A custom hub is stored with its host and, optionally, a separate pull endpoint. Each hub host is unique.

### 3a. Registry credentials (source credentials)

Images that are public need no registry credential. For private images, each **source** can carry one registry credential: a username and a token. A source has at most one credential, and there is no hub-wide or namespace-wide credential.

- **ghcr.io:** use a personal access token (classic) with the `read:packages` scope. Dockward rejects a fine-grained token for `ghcr.io` with the message "ghcr.io needs a personal access token (classic) with read:packages."
- **docker.io and custom hubs:** use the username and token that your registry accepts for login, with read access to the repositories you map. The exact token type for docker.io is not checked in this guide; confirm it with Docker Hub before you rely on it.

Dockward encrypts the registry token with AES-256-GCM before storing it and never shows it again. Press **Test** on the credential before you rely on it. A registry that rejects the credential shows "registry rejected the credentials". A rate-limit response shows "registry rate limit reached".

### 3b. Add a source

A **source** is one image to watch. Create one per image (or per tag pattern) on the Sources page:

- **Hub:** `ghcr.io`, `docker.io`, or a custom hub.
- **Repository:** the full repository path, for example `owner/app`. The first segment is the namespace, which the CVE list can filter on.
- **Tag:** an exact tag, or a pattern that uses `*` or `?`.
- **GitHub credential:** the GitHub credential from section 4 that Dockward uses to publish results.
- **GitHub owner and repository:** where the SARIF and issues go.
- **Default branch:** used only when the image has neither the `io.github.nrosier.dockward.branch` label nor the legacy `io.github.nrosier.harborgate.branch` label (default `main`).
- **Auto-create issues:** on or off.
- **Minimum issue severity:** `CRITICAL` (default) or `HIGH`.

A source is unique per hub, repository and tag value. Several sources can publish to one GitHub repository. Each source gets its own Code Scanning category (see section 6), so their alerts stay separate.

Use **Scan now** on a source to queue a scan without waiting for the next discovery pass.

## 4. GitHub Setup

Do these steps once for each repository Dockward will write to.

**GitHub address (optional).** In Admin > Settings > GitHub, leave both fields empty to use github.com. An empty value means github.com, so an existing install needs no change. The setting is for the whole Dockward instance and only an admin can change it.

- **API base URL:** the full API base, as an `https` address. For GitHub Enterprise Server enter the host with `/api/v3`, for example `https://ghes.example.com/api/v3`. For GHE.com enter `https://api.SUBDOMAIN.ghe.com` (no path). It must not contain a user name, password, port, query, or fragment.
- **Web URL:** the host only, for example `https://ghes.example.com`. Dockward uses it to check the `org.opencontainers.image.source` label (see section 6).
- Any other value is refused with the message "Enter an https address with a host, for example https://ghes.example.com." and nothing is saved.
- The addresses are stored in the database (not as secrets) and are shown on this page. Tokens are never shown or logged.

### 4a. Create a fine-grained personal access token

1. In GitHub, go to **Settings > Developer settings > Personal access tokens > Fine-grained tokens** and click **Generate new token** (verified in GitHub's "Managing your personal access tokens"). A pre-filled form with the right permissions: `https://github.com/settings/personal-access-tokens/new?name=Dockward&target_name=<owner>&expires_in=90&security_events=write&issues=write`. You still pick the repositories yourself. Leave out `&issues=write` if issues are not used.
2. **Resource owner:** select the organization or user account that owns the target repository, `<owner>`. A fine-grained token can only access resources owned by its single resource owner.
3. **Repository access:** choose **Only select repositories** and select only the repositories Dockward will write to. Do not choose "All repositories".
4. **Expiration:** set an expiry. Recommended: 90 days, and create a calendar reminder to rotate the token a week before it expires. Non-expiring tokens are allowed by GitHub but are not recommended.

### 4b. Permissions (minimum)

Grant only these repository permissions:

| GitHub permission name | Access | Why it is needed |
| --- | --- | --- |
| Code scanning alerts | Read and write | Upload SARIF (`POST /repos/{owner}/{repo}/code-scanning/sarifs`) and read alerts. URL parameter `security_events`. |
| Issues | Read and write | Create and update issues (`POST /repos/{owner}/{repo}/issues`, `PATCH /repos/{owner}/{repo}/issues/{issue_number}`). Needed for automatic issues and for manual issue creation. |

> **Warning:** without the Issues permission, the GitHub credential test still passes with a warning (`issues_permission_missing`), because SARIF upload does not need Issues. A token without Issues can still sync SARIF but cannot create issues. Saving a source with auto-created issues on is rejected until the token has the Issues permission.

Metadata: read is always included. Do not grant Contents, Administration, Workflows, Actions, or any organization-wide permission.

The target repository must support code scanning: a public repository, or an organization-owned repository on GitHub Team or Enterprise with GitHub Code Security enabled. A private repository owned by a personal account cannot receive SARIF uploads, and Dockward rejects such a source (`code_scanning_unavailable`).

### 4c. Save the token in Dockward

1. Copy the token once when GitHub shows it.
2. Paste it into Dockward's credentials screen (Account > Credentials) as a GitHub credential.
3. Dockward encrypts the token with AES-256-GCM before storing it and never shows it again. If you need it later, you must generate a new one.

### 4d. Enable code scanning on the repository

1. In GitHub, open the repository, go to **Settings**, and check that code scanning is enabled. The **Security** tab should show **Code scanning**.
2. SARIF uploads to a repository without code scanning enabled do not display results. Enable it before the first publish.

## 5. Connect Dockward

These steps are for the first run and for each user. The first local account you create becomes the admin.

1. **First run:** open `https://<your-host>` and create the first local account. That account is the admin.
2. **Registry credential (optional):** for each private image, add the registry credential to its source (section 3a). Press **Test**.
3. **GitHub credential:** add a GitHub credential with the token from section 4. Press **Test**. The test must succeed before you continue. A warning about Issues is acceptable if you do not use issues.
4. **Source:** add one source per image (section 3b), choosing the hub, repository, tag, and GitHub target.
5. **Check the first run:** after the next discovery pass (or **Scan now**), the source's images appear on the Dashboard and Jobs page, and the publish step succeeds. Jobs that fail show their error on the Jobs page and under Admin > Failed.
6. **SARIF category:** Dockward sets the SARIF category to `dockward/<hub host>/<repository>/<tag>/` automatically (`services/sarif.rs`, `automation_id`), so each tag's results stay separate in the Security tab. The tool and driver name are `Dockward`. You do not configure it. Older uploads used the category `harborgate/...`; see section 10.

Each user sees only their own credentials and sources. Admins can view all of them read-only.

## Single sign-on (OIDC), optional

You can sign in to Dockward through an OpenID Connect (OIDC) provider instead of, or as well as, local accounts. This section is optional. Skip it if you use local accounts only.

1. **Register Dockward with your provider.** In your identity provider, create an OIDC client for Dockward. Register this redirect URI:

   ```text
   https://<your-host>/api/v1/auth/oidc/callback
   ```

   Replace `<your-host>` with the host name that users open in the browser. Note the client ID and client secret the provider gives you.

   The client type, grant settings, and steps to create the client differ by provider; follow your provider's documentation. Dockward needs a confidential client with the authorization code flow.

2. **Enter the settings in Dockward.** Sign in as an admin, open **Admin > Settings > OIDC**, and fill in the section:
   - **Issuer URL:** `<issuer-url>`. It must use `https://`.
   - **Client ID:** `<client-id>`.
   - **Client secret:** `<client-secret>`. Dockward stores it encrypted and never shows it again.
   - **Role claim:** the name of the token claim that lists the user's groups (for example `groups`). The claim name depends on your provider.
   - **Admin group:** the group value that gives the `Admin` role.
   - **User group:** the group value that gives the `User` role.

3. **Put users in the groups.** In your provider, add each user to the admin group or the user group. How you add group membership, and how you include the groups claim in the ID token, differ by provider; follow your provider's documentation. A user who is in neither group cannot sign in.

4. **Sign in.** Users open Dockward and choose the OIDC sign-in option. Dockward creates the account on the user's first successful sign-in. The role comes from the group claim, and Dockward checks it again on every sign-in. If you move a user to another group, the new role applies at that user's next sign-in.

Keep at least one local admin account as a break-glass login. Local login stays available for admins if the provider is unavailable or misconfigured.

## 6. OCI Labels on Images

Dockward reads the commit and repository from OCI labels on the image. Add these labels to your image build.

```dockerfile
LABEL org.opencontainers.image.revision="<commit-sha>"
LABEL org.opencontainers.image.source="https://github.com/<owner>/<repo>"
LABEL io.github.nrosier.dockward.branch="<branch>"
```

- `org.opencontainers.image.revision` (required): the full commit SHA. If it is missing, the publish is marked `failed` with a clear error. Dockward does not guess the SHA.
- `org.opencontainers.image.source` (recommended): the repository URL. When present, it must match the source's GitHub target, `https://github.com/<owner>/<repo>` (or `<web URL>/<owner>/<repo>` when a custom web URL is set). The comparison ignores case and a trailing `/` or `.git`. On a mismatch the publish is marked `failed`, and nothing is uploaded. When the label is absent, the publish proceeds.
- `io.github.nrosier.dockward.branch` (optional): the branch name. When present, Dockward uses it as the target branch. When absent, Dockward uses the source's default branch. The legacy label `io.github.nrosier.harborgate.branch` is still read when the new label is absent, and logs a deprecation warning. If both are set, the new label wins. Rename the label in your Dockerfiles. Dockward does not read `org.opencontainers.image.ref.name` for the branch, because the OCI image spec defines that key as the name of a reference, typically a tag, not a branch.

In a CI pipeline you can pass the values at build time, for example `docker build --label org.opencontainers.image.revision=$GIT_SHA ...`. Use placeholders in examples only, and never hardcode a real SHA in the Dockerfile.

## 7. Verify the Setup

Check each item before you rely on the setup:

- [ ] The GitHub test in Dockward is green.
- [ ] A source's image is discovered and its pull, scan and publish jobs show `done` on the Jobs page.
- [ ] The SARIF result appears in the repository's **Security > Code scanning** tab.
- [ ] If auto-issues are on, an issue appears for a `CRITICAL` or `HIGH` finding (based on the severity threshold), and only one open issue exists per CVE per repository.
- [ ] Lower-severity findings do not create issues.

## 8. Rotation and Revocation

### Rotate the registry credential

1. In the registry, create a new token with the same read permission.
2. In Dockward, open the source's credential, paste the new token, and press **Test**.
3. Revoke the old token in the registry.

### Rotate the GitHub token

1. In GitHub, create a new fine-grained token with the same settings from section 4.
2. In Dockward, replace the GitHub credential with the new token and press **Test**.
3. Revoke the old token in GitHub.

### Revoke access

- To stop Dockward from reading a registry, revoke the token in the registry or delete the source's credential.
- To stop Dockward from writing to GitHub, revoke the token in GitHub (**Settings > Developer settings > Personal access tokens**).
- After revocation, new jobs fail. Each failure appears on the Jobs page and under Admin > Failed with the error message. Fix the credential and retry the job, or remove the source.

## Restore from a backup

Restore is a command-line command that runs with Dockward stopped. It is not an HTTP route and not in the admin UI. A backup is made in the admin UI under Admin > Settings > Backup, and is written to `DOCKWARD_BACKUP_DIR` (default `/data/backups`) as `harborgate-<yyyymmddThhmmssZ>.hgbk`. The file name keeps its `harborgate` prefix. Dockward creates that folder at startup (mode 0700) if it does not exist, so you do not create it yourself. If the folder already exists and is not writable, a backup fails with a clear error and Dockward does not change its permissions.

1. **Find the key.** You need the same `DOCKWARD_ENCRYPTION_KEY` that created the backup. After a key rotation, older backups need the old key. A backup made under a different key is rejected.
2. **Stop Dockward.** Stop the app yourself first. The command also checks that port 8080 is free in its own container and prints `stop Dockward before restoring` if it is not. That check cannot see an app running in another container, so do not rely on it.
3. **Run the command** in a one-off container that uses the same data volume and the same environment as the app. For the compose setup:

   ```bash
   docker compose stop dockward
   docker compose run --rm dockward restore /data/backups/harborgate-20260101T030000Z.hgbk
   ```

   The image's entrypoint is the `dockward` binary (`/usr/local/bin/dockward`), so the words after the service name are the subcommand. The command takes the settings from the environment (`DOCKWARD_ENCRYPTION_KEY`, `DOCKWARD_PUBLIC_URL`, `DOCKWARD_DATA_DIR`). It does not bind the port.
4. **What it checks.** It verifies the file's authentication tag first. Then it writes a temporary copy in `DOCKWARD_DATA_DIR`, runs SQLite's `PRAGMA integrity_check` on it, and applies the schema migrations. Only after all of that passes does it replace the live database. If any step fails, the command exits with code 1, prints the reason, and the live database is unchanged.
5. **Check the result.** The command appends one `restore.run` entry to the audit log with actor `cli`, the backup file name, and the backup's creation time. The creation time comes from the file name; if the file was renamed, it comes from the file's modification time. Start Dockward again and look for the entry in the Admin audit log.

Restored sessions and jobs are those in the backup. Credentials in the backup open only with the key that created it.

## Key rotation

Rotation replaces `DOCKWARD_ENCRYPTION_KEY` with a new key and re-encrypts every stored secret under it: registry and GitHub credentials, the OIDC client secret, and the alert channel settings. It is a command-line command (`dockward rotate-key`) that runs with Dockward stopped. It is not an HTTP route and not in the admin UI.

Do the steps in this order. The backup needs the app running; the rotation needs it stopped.

1. **Use the same image version as the app.** The command never migrates the database, so a failed run leaves it exactly as it was. Run it with the same Dockward image version the app runs, and only after the app has started at least once on that version, so its migrations are already applied. To upgrade and rotate, upgrade first, start the app once, then rotate.
2. **Make a backup while the app is running.** Create one in the admin UI (Admin > Settings > Backup). A backup is encrypted with the key that was current when it was made, so keep the old key as long as you keep that backup.
3. **Generate the new key** with `openssl rand -base64 32` and store it in your secrets store.
4. **Stop Dockward.** Stop the app yourself. The command also checks that port 8080 is free in its own container and prints `stop Dockward before rotating the key` if it is not. That check cannot see an app running in another container, so do not rely on it.
5. **Run the command** in a one-off container with the same data volume. Pass the old key as `DOCKWARD_OLD_ENCRYPTION_KEY` and the new key as `DOCKWARD_ENCRYPTION_KEY`. For the compose setup, put the new key in `.env` and export the old key in your shell (for example, read it from your secrets store into the variable). Then pass the variable by name only:

   ```bash
   docker compose stop dockward
   docker compose run --rm -e DOCKWARD_OLD_ENCRYPTION_KEY dockward rotate-key
   ```

   `-e DOCKWARD_OLD_ENCRYPTION_KEY` with no `=value` copies the variable from your shell into the container. Do not write the key itself on the command line (`-e NAME=value`): it would be visible in the process list, your shell history, and `docker inspect`. The command takes the other settings from the environment (`DOCKWARD_PUBLIC_URL`, `DOCKWARD_DATA_DIR`). It does not bind the port.
6. **What it does.** In one database transaction it decrypts each stored value with the old key and encrypts it with the new key. If any value does not open with the old key, or the two keys are the same, the command exits with code 1, prints the reason, and the database is unchanged. On success it prints only the number of values it re-encrypted, and it appends one `key.rotate` entry to the audit log with actor `cli` and that count. The command never prints a key. A count of 0 means nothing was stored to re-encrypt. In that case the command cannot tell whether the old key was the right one.
7. **Start Dockward** with `DOCKWARD_ENCRYPTION_KEY` set to the new key, and remove `DOCKWARD_OLD_ENCRYPTION_KEY` from the environment (`unset DOCKWARD_OLD_ENCRYPTION_KEY` in your shell). Sessions are signed with a key derived from the encryption key, so users sign in again.
8. **Check the result.** Open the audit log and look for the `key.rotate` entry, then use the test button on one credential.

Backups made before the rotation open only with the old key.

## 9. Troubleshooting

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| Registry rejected the credentials | Wrong or expired registry token | Replace the token in the source's credential and press Test. |
| "ghcr.io needs a personal access token (classic)" | A fine-grained token was used for ghcr.io | Create a classic token with `read:packages` and paste it. |
| 403 from GitHub on SARIF upload | Token is missing the Code scanning alerts permission, or the repository is not selected for the token | Edit the token in GitHub to grant Code scanning alerts (read and write) and select the repository. |
| 404 from GitHub | GitHub repository name or owner is wrong, or the token is not scoped to the repository | Check the source's owner and repo name. Confirm the token's repository access includes the repo. |
| "the image has no org.opencontainers.image.revision label, so the commit is unknown." | The image has no `org.opencontainers.image.revision` label | Add the label at build time (section 6) and rebuild the image. |
| Publish failed: source label mismatch | `org.opencontainers.image.source` does not match the source's GitHub target | Correct the label or the source's owner and repository. |
| `code_scanning_unavailable` | The GitHub repository cannot receive SARIF (for example a private repository on a personal account) | Use a repository that supports code scanning (section 4b). |
| Issue not created | Severity is below the threshold, the CVE is accepted on the source, auto-issues is off, or the GitHub token lacks the Issues permission | Check the source's minimum severity and auto-issues setting. Check the CVE's acceptance status. Check that the token has Issues (read and write). |
| "this database was created by HarborGate and cannot be used by this version" | An old HarborGate database (`repo_mappings` table) is in the data directory | Dockward 0.2 does not migrate HarborGate data. Use a new data directory. |
| Log: "GitHub refused the legacy analysis retirement" | GitHub refused the delete of an old `HarborGate` analysis (401 or 403). The token lacks `repo` (classic) or "Code scanning alerts" write (fine-grained), or the repository is not selected for the token | Grant the scope (section 10, step 5), or remove the old configuration by hand (section 10, step 6). Dockward retries the step on the next publish. |

## 10. Upgrading from HarborGate

This section is for an operator who ran HarborGate before the rename to Dockward. A new install can skip it.

1. **Stop the old HarborGate instance first.** If an old instance still runs, it creates new `harborgate` issues after the re-key, and those issues are not re-keyed. Stop it before you start Dockward.
2. **Start with a fresh database.** The database file is `dockward.db`. Dockward refuses a HarborGate database (a file that holds the `repo_mappings` table) with the message "this database was created by HarborGate and cannot be used by this version". It does not migrate that file, and it does not import anything from `harborgate.db`. Sources, credentials and history from HarborGate are not carried over; create them again in Dockward (sections 3b and 5).
3. **Rename the OCI label in your image builds.** Use `io.github.nrosier.dockward.branch` (section 6). The legacy `io.github.nrosier.harborgate.branch` label is still read when the new label is absent, and Dockward logs a deprecation warning each time it reads the legacy label.
4. **Issue re-key (automatic, once per GitHub repository).** On the next publish to a repository, Dockward runs a one-time re-key of the old HarborGate issues:
   - The label `harborgate` is renamed to `dockward` in one GitHub call, so the rename covers open and closed issues.
   - Only the first line of each OPEN old issue is rewritten, from `<!-- harborgate:<CVE> -->` to `<!-- dockward:<CVE> -->`. Closed issues keep their old marker and are not rewritten.
   - Old issues stay adoptable under either the old label or the old marker, so an existing CVE issue is found and not duplicated.
   - Each write waits one second after the write before it, so the re-key stays under GitHub's secondary rate limits.
   - The re-key runs once per repository. A clean pass is recorded, and later publishes skip it. If it does not finish, the next publish runs it again.
5. **Code Scanning: the new category and tool.** SARIF uploads now use the tool name `Dockward` and the category `dockward/<hub host>/<repository>/<tag>/`. The first upload under the new name creates a new configuration on GitHub. The old `HarborGate` analyses of each published source are then retired automatically:
   - Dismissals are carried over first. For each rule where every old alert is dismissed with the same reason, the matching new open alerts are dismissed with that reason and the old comment. A mixed group (dismissed with different reasons, or with some alerts still open) is NOT carried over. Decide those again in the new alerts.
   - Then the old analyses of exactly the legacy category of that source are deleted, on every branch.
   - The step runs only after the new upload has succeeded. It never fails the publish job.
   - **Deletion on GitHub cannot be undone.** The alert history for the deleted analyses is lost. Dismissals are carried over before the delete, but the old alerts themselves are gone.
   - A delete needs a token scope. A classic personal access token needs the `repo` scope for the delete, or `public_repo` if the repository is public (the SARIF upload still needs `security_events`). A fine-grained token needs the "Code scanning alerts" repository permission with write access. Both are from GitHub's REST docs for "Delete a code scanning analysis from a repository".
   - If GitHub refuses the delete with 401 or 403, the step stops and writes no record. It logs the fixed message "GitHub refused the legacy analysis retirement; remove the GitHub configuration from the tool status page". The next publish tries again.
6. **Old categories of deleted sources are not removed automatically.** The step only covers sources that are still published. For a source you have deleted, remove its old `harborgate/<hub host>/<repository>/<tag>` configuration by hand:
   1. In GitHub, open the repository and click the **Security and quality** tab (or open the dropdown and choose it).
   2. In the left sidebar, click **Code scanning**.
   3. Click **Tool status** in the tools banner.
   4. Under configurations, select the old configuration.
   5. Click the menu at the top right of the page and select **Delete configuration**.
   6. Read the warning about alerts, then click **Delete** to confirm.

   GitHub only lets you remove configurations for the default branch from this page. For other branches, see GitHub's "Resolving code scanning alerts" documentation.
7. **Leftover `harborgate` labels on issues.** A repository that was re-keyed has its `harborgate` label renamed, so none should remain. If the re-key found that a `dockward` label already existed, it kept the old `harborgate` label and labelled the issues instead. In that case you may delete the old `harborgate` label by hand in the repository's labels page.
8. **Backups.** Backups are still written as `harborgate-<yyyymmddThhmmssZ>.hgbk` (section "Restore from a backup").
