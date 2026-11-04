# HarborGate Setup Guide

This guide explains how an operator configures Harbor, GitHub, and HarborGate so that vulnerability reports flow from Harbor to GitHub Code Scanning and, optionally, to GitHub Issues.

## 1. Overview

HarborGate is a security relay. When Harbor finishes scanning an image, it sends a webhook to HarborGate. HarborGate fetches the vulnerability report for that image from the Harbor REST API, converts the Trivy results to SARIF 2.1.0, and uploads the SARIF to the GitHub code-scanning API for the repository that matches the image. For `CRITICAL` and `HIGH` findings it can also open one GitHub issue per CVE per repository. An issue closes automatically with a comment when no tag of the image still reports the CVE. If any tag still reports it, the issue stays open. If a closed CVE reappears in a later scan, HarborGate reopens the same issue and comments.

The flow is:

```text
Harbor scan completes -> webhook to HarborGate -> Harbor API (vulnerabilities)
  -> Trivy-to-SARIF conversion -> GitHub code-scanning upload -> Security tab
                                                              -> optional issues
```

If a webhook is missed, HarborGate is designed to also poll every 15 minutes and to skip any digest and tag pair that already synced successfully. Polling is not built yet (see the status in [README.md](../README.md)).

## 2. Before You Start

### Prerequisites

- **Docker Engine 25.0 or later.** On Engine 25.0 and later, health checks run every `start_interval` (5 seconds by default) during the healthcheck's `start_period`, so Traefik routes to HarborGate within seconds of start. On an older Engine the first check runs only after the 30-second `interval`, and Traefik does not route to HarborGate until then (see [specs/deployment.md](../specs/deployment.md), Health).
- **A public HTTPS hostname** for HarborGate. You set it as `HARBORGATE_PUBLIC_URL` below.
- **Your reverse proxy addresses**, if Traefik or another proxy sits in front of HarborGate. You set them as `HARBORGATE_TRUSTED_PROXIES` below.

### Encryption key

HarborGate needs an encryption key in the environment variable `HARBORGATE_ENCRYPTION_KEY`. This is required.

- The value is the base64 encoding of exactly 32 random bytes. The app refuses to start if the value is missing or does not decode to 32 bytes.
- It encrypts stored credentials (Harbor robot secrets, GitHub tokens) with AES-256-GCM. It also signs session cookies.
- If you lose the key, the stored credentials cannot be recovered. You must re-enter every credential.
- Store the key in a password manager or secrets store. Do not commit it to git or put it in an image.

To generate a random value, run this once and paste the output into your secrets store. The value shown here is only an example of the command, not a key to use:

```bash
openssl rand -base64 32
```

Set the result as `HARBORGATE_ENCRYPTION_KEY` in your deployment environment (for example, a `.env` file that is kept out of git).

### Public URL and trusted proxies

Set these in the same `.env` file. Both are described in [specs/deployment.md](../specs/deployment.md), Configuration.

- **`HARBORGATE_PUBLIC_URL`** (required). The external origin that users open, for example `https://harborgate.example.com`. It must use `https://`. For local development only, `http://localhost` with any port is also accepted. HarborGate builds the OIDC redirect URI, the webhook URLs it shows, and the login origin check from this value. It never reads the host from the request, so a wrong value breaks sign-in and the webhook URLs. HarborGate refuses to start without it.
- **`HARBORGATE_TRUSTED_PROXIES`** (optional, default empty). A comma-separated list of CIDRs for the reverse proxies whose `X-Forwarded-For` header HarborGate trusts. Write a single address as `/32` (IPv4) or `/128` (IPv6). Each entry must have no host bits set. With the default empty list, HarborGate ignores `X-Forwarded-For`, so every visitor behind a proxy shares one client IP for rate limits. In the reference setup (Cloudflare tunnel, then Traefik), list Traefik's address on the `proxy` network and the address cloudflared connects to Traefik from.

The addresses differ per host, so follow [specs/deployment.md](../specs/deployment.md), "Client IP behind Cloudflare and Traefik", to find them and to set Traefik's `forwardedHeaders.trustedIPs`. Use the narrowest ranges that work. Trusting the whole `proxy` subnet lets any container on that network send its own `X-Forwarded-For`. After you start HarborGate, check Admin > Health: it must show your public IP as the client IP, with source `x-forwarded-for`.

## 3. Harbor Setup

Do these steps for each Harbor project that HarborGate will map. Use a project administrator account in Harbor.

### 3a. Create a project-scoped robot account

1. In Harbor, open **Projects**, choose `<project>`, open the **Robot Accounts** tab, and click **NEW ROBOT ACCOUNT**.
2. Create a **project** robot account. Do not create a system robot account, because a system robot can cover multiple projects.
3. Scope it to only the project `<project>`.
4. Grant only the permissions needed to read artifacts and their vulnerability reports:

| Permission (Harbor name) | Why it is needed |
| --- | --- |
| Artifact: List | List artifacts in a repository (`GET .../repositories/{repository}/artifacts`) |
| Artifact: Read | Read one artifact, including its OCI labels and scan overview |
| Artifact Addition: Read | Read the vulnerability report (`GET .../artifacts/{reference}/additions/vulnerabilities`) |

In the robot's permission list these appear as the resources **Artifact** and **Artifact Addition**, with the actions **List** and **Read**. Do not grant anything else: no Repository Pull or Push, no Scan, no create, delete, or tag permissions, and no project or system administration.

Verification status (2026-11-03):
- Each endpoint's permission check was read in the Harbor source (`src/server/v2.0/handler/artifact.go`): listing artifacts needs Artifact List, reading an artifact needs Artifact Read, and the vulnerabilities addition needs Artifact Addition Read. The scan overview comes with the artifact read, so Scan Read is not needed. HarborGate never pulls an image, so Repository Pull is not needed.
- The UI labels (Robot Accounts, NEW ROBOT ACCOUNT, Artifact, Artifact Addition, List, Read) come from Harbor's English string catalog (`src/portal/src/i18n/lang/en-us-lang.json`) on the `main` branch. An older Harbor release can word them slightly differently.

### 3b. Save the robot username and secret

1. After you create the robot account, Harbor shows the username and secret once in the confirmation window. Copy both at this point or export them.
2. Harbor does not store the secret. If you lose it, you can refresh it (which generates a new secret), but you cannot read the old one.
3. The robot username has the form `robot$<project>+<name>`. Verified in the Harbor source (`src/controller/robot/controller.go`): a project robot is named `<prefix><project>+<name>`, and the prefix defaults to `robot$`. An administrator can change the prefix, so copy the exact username Harbor shows.
4. Robot accounts expire after 30 days by default (verified). Set the lifespan you want in Harbor's system settings, or plan to rotate the secret before it expires.
5. Store the username and secret in your password manager. You will paste them into HarborGate in section 5.

### 3c. Create the project webhook

Harbor webhooks are configured per project, so one webhook sends HarborGate the scan events of every repository in the project. HarborGate ignores events for repositories that have no mapping, and it ignores untagged pushes (an image pushed by digest only, with no tag). Only tagged events from a mapped repository are synced.

1. In Harbor, open the project `<project>`, go to **Webhooks**, and create a new endpoint (requires project administrator rights).
2. Set the notify type to **HTTP**.
3. Select a payload format. Harbor offers `Default` and `CloudEvents` (verified). HarborGate accepts both formats (see [specs/integrations.md](../specs/integrations.md)).
4. Select only the event **Scan completed** (`SCANNING_COMPLETED`). Do not select push, pull, delete, or other events. HarborGate triggers on `SCANNING_COMPLETED` only.
5. Set the endpoint URL to HarborGate's webhook URL:

```text
https://<your-host>/api/v1/webhooks/harbor/<mapping_token>
```

- `<your-host>` is the public hostname of your HarborGate instance. Use HTTPS only. HarborGate builds this URL from `HARBORGATE_PUBLIC_URL`, so the hostname here must match it.
- `<mapping_token>` is the webhook token shown in the HarborGate mapping screen. You get it in section 5, after you create the mapping. Create the mapping first, then return here.

6. Set the auth header on the webhook. In Harbor's webhook settings, set the **Auth Header** field to `Bearer <webhook-secret>`. Use the secret value shown once in the HarborGate mapping screen. Harbor sends this value as the `Authorization` header with every notification, and HarborGate checks it. Treat it as a secret. The field is labelled **Auth Header** in the Add Webhook form (verified in Harbor's string catalog).

```text
Auth Header: Bearer <webhook-secret>
```

7. Leave **Verify Remote Certificate** checked. Harbor's tooltip: "Determine whether the webhook should verify the certificate of a remote URL. Uncheck this box when the remote URL uses a self-signed or untrusted certificate." HarborGate behind Traefik has a valid certificate, so never uncheck it.
8. Click **Add**.

HarborGate shows the webhook URL and the auth secret **once**, when you create the mapping and again when you rotate them. HarborGate stores only a digest of each, so it cannot show them again. Copy both before you leave the screen. If you lose one, rotate it (section 8) and update Harbor.

Treat the webhook URL and the auth secret as secrets. Anyone who has the URL can trigger a sync for that mapping. Do not paste them into tickets, chat, or screenshots. Do not log them. If either leaks, rotate it (section 8).

### 3d. Enable scanning on the project

1. In Harbor, open the project `<project>`, go to the **Configuration** tab, and under **Vulnerability scanning** check **Automatically scan images on push**. Save.
2. Confirm that the scanner for the project is Trivy, and that a newly pushed image is scanned. Harbor shows the results on the artifact's **Vulnerabilities** view.
3. HarborGate only converts Trivy output. Other scanners are not supported (per the project specification).

## 4. GitHub Setup

Do these steps once for each repository HarborGate will write to.

### 4a. Create a fine-grained personal access token

1. In GitHub, go to **Settings > Developer settings > Personal access tokens > Fine-grained tokens** and click **Generate new token** (verified in GitHub's "Managing your personal access tokens"). A pre-filled form with the right permissions: `https://github.com/settings/personal-access-tokens/new?name=HarborGate&target_name=<owner>&expires_in=90&security_events=write&issues=write`. You still pick the repositories yourself. Leave out `&issues=write` if issues are not used.
2. **Resource owner:** select the organization or user account that owns the target repository, `<owner>`. A fine-grained token can only access resources owned by its single resource owner.
3. **Repository access:** choose **Only select repositories** and select only the repositories HarborGate will write to. Do not choose "All repositories".
4. **Expiration:** set an expiry. Recommended: 90 days, and create a calendar reminder to rotate the token a week before it expires. Non-expiring tokens are allowed by GitHub but are not recommended.

### 4b. Permissions (minimum)

Grant only these repository permissions:

| GitHub permission name | Access | Why it is needed | Status |
| --- | --- | --- | --- |
| Code scanning alerts | Read and write | Upload SARIF (`POST /repos/{owner}/{repo}/code-scanning/sarifs`) and read alerts | Verified: "Code scanning alerts" read/write covers the SARIF upload. The fine-grained label is "Code scanning alerts", URL parameter `security_events` (verified in GitHub's token pre-fill parameter table). |
| Issues | Read and write | Create and update issues (`POST /repos/{owner}/{repo}/issues`, `PATCH /repos/{owner}/{repo}/issues/{issue_number}`) | Verified. Needed for automatic issues and for manual issue creation. |

> **Warning:** without the Issues permission, the GitHub credential test still passes with a warning (`issues_permission_missing`), because SARIF upload does not need Issues. A token without Issues can still sync SARIF but cannot create issues. Saving a mapping with auto-created issues on is rejected with `422 validation_failed` until the token has the Issues permission.

Metadata: read is always included. Do not grant Contents, Administration, Workflows, Actions, or any organization-wide permission.

The target repository must support code scanning: a public repository, or an organization-owned repository on GitHub Team or Enterprise with GitHub Code Security enabled. A private repository owned by a personal account cannot receive SARIF uploads, and HarborGate rejects such a mapping (`code_scanning_unavailable`).

### 4c. Save the token in HarborGate

1. Copy the token once when GitHub shows it.
2. Paste it into HarborGate's credentials screen as a GitHub credential (section 5).
3. HarborGate encrypts the token with AES-256-GCM before storing it and never shows it again. If you need it later, you must generate a new one.

### 4d. Enable code scanning on the repository

1. In GitHub, open the repository, go to **Settings**, and check that code scanning is enabled. The **Security** tab should show **Code scanning**.
2. SARIF uploads to a repository without code scanning enabled do not display results. Enable it before the first sync.

## 5. Connect HarborGate

These steps are for the first run and for each user. The first local account you create becomes the admin.

1. **First run:** open `https://<your-host>` and create the first local account. That account is the admin.
2. **Harbor credential:** on the credentials screen, add a Harbor credential with the Harbor base URL, the robot username from section 3b, and the robot secret. Press **Test**. The test must succeed before you continue.
3. **GitHub credential:** add a GitHub credential with the token from section 4. Press **Test**. The test must succeed before you continue.
4. **Repository mapping:** create one mapping per Harbor repository (one image name within a project), not one mapping for a whole project. Each mapping has its own webhook URL. Each GitHub repository can be the target of only one mapping, regardless of branch. HarborGate rejects a second mapping for the same target. Create a mapping with these settings:
   - Harbor credential and GitHub credential: select the ones you added in steps 2 and 3
   - Harbor project: `<project>`
   - Harbor repository: `<harbor-repository>`, the image name within the project. Harbor's **Repositories** tab shows the full name `<project>/<harbor-repository>` (for example `library/busybox`, the same form as `repo_full_name` in Harbor's webhook payload). Enter only the part after `<project>/`.
   - GitHub repository: `<repo>` (the GitHub repository)
   - GitHub owner: `<owner>`
   - Default branch: used only when the image has no `io.github.nrosier.harborgate.branch` label (default `main`)
   - Auto-create issues: on or off
   - Minimum issue severity: `CRITICAL` (default) or `HIGH`
5. **Copy the webhook URL and auth secret:** after you save the mapping, copy the webhook URL and the auth secret shown for it. They are shown once. Paste the URL into the Harbor project webhook from section 3c, replacing `<mapping_token>`, and paste the secret into the Auth Header.
6. **SARIF category:** HarborGate sets the SARIF run ID to `harborgate/<project>/<harbor-repository>/` automatically. The category is the part before the last `/`, so each image's results stay separate in the Security tab. You do not configure it.

Creating a mapping also checks the GitHub repository. If code scanning is not available for it (for example, a private repository on a personal account), HarborGate rejects the mapping with `422 code_scanning_unavailable`. This shows the problem at setup, not at the first sync.

Each user sees only their own credentials and mappings. Admins can view all of them read-only.

## Single sign-on (OIDC), optional

You can sign in to HarborGate through an OpenID Connect (OIDC) provider instead of, or as well as, local accounts. This section is optional. Skip it if you use local accounts only.

1. **Register HarborGate with your provider.** In your identity provider, create an OIDC client for HarborGate. Register this redirect URI:

   ```text
   https://<your-host>/api/v1/auth/oidc/callback
   ```

   Replace `<your-host>` with the host name that users open in the browser. Note the client ID and client secret the provider gives you.

   The client type, grant settings, and steps to create the client differ by provider; follow your provider's documentation. HarborGate needs a confidential client with the authorization code flow.

2. **Enter the settings in HarborGate.** Sign in as an admin, open **Admin > Settings**, and fill in the OIDC section:
   - **Issuer URL:** `<issuer-url>`. It must use `https://`.
   - **Client ID:** `<client-id>`.
   - **Client secret:** `<client-secret>`. HarborGate stores it encrypted and never shows it again.
   - **Role claim:** the name of the token claim that lists the user's groups (for example `groups`). The claim name depends on your provider.
   - **Admin group:** the group value that gives the `Admin` role.
   - **User group:** the group value that gives the `User` role.

3. **Put users in the groups.** In your provider, add each user to the admin group or the user group. How you add group membership, and how you include the groups claim in the ID token, differ by provider; follow your provider's documentation. A user who is in neither group cannot sign in.

4. **Sign in.** Users open HarborGate and choose the OIDC sign-in option. HarborGate creates the account on the user's first successful sign-in. The role comes from the group claim, and HarborGate checks it again on every sign-in. If you move a user to another group, the new role applies at that user's next sign-in.

Keep at least one local admin account as a break-glass login. Local login stays available for admins if the provider is unavailable or misconfigured.

## 6. OCI Labels on Images

HarborGate reads the commit and repository from OCI labels on the Harbor artifact. Add these labels to your image build.

```dockerfile
LABEL org.opencontainers.image.revision="<commit-sha>"
LABEL org.opencontainers.image.source="https://github.com/<owner>/<repo>"
LABEL io.github.nrosier.harborgate.branch="<branch>"
```

- `org.opencontainers.image.revision` (required): the full commit SHA. If it is missing, the sync is marked `failed` with a clear error. HarborGate does not guess the SHA.
- `org.opencontainers.image.source` (recommended): the repository URL. When present, it must match the mapping's GitHub target, `https://github.com/<owner>/<repo>`. The comparison ignores case and a trailing `/` or `.git`. On a mismatch the sync is marked `failed`, and nothing is uploaded. When the label is absent, the sync proceeds.
- `io.github.nrosier.harborgate.branch` (optional): the branch name. When present, HarborGate uses it as the target branch. When absent, HarborGate uses the mapping's default branch. HarborGate does not read `org.opencontainers.image.ref.name` for the branch, because the OCI image spec defines that key as the name of a reference, typically a tag, not a branch.

In a CI pipeline you can pass the values at build time, for example `docker build --label org.opencontainers.image.revision=$GIT_SHA ...`. Use placeholders in examples only, and never hardcode a real SHA in the Dockerfile.

## 7. Verify the Setup

Check each item before you rely on the setup:

- [ ] The Harbor test in HarborGate is green.
- [ ] The GitHub test in HarborGate is green.
- [ ] Pushing a test image to the mapped Harbor project triggers a sync after Harbor finishes its scan. The sync appears in the sync logs with status `done`.
- [ ] The SARIF result appears in the repository's **Security > Code scanning** tab.
- [ ] If auto-issues are on, an issue appears for a `CRITICAL` or `HIGH` finding (based on the severity threshold), and only one open issue exists per CVE per repository.
- [ ] Lower-severity findings do not create issues.

## 8. Rotation and Revocation

### Rotate the Harbor robot secret

1. In Harbor, open the robot account and refresh its secret. Harbor generates a new secret and shows it once.
2. In HarborGate, open the Harbor credential, paste the new secret, and press **Test**.
3. Run one test push to confirm that a sync succeeds.

### Rotate the webhook URL or the auth secret

1. In HarborGate, open the mapping and choose **Rotate webhook URL** or **Rotate auth secret**. Confirm the dialog.
2. HarborGate shows the new value once. Copy it before you leave the screen.
3. In Harbor, update the project webhook: paste the new URL into the endpoint URL, or the new secret into the **Auth Header** as `Bearer <webhook-secret>`.
4. Run one test push. The old value stops working as soon as you rotate it, so a webhook that still uses it returns `401`.

### Rotate the GitHub token

1. In GitHub, create a new fine-grained token with the same settings from section 4.
2. In HarborGate, replace the GitHub credential with the new token and press **Test**.
3. Revoke the old token in GitHub.

### Revoke access

- To stop HarborGate from reading from Harbor, delete the robot account in Harbor.
- To stop HarborGate from writing to GitHub, revoke the token in GitHub (**Settings > Developer settings > Personal access tokens**).
- After revocation, new syncs fail. Each failure appears in the admin **Failed syncs** view with the error message. Fix the credential and use the retry action, or remove the mapping.

## Restore from a backup

Restore is a command-line command that runs with HarborGate stopped. It is not an HTTP route and not in the admin UI. A backup is made in the admin UI under Settings > Backup and restore, and is written to `HARBORGATE_BACKUP_DIR` (default `/data/backups`) as `harborgate-<yyyymmddThhmmssZ>.hgbk`.

1. **Find the key.** You need the same `HARBORGATE_ENCRYPTION_KEY` that created the backup. After a key rotation, older backups need the old key. A backup made under a different key is rejected.
2. **Stop HarborGate.** Stop the app yourself first. The command also checks that port 8080 is free in its own container and prints `stop HarborGate before restoring` if it is not. That check cannot see an app running in another container, so do not rely on it.
3. **Run the command** in a one-off container that uses the same data volume and the same environment as the app. For the compose setup:

   ```bash
   docker compose stop harborgate
   docker compose run --rm harborgate restore /data/backups/harborgate-20260101T030000Z.hgbk
   ```

   The image's entrypoint is the `harborgate` binary, so the words after the service name are the subcommand. The command takes the settings from the environment (`HARBORGATE_ENCRYPTION_KEY`, `HARBORGATE_PUBLIC_URL`, `HARBORGATE_DATA_DIR`). It does not bind the port.
4. **What it checks.** It verifies the file's authentication tag first. Then it writes a temporary copy in `HARBORGATE_DATA_DIR`, runs SQLite's `PRAGMA integrity_check` on it, and applies the schema migrations. Only after all of that passes does it replace the live database. If any step fails, the command exits with code 1, prints the reason, and the live database is unchanged.
5. **Check the result.** The command appends one `restore.run` entry to the audit log with actor `cli`, the backup file name, and the backup's creation time. The creation time comes from the file name; if the file was renamed, it comes from the file's modification time. Start HarborGate again and look for the entry in the Admin audit log.

Restored sessions and sync jobs are those in the backup. Credentials in the backup open only with the key that created it.

## 9. Troubleshooting

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| 401 from Harbor | Wrong robot secret, or the robot account has expired (30-day default) | Refresh the robot secret in Harbor, update the credential in HarborGate, and test again. |
| 403 from GitHub on SARIF upload | Token is missing the Code scanning alerts permission, or the repository is not selected for the token | Edit the token in GitHub to grant Code scanning alerts (read and write) and select the repository. |
| 404 from GitHub | GitHub repository name or owner is wrong, or the token is not scoped to the repository | Check the mapping's owner and repo name. Confirm the token's repository access includes the repo. |
| Sync failed: missing SHA label | The image has no `org.opencontainers.image.revision` label | Add the label at build time (section 6) and push the image again. |
| No webhook triggers | Webhook event is not "Scan completed", the webhook token does not match the mapping, or the pushed image has no tag (HarborGate ignores untagged pushes) | Edit the Harbor webhook so it subscribes only to Scan completed, confirm the URL contains the mapping's token, and push the image with a tag. |
| Issue not created | Severity is below the threshold, the CVE is accepted on the mapping, auto-issues is off, or the GitHub token lacks the Issues permission | Check the mapping's minimum severity and auto-issues setting. Check the CVE's acceptance status. Check that the token has Issues (read and write). |
| Webhook returns 401 | Authorization header missing or wrong | Compare the Auth Header value in Harbor (`Bearer <webhook-secret>`) with the HarborGate mapping screen; rotate the value if it was exposed. |
