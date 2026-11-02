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

If a webhook is missed, HarborGate also polls every 15 minutes and skips images whose digest was already synced.

## 2. Before You Start

HarborGate needs an encryption key in the environment variable `HARBORGATE_ENCRYPTION_KEY`. This is required.

- The app refuses to start without it. There is no file fallback.
- It encrypts stored credentials (Harbor robot secrets, GitHub tokens) with AES-256-GCM. It also signs session cookies.
- If you lose the key, the stored credentials cannot be recovered. You must re-enter every credential.
- Store the key in a password manager or secrets store. Do not commit it to git or put it in an image.

To generate a random value, run this once and paste the output into your secrets store. The value shown here is only an example of the command, not a key to use:

```bash
openssl rand -base64 32
```

Set the result as `HARBORGATE_ENCRYPTION_KEY` in your deployment environment (for example, a `.env` file that is kept out of git).

## 3. Harbor Setup

Do these steps for each Harbor project that HarborGate will map. Use a project administrator account in Harbor.

### 3a. Create a project-scoped robot account

1. Open the Harbor project `<project>` and go to the robot accounts section (UNVERIFIED: confirm the exact menu path in your Harbor version UI).
2. Create a **project** robot account. Do not create a system robot account, because a system robot can cover multiple projects.
3. Scope it to only the project `<project>`.
4. Grant only the permissions needed to read artifacts and their vulnerability reports:

| Permission (Harbor name) | Why it is needed |
| --- | --- |
| Pull Repository | Pull access to repository artifacts in the project |
| Read Artifact | Read artifact metadata, including the OCI labels |
| List Artifact | List artifacts in a repository |
| Read Artifact Addition | Read the `additions/vulnerabilities` endpoint |
| Read Scan | Read scan report data |

Do not grant any push, delete, or tag-changing permission, and do not grant any project administrator or system administration permission. UNVERIFIED: confirm the exact names of these permissions in the Harbor UI, since this guide only verified the read-side names above.

Verification status:
- The permission names and their mapping to the `artifacts` and `additions/vulnerabilities` endpoints are verified from the Harbor robot account documentation (https://goharbor.io/docs/latest/administration/robot-accounts/), which lists Pull Repository, Read Artifact, List Artifact, Read Artifact Addition, and Read Scan.
- The Harbor UI labels may differ slightly by version. UNVERIFIED: confirm the exact labels in the Harbor UI.
- Project-scoping of a robot account is verified from the same page.

### 3b. Save the robot username and secret

1. After you create the robot account, Harbor shows the username and secret once in the confirmation window. Copy both at this point or export them.
2. Harbor does not store the secret. If you lose it, you can refresh it (which generates a new secret), but you cannot read the old one.
3. The robot username follows the form `robot$<project>+<name>`. UNVERIFIED: the docs confirm the `robot$` prefix and `<prefix><account_name>` format, but the project-level `+` form was not confirmed. Copy the exact username that Harbor displays.
4. Robot accounts expire after 30 days by default (verified). Set the lifespan you want in Harbor's system settings, or plan to rotate the secret before it expires.
5. Store the username and secret in your password manager. You will paste them into HarborGate in section 5.

### 3c. Create the project webhook

1. In Harbor, open the project `<project>`, go to **Webhooks**, and create a new endpoint (requires project administrator rights).
2. Set the notify type to **HTTP**.
3. Select a payload format. Harbor offers `Default` and `CloudEvents` (verified). UNVERIFIED: the project specification does not say which format HarborGate parses. Use the format the HarborGate version you run expects, and confirm it in the HarborGate webhook handler or release notes.
4. Select only the event **Scan completed** (`SCANNING_COMPLETED`). Do not select push, pull, delete, or other events. HarborGate triggers on `SCANNING_COMPLETED` only.
5. Set the endpoint URL to HarborGate's webhook URL:

```text
https://<your-host>/api/v1/webhooks/harbor/<mapping_token>
```

- `<your-host>` is the public hostname of your HarborGate instance. Use HTTPS only.
- `<mapping_token>` is the token shown on the HarborGate mapping screen. You get it in section 5, after you create the mapping. Create the mapping first, then return here.

6. Add a custom auth header to the webhook. The header name and secret value are shown in the HarborGate mapping screen once; copy them into Harbor's auth header field. Harbor sends this header with every notification. Treat it as a secret. UNVERIFIED: confirm in the Harbor UI the exact menu path for the auth header field.

```text
<header-name>: <header-value>
```

7. Leave verify-SSL enabled if HarborGate uses a valid TLS certificate. UNVERIFIED: the Harbor docs say only "Verify Remote Certificate" and do not describe its behavior in detail. Confirm the option in your Harbor UI.
8. Click **Add**.

Treat the webhook URL as a secret. Anyone who has it can trigger a sync for that mapping. Do not paste it into tickets, chat, or screenshots. Do not log it. If it leaks, rotate the mapping (section 8).

### 3d. Enable scanning on the project

1. In Harbor, open the project `<project>` and turn on automatic scanning of images on push. UNVERIFIED: the Harbor docs were not checked for this setting; confirm the label in the Harbor UI.
2. Confirm that the scanner for the project is Trivy, and that a newly pushed image is scanned. Harbor shows scan results on the artifact's vulnerability view. UNVERIFIED: confirm the view name in the Harbor UI.
3. HarborGate only converts Trivy output. Other scanners are not supported (per the project specification).

## 4. GitHub Setup

Do these steps once for each repository HarborGate will write to.

### 4a. Create a fine-grained personal access token

1. In GitHub, go to **Settings > Developer settings > Personal access tokens > Fine-grained tokens** and choose **Generate new token**. UNVERIFIED: confirm the menu path in the GitHub UI.
2. **Resource owner:** select the organization or user account that owns the target repository, `<owner>`. A fine-grained token can only access resources owned by its single resource owner.
3. **Repository access:** choose **Only select repositories** and select only the repositories HarborGate will write to. Do not choose "All repositories".
4. **Expiration:** set an expiry. Recommended: 90 days, and create a calendar reminder to rotate the token a week before it expires. Non-expiring tokens are allowed by GitHub but are not recommended.

### 4b. Permissions (minimum)

Grant only these repository permissions:

| GitHub permission name | Access | Why it is needed | Status |
| --- | --- | --- | --- |
| Contents | Read-only | Read repository contents (`GET /repos/{owner}/{repo}/contents/{path}`) | Verified: "Contents" read maps to that endpoint. |
| Code scanning alerts | Read and write | Upload SARIF (`POST /repos/{owner}/{repo}/code-scanning/sarifs`) and read alerts | Verified: "Code scanning alerts" read/write covers the SARIF upload. The permission-to-scope mapping (`security_events`) is for classic tokens. UNVERIFIED: confirm the fine-grained label in the GitHub UI. |
| Issues | Read and write | Create and update issues (`POST /repos/{owner}/{repo}/issues`, `PATCH /repos/{owner}/{repo}/issues/{issue_number}`) | Verified. Required only if auto-issues or manual issue creation is enabled. |

Do not grant Administration, Workflows, Actions, or any organization-wide permission.

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
4. **Repository mapping:** create one mapping per Harbor repository (one image name within a project), not one mapping for a whole project. Each mapping has its own webhook URL. Each GitHub repository and branch can be the target of only one mapping. HarborGate rejects a second mapping for the same target. Create a mapping with these settings:
   - Harbor credential and GitHub credential: select the ones you added in steps 2 and 3
   - Harbor project: `<project>`
   - Harbor repository: `<harbor-repository>` (the image name within the project; UNVERIFIED: confirm how Harbor displays this name in your version UI)
   - GitHub repository: `<repo>` (the GitHub repository)
   - GitHub owner: `<owner>`
   - Default branch: used only when the image has no `org.opencontainers.image.ref.name` label (default `main`)
   - Auto-create issues: on or off
   - Minimum issue severity: `CRITICAL` (default) or `HIGH`
5. **Copy the webhook URL:** after you save the mapping, copy the webhook URL shown for it. Paste it into the Harbor project webhook from section 3c, replacing `<mapping_token>`.
6. **SARIF category:** HarborGate sets the SARIF category to the Harbor repository name automatically, so each image's results stay separate in the Security tab. You do not configure the category.

Each user sees only their own credentials and mappings. Admins can view all of them read-only.

## 6. OCI Labels on Images

HarborGate reads the commit and repository from OCI labels on the Harbor artifact. Add these labels to your image build.

```dockerfile
LABEL org.opencontainers.image.revision="<commit-sha>"
LABEL org.opencontainers.image.source="https://github.com/<owner>/<repo>"
LABEL org.opencontainers.image.ref.name="<branch>"
```

- `org.opencontainers.image.revision` (required): the full commit SHA. If it is missing, the sync is marked `failed` with a clear error. HarborGate does not guess the SHA.
- `org.opencontainers.image.source` (recommended): the repository URL.
- `org.opencontainers.image.ref.name` (optional): the branch name. When present, HarborGate uses it as the target branch. When absent, HarborGate uses the mapping's `default_branch`.

In a CI pipeline you can pass the values at build time, for example `docker build --label org.opencontainers.image.revision=$GIT_SHA ...`. Use placeholders in examples only, and never hardcode a real SHA in the Dockerfile.

## 7. Verify the Setup

Check each item before you rely on the setup:

- [ ] The Harbor test in HarborGate is green.
- [ ] The GitHub test in HarborGate is green.
- [ ] Pushing a test image to the mapped Harbor project triggers a sync after Harbor finishes its scan. The sync appears in the sync logs with status `success`.
- [ ] The SARIF result appears in the repository's **Security > Code scanning** tab.
- [ ] If auto-issues are on, an issue appears for a `CRITICAL` or `HIGH` finding (based on the severity threshold), and only one open issue exists per CVE per repository.
- [ ] Lower-severity findings do not create issues.

## 8. Rotation and Revocation

### Rotate the Harbor robot secret

1. In Harbor, open the robot account and refresh its secret. Harbor generates a new secret and shows it once.
2. In HarborGate, open the Harbor credential, paste the new secret, and press **Test**.
3. Run one test push to confirm that a sync succeeds.

### Rotate the GitHub token

1. In GitHub, create a new fine-grained token with the same settings from section 4.
2. In HarborGate, replace the GitHub credential with the new token and press **Test**.
3. Revoke the old token in GitHub.

### Revoke access

- To stop HarborGate from reading from Harbor, delete the robot account in Harbor.
- To stop HarborGate from writing to GitHub, revoke the token in GitHub (**Settings > Developer settings > Personal access tokens**).
- After revocation, new syncs fail. Each failure appears in the admin **Failed Syncs** view with the error message. Fix the credential and use the retry action, or remove the mapping.

## 9. Troubleshooting

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| 401 from Harbor | Wrong robot secret, or the robot account has expired (30-day default) | Refresh the robot secret in Harbor, update the credential in HarborGate, and test again. |
| 403 from GitHub on SARIF upload | Token is missing the Code scanning alerts permission, or the repository is not selected for the token | Edit the token in GitHub to grant Code scanning alerts (read and write) and select the repository. |
| 404 from GitHub | GitHub repository name or owner is wrong, or the token is not scoped to the repository | Check the mapping's owner and repo name. Confirm the token's repository access includes the repo. |
| Sync failed: missing SHA label | The image has no `org.opencontainers.image.revision` label | Add the label at build time (section 6) and push the image again. |
| No webhook triggers | Webhook event is not "Scan completed", or the URL token does not match the mapping | Edit the Harbor webhook so it subscribes only to Scan completed, and confirm the URL contains the mapping's token. |
| Issue not created | Severity is below the threshold, the CVE is accepted on the mapping, or auto-issues is off | Check the mapping's minimum severity and auto-issues setting. Check the CVE's acceptance status. |
| Webhook returns 401 or 403 | Auth header missing or wrong | Compare the header name and value in Harbor with the HarborGate mapping screen; rotate the value if it was exposed. |
