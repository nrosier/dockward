---
name: sqlx-prepare
description: Run SQLx migrations and `cargo sqlx prepare` in backend/, then confirm the offline metadata (backend/.sqlx) is current and included in git-tracked changes. Use after any change to a query or to backend/migrations/.
---

# sqlx-prepare

Refreshes SQLx offline query metadata so `sqlx::query!` builds work without a live database.

**Note:** The project has no Cargo or Docker files yet. Until `backend/Cargo.toml` and `backend/migrations/` exist, this skill is expected to fail with "file not found" (or "No such file or directory"). That is not a failure of the skill.

## Steps

1. Use a throwaway SQLite database outside the repo. Do not put real credentials in it.
   `export DATABASE_URL="sqlite:///tmp/harborgate-sqlx-prepare.db"`
   (Create the file with `touch /tmp/harborgate-sqlx-prepare.db` if the tool requires it.)
2. Apply migrations:
   `cd /Users/nrosier/Development/harborgate/backend && cargo sqlx migrate run`
3. Regenerate offline metadata:
   `cargo sqlx prepare -- --all-targets`
4. Confirm metadata is current:
   `cargo sqlx prepare --check -- --all-targets`
5. Confirm `backend/.sqlx` is visible to git. Read-only checks only; do NOT run `git add`:
   `git -C /Users/nrosier/Development/harborgate status --short backend/.sqlx backend/migrations`
   `git -C /Users/nrosier/Development/harborgate ls-files backend/.sqlx | wc -l`

## Pass / fail

- PASS: steps 2–4 exit 0, and step 5 shows `backend/.sqlx` either as tracked files or as new/modified entries in `git status`. No `.sqlx` file is listed as deleted without a replacement.
- FAIL: any command exits non-zero, `--check` reports stale metadata, or `backend/.sqlx` is missing or untracked and not listed as a change.

## Report

- Each command run and its exit code.
- The `git status` lines for `backend/.sqlx`.
- The `DATABASE_URL` form used, with no credentials.
- Any migration that failed, with its error text.
