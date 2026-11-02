---
name: rust-gate
description: In backend/, run `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test`, and grep non-test source for `unwrap()` and `expect(`, reporting any hits. Pass only if all four are clean. Use before reporting any Rust change as done.
---

# rust-gate

Quality gate for Rust changes in `backend/`. All four checks must be clean.

**Note:** The project has no Cargo or Docker files yet, so this skill is expected to fail with "file not found" (for example `backend/Cargo.toml`) until the backend exists. That is not a failure of the skill.

## Steps

Run from `/Users/nrosier/Development/harborgate/backend`. Run every step even if an earlier one fails, so the report is complete.

1. Formatting: `cargo fmt --check`
2. Lints: `cargo clippy --all-targets -- -D warnings`
3. Tests: `cargo test`
4. Panic-prone calls in non-test source:
   `grep -rnE 'unwrap\(\)|expect\(' /Users/nrosier/Development/harborgate/backend/src`
   Any hit inside a `#[cfg(test)]` module or a `tests/` directory is allowed. Judge each hit by reading the surrounding lines. Do not assume.

## Pass / fail

- PASS: steps 1–3 exit 0, and step 4 has no hits outside test code.
- FAIL: any of the above. Also FAIL if step 4 grep exits 0 with a non-test hit.
- Note: grep exits 1 when there are no hits. That is the clean result.

## Report

- Exit code for each of steps 1–3.
- Each step 4 hit as `file:line: text`, marked test or non-test.
- Overall PASS or FAIL. The first failing line in each failed step, verbatim.
