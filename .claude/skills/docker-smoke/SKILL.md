---
name: docker-smoke
description: Build the image (`docker build -t harborgate:latest .` from the repo root), run it with `-p 8080:8080` and a `-v harborgate_data:/data` volume, wait for it to respond, check the health endpoint, then stop and remove the container. Use after Dockerfile or runtime-config changes.
---

# docker-smoke

Smoke-tests the single-container build and runtime.

**Note:** The project has no Cargo or Docker files yet, so this skill is expected to fail with "file not found" (for example `Dockerfile`) until they exist. That is not a failure of the skill.

## Steps

1. Build from the repo root:
   `cd /Users/nrosier/Development/harborgate && docker build -t harborgate:latest .`
2. Start the container with a named volume. Do not pass secrets. Do not set `HARBORGATE_ENCRYPTION_KEY`:
   `docker run -d --name harborgate-smoke -p 8080:8080 -v harborgate_data:/data harborgate:latest`
3. Wait up to 60 seconds for the root URL to respond (any HTTP status below 500 counts as responding):
   `for i in $(seq 1 30); do code=$(curl -s -o /dev/null -w '%{http_code}' http://localhost:8080/); [ "$code" -gt 0 ] && [ "$code" -lt 500 ] && break; sleep 2; done; echo "$code"`
4. Health check. Set the path here, then run:
   `HEALTH_PATH="/healthz"`
   If `HEALTH_PATH` is empty, mark the health check NOT VERIFIED. Otherwise run:
   `curl -s -o /dev/null -w '%{http_code}' "http://localhost:8080${HEALTH_PATH}"`
   Expect `200`.
5. Always clean up, even after a failure:
   `docker logs harborgate-smoke | tail -n 50; docker stop harborgate-smoke; docker rm harborgate-smoke`

## Pass / fail

- PASS: step 1 exits 0, step 2 starts, step 3 gets a response below 500, and step 4 returns 200 (or is explicitly NOT VERIFIED because `HEALTH_PATH` is unset, which must be stated in the report).
- FAIL: build or run error, no response within 60 seconds, a health status other than 200, or a container that exits early (check the logs in step 5).

## Report

- Build result and image ID.
- Response code from step 3, and whether the wait timed out.
- Health result, or NOT VERIFIED with the reason.
- The last 50 log lines, with any secrets redacted, if the container failed.
- Confirm the container was stopped and removed.
