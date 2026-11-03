// Keeps issue dependencies consistent across the repository.
//
// Source of truth: the line `**Depends on:** #a, #b` (or `none`) in each issue body.
// Every `#N` on that line is a dependency, so notes on that line must not name other
// issues; put those on a separate line such as `**Conflicts with:**`.
//
// For every open issue that has the line, this script:
//   1. syncs GitHub's native "blocked by" relationships to match the line;
//   2. labels: any dependency open -> `blocked` (and not `ready`);
//      all dependencies closed -> drop `blocked`, add `ready` if the issue has a `## Brief`.
//      Each label move posts a comment naming the dependencies.
// `needs-decision` is never touched. Issues without the line are left alone.
//
// Env: GITHUB_TOKEN, GITHUB_REPOSITORY (owner/name). Pass --dry-run to only print.

const token = process.env.GITHUB_TOKEN;
const repo = process.env.GITHUB_REPOSITORY;
const dryRun = process.argv.includes("--dry-run");
if (!token || !repo) {
  console.error("GITHUB_TOKEN and GITHUB_REPOSITORY are required");
  process.exit(1);
}

const API = `https://api.github.com/repos/${repo}`;

async function gh(method, path, body) {
  const res = await fetch(path.startsWith("http") ? path : `${API}${path}`, {
    method,
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: "application/vnd.github+json",
      "X-GitHub-Api-Version": "2022-11-28",
      "User-Agent": "harborgate-issue-deps",
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (!res.ok) {
    throw new Error(`${method} ${path} -> ${res.status}: ${await res.text()}`);
  }
  return res.status === 204 ? null : res.json();
}

async function paged(path) {
  const out = [];
  for (let page = 1; ; page++) {
    const sep = path.includes("?") ? "&" : "?";
    const batch = await gh("GET", `${path}${sep}per_page=100&page=${page}`);
    out.push(...batch);
    if (batch.length < 100) return out;
  }
}

async function act(description, fn) {
  console.log(`${dryRun ? "[dry-run] " : ""}${description}`);
  if (!dryRun) await fn();
}

export function parseDeps(body, self) {
  const line = (body ?? "").split(/\r?\n/).find((l) => /^\s*\*\*Depends on:\*\*/i.test(l));
  if (line === undefined) return null;
  const nums = [...line.matchAll(/#(\d+)/g)].map((m) => Number(m[1]));
  return [...new Set(nums)].filter((n) => n !== self).sort((a, b) => a - b);
}

const refs = (nums) => nums.map((n) => `#${n}`).join(", ");

async function main() {
  const open = (await paged("/issues?state=open")).filter((i) => !i.pull_request);
  const cache = new Map(open.map((i) => [i.number, i]));
  const issue = async (n) => {
    if (!cache.has(n)) cache.set(n, await gh("GET", `/issues/${n}`));
    return cache.get(n);
  };

  for (const it of open) {
    const deps = parseDeps(it.body, it.number);
    if (deps === null) continue;

    // 1. Native "blocked by" relationships mirror the Depends on line.
    const native = await paged(`/issues/${it.number}/dependencies/blocked_by`);
    const nativeNums = new Set(native.map((d) => d.number));
    for (const n of deps) {
      if (nativeNums.has(n)) continue;
      const dep = await issue(n);
      await act(`#${it.number}: add blocked-by #${n}`, () =>
        gh("POST", `/issues/${it.number}/dependencies/blocked_by`, { issue_id: dep.id }),
      );
    }
    for (const d of native) {
      if (deps.includes(d.number)) continue;
      await act(`#${it.number}: remove blocked-by #${d.number}`, () =>
        gh("DELETE", `/issues/${it.number}/dependencies/blocked_by/${d.id}`),
      );
    }

    // 2. Labels follow the dependency states.
    const labels = new Set(it.labels.map((l) => l.name));
    const openDeps = [];
    for (const n of deps) if ((await issue(n)).state === "open") openDeps.push(n);
    const hasBrief = /^#{1,6}\s*Brief\b/im.test(it.body ?? "");

    if (openDeps.length > 0) {
      const wasReady = labels.has("ready");
      if (!labels.has("blocked")) {
        await act(`#${it.number}: add blocked`, () =>
          gh("POST", `/issues/${it.number}/labels`, { labels: ["blocked"] }),
        );
      }
      if (wasReady) {
        await act(`#${it.number}: remove ready`, () =>
          gh("DELETE", `/issues/${it.number}/labels/ready`),
        );
        await act(`#${it.number}: comment (re-blocked)`, () =>
          gh("POST", `/issues/${it.number}/comments`, {
            body: `Moved back to \`blocked\`: waiting on ${refs(openDeps)}.`,
          }),
        );
      }
    } else if (labels.has("blocked")) {
      await act(`#${it.number}: remove blocked`, () =>
        gh("DELETE", `/issues/${it.number}/labels/blocked`),
      );
      const done = deps.length ? `All dependencies are closed (${refs(deps)}).` : "No dependencies.";
      if (hasBrief && !labels.has("ready")) {
        await act(`#${it.number}: add ready`, () =>
          gh("POST", `/issues/${it.number}/labels`, { labels: ["ready"] }),
        );
        await act(`#${it.number}: comment (released)`, () =>
          gh("POST", `/issues/${it.number}/comments`, { body: `${done} Moved to \`ready\`.` }),
        );
      } else if (!hasBrief) {
        await act(`#${it.number}: comment (needs brief)`, () =>
          gh("POST", `/issues/${it.number}/comments`, {
            body: `${done} Removed \`blocked\`. This issue has no \`## Brief\` yet, so it is not \`ready\`.`,
          }),
        );
      }
    }
  }
}

if (import.meta.url === `file://${process.argv[1]}` || process.argv[1]?.endsWith("issue-deps.mjs")) {
  main().catch((err) => {
    console.error(err.message);
    process.exit(1);
  });
}
