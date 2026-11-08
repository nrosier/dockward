// Opens, updates or closes the single `security` issue for .github/workflows/security-scan.yml.
// Spec: specs/testing-and-ci.md, "Security scanning workflow", "Scheduled issue".
//
// The body holds only counts, fixed text and URLs built from `context`. It never copies
// finding text. Called from actions/github-script with the injected github, context and core.

import { readFile } from "node:fs/promises";
import path from "node:path";

export const MARKER = "<!-- harborgate-ci:security-scan -->";
const TITLE = "Security scan: High or Critical findings";
const LABEL = "security";

const TARGETS = ["source", "image"];
const ENGINES = ["grype", "trivy"];

// CVSS v3.1 qualitative bands: 9.0 to 10.0 Critical, 7.0 to 8.9 High.
function classify(score) {
  const n = typeof score === "number" ? score : typeof score === "string" ? Number(score) : NaN;
  if (!Number.isFinite(n)) return null;
  if (n >= 9.0) return "critical";
  if (n >= 7.0) return "high";
  return null;
}

function countSarif(sarif) {
  let critical = 0;
  let high = 0;
  for (const run of sarif?.runs ?? []) {
    const rules = run?.tool?.driver?.rules ?? [];
    for (const result of run?.results ?? []) {
      let rule;
      const index = result?.ruleIndex ?? result?.rule?.index;
      if (Number.isInteger(index)) rule = rules[index];
      if (rule === undefined && result?.ruleId !== undefined) {
        rule = rules.find((r) => r?.id === result.ruleId);
      }
      const band = classify(rule?.properties?.["security-severity"]);
      if (band === "critical") critical++;
      else if (band === "high") high++;
    }
  }
  return { critical, high };
}

export function summarise(inputs) {
  const rows = [];
  for (const target of TARGETS) {
    for (const engine of ENGINES) {
      const input = inputs.find((i) => i.target === target && i.engine === engine);
      const sarif = input?.sarif ?? null;
      if (sarif === null) {
        rows.push({ target, engine, available: false, critical: 0, high: 0 });
      } else {
        rows.push({ target, engine, available: true, ...countSarif(sarif) });
      }
    }
  }
  const total = rows.reduce((sum, r) => sum + r.critical + r.high, 0);
  const complete = rows.every((r) => r.available);
  return { rows, total, complete };
}

function runInfo(context) {
  const { owner, repo } = context.repo;
  const base = context.serverUrl ?? "https://github.com";
  const runId = context.runId;
  return {
    owner,
    repo,
    runId,
    runUrl: `${base}/${owner}/${repo}/actions/runs/${runId}`,
    scanningUrl: `${base}/${owner}/${repo}/security/code-scanning`,
  };
}

function buildBody(summary, info) {
  const lines = [MARKER, "", "| Target | Engine | Critical | High |", "| --- | --- | --- | --- |"];
  for (const r of summary.rows) {
    if (r.available) lines.push(`| ${r.target} | ${r.engine} | ${r.critical} | ${r.high} |`);
    else lines.push(`| ${r.target} | ${r.engine} | not available (scan failed) | not available (scan failed) |`);
  }
  lines.push("", `Run: [${info.runId}](${info.runUrl})`, "", info.scanningUrl);
  return lines.join("\n");
}

async function findIssues({ github, info }) {
  const items = await github.paginate(github.rest.issues.listForRepo, {
    owner: info.owner,
    repo: info.repo,
    state: "open",
    labels: LABEL,
    per_page: 100,
  });
  return items
    .filter((i) => i.pull_request === undefined || i.pull_request === null)
    .filter((i) => ((i.body ?? "").split(/\r?\n/)[0] ?? "").trim() === MARKER)
    .sort((a, b) => a.number - b.number);
}

export async function upsertIssue({ github, context, core, summary }) {
  const info = runInfo(context);
  const matches = await findIssues({ github, info });
  const existing = matches[0];
  if (matches.length > 1) {
    core.warning(
      `More than one open security-scan issue; using #${existing.number}. Others: ${matches
        .slice(1)
        .map((i) => `#${i.number}`)
        .join(", ")}`,
    );
  }

  if (summary.total > 0) {
    const body = buildBody(summary, info);
    if (existing === undefined) {
      const created = await github.rest.issues.create({
        owner: info.owner,
        repo: info.repo,
        title: TITLE,
        labels: [LABEL],
        body,
      });
      return { action: "created", number: created.data.number };
    }
    await github.rest.issues.update({
      owner: info.owner,
      repo: info.repo,
      issue_number: existing.number,
      body,
    });
    return { action: "updated", number: existing.number };
  }

  if (summary.complete && existing !== undefined) {
    const clear = `No High or Critical findings in [run ${info.runId}](${info.runUrl}).`;
    await github.rest.issues.update({
      owner: info.owner,
      repo: info.repo,
      issue_number: existing.number,
      body: `${MARKER}\n\n${clear}`,
    });
    await github.rest.issues.createComment({
      owner: info.owner,
      repo: info.repo,
      issue_number: existing.number,
      body: `Closed by the scheduled security scan: ${clear}`,
    });
    await github.rest.issues.update({
      owner: info.owner,
      repo: info.repo,
      issue_number: existing.number,
      state: "closed",
      state_reason: "completed",
    });
    return { action: "closed", number: existing.number };
  }

  return { action: "none", number: existing?.number };
}

async function readSarif(file) {
  try {
    return JSON.parse(await readFile(file, "utf8"));
  } catch {
    return null;
  }
}

// Entry point for the workflow: reads <sarifDir>/sarif-<target>/<engine>-results.sarif.
export async function run({ github, context, core, sarifDir }) {
  const inputs = [];
  for (const target of TARGETS) {
    for (const engine of ENGINES) {
      const file = path.join(sarifDir, `sarif-${target}`, `${engine}-results.sarif`);
      inputs.push({ target, engine, sarif: await readSarif(file) });
    }
  }
  const summary = summarise(inputs);
  for (const r of summary.rows) {
    core.info(
      `${r.target}/${r.engine}: ${r.available ? `critical=${r.critical} high=${r.high}` : "not available"}`,
    );
  }
  const result = await upsertIssue({ github, context, core, summary });
  core.info(`Issue action: ${result.action}${result.number ? ` #${result.number}` : ""}`);
  return result;
}
