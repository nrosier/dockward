import test from "node:test";
import assert from "node:assert/strict";
import { MARKER, summarise, upsertIssue } from "./security-scan-report.mjs";

function sarif(scores) {
  return {
    version: "2.1.0",
    runs: [
      {
        tool: { driver: { rules: scores.map((s, i) => ({ id: `R${i}`, properties: { "security-severity": s } })) } },
        results: scores.map((_, i) => ({ ruleId: `R${i}`, ruleIndex: i })),
      },
    ],
  };
}

function inputs(perInput) {
  const out = [];
  for (const target of ["source", "image"]) {
    for (const engine of ["grype", "trivy"]) {
      out.push({ target, engine, sarif: perInput(target, engine) });
    }
  }
  return out;
}

const clean = () => sarif([]);

function stub(issues = []) {
  const calls = { create: [], update: [], comment: [] };
  const warnings = [];
  const github = {
    paginate: async () => issues,
    rest: {
      issues: {
        listForRepo: () => {},
        create: async (a) => {
          calls.create.push(a);
          return { data: { number: 99 } };
        },
        update: async (a) => {
          calls.update.push(a);
          return {};
        },
        createComment: async (a) => {
          calls.comment.push(a);
          return {};
        },
      },
    },
  };
  const context = { repo: { owner: "o", repo: "r" }, runId: 7, serverUrl: "https://github.com" };
  const core = { warning: (m) => warnings.push(m) };
  return { github, context, core, calls, warnings };
}

const marked = (number, extra = {}) => ({ number, body: `${MARKER}\n\nold`, ...extra });

test("score of exactly 9.0 is Critical, 6.9 is not counted", () => {
  const s = summarise(inputs((t, e) => (t === "source" && e === "grype" ? sarif(["9.0", 6.9, 7.0, "x", 0]) : clean())));
  const row = s.rows.find((r) => r.target === "source" && r.engine === "grype");
  assert.equal(row.critical, 1);
  assert.equal(row.high, 1);
  assert.equal(s.total, 2);
  assert.equal(s.complete, true);
});

test("null input makes the summary incomplete", () => {
  const s = summarise(inputs((t, e) => (t === "image" && e === "trivy" ? null : clean())));
  assert.equal(s.complete, false);
});

test("no findings and no issue: none", async () => {
  const h = stub([]);
  const r = await upsertIssue({ ...h, summary: summarise(inputs(clean)) });
  assert.equal(r.action, "none");
  assert.equal(h.calls.update.length, 0);
});

test("findings and no issue: created", async () => {
  const h = stub([]);
  const r = await upsertIssue({ ...h, summary: summarise(inputs(() => sarif([9.5]))) });
  assert.equal(r.action, "created");
  assert.equal(h.calls.create.length, 1);
  assert.deepEqual(h.calls.create[0].labels, ["security"]);
  assert.ok(h.calls.create[0].body.startsWith(MARKER));
});

test("findings and a marker issue: updated, no create", async () => {
  const h = stub([marked(5)]);
  const r = await upsertIssue({ ...h, summary: summarise(inputs(() => sarif([9.5]))) });
  assert.equal(r.action, "updated");
  assert.equal(h.calls.create.length, 0);
  assert.equal(h.calls.update[0].issue_number, 5);
});

test("two marker issues: lowest number updated, with a warning", async () => {
  const h = stub([marked(8), marked(3)]);
  const r = await upsertIssue({ ...h, summary: summarise(inputs(() => sarif([8.0]))) });
  assert.equal(r.number, 3);
  assert.equal(h.warnings.length, 1);
});

test("a pull request with the marker is ignored", async () => {
  const h = stub([marked(4, { pull_request: {} })]);
  const r = await upsertIssue({ ...h, summary: summarise(inputs(() => sarif([8.0]))) });
  assert.equal(r.action, "created");
});

test("marker must be the first line", async () => {
  const h = stub([{ number: 2, body: `intro\n${MARKER}` }]);
  const r = await upsertIssue({ ...h, summary: summarise(inputs(() => sarif([8.0]))) });
  assert.equal(r.action, "created");
});

test("no findings, one input null, marker issue: none, stays open", async () => {
  const h = stub([marked(5)]);
  const r = await upsertIssue({ ...h, summary: summarise(inputs((t, e) => (t === "source" && e === "grype" ? null : clean()))) });
  assert.equal(r.action, "none");
  assert.equal(h.calls.update.length, 0);
});

test("no findings, complete, marker issue: closed with one comment", async () => {
  const h = stub([marked(5)]);
  const r = await upsertIssue({ ...h, summary: summarise(inputs(clean)) });
  assert.equal(r.action, "closed");
  assert.equal(h.calls.comment.length, 1);
  const last = h.calls.update.at(-1);
  assert.equal(last.state, "closed");
  assert.equal(last.state_reason, "completed");
  assert.ok(h.calls.update[0].body.startsWith(MARKER));
});

test("no findings, complete, no marker issue: no close call", async () => {
  const h = stub([]);
  const r = await upsertIssue({ ...h, summary: summarise(inputs(clean)) });
  assert.equal(r.action, "none");
  assert.equal(h.calls.update.length, 0);
  assert.equal(h.calls.comment.length, 0);
});
