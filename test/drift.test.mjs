// Unit tests for the diff classification logic itself (step 1 of the
// drift-detection phase) — synthetic reports, not real fixtures, since this
// is purely about diffReports()'s behavior given two finding sets.
import { test } from "node:test";
import assert from "node:assert/strict";
import { diffReports, printDrift, driftToJson } from "../dist/drift.js";

function report(target, mode, findings) {
  return { target, mode, findings };
}

function finding(id, severity, overrides = {}) {
  return { id, severity, title: id, detail: id, ...overrides };
}

test("identical reports produce no drift", () => {
  const a = report("repo", "source", [finding("auth.stdio-only", "info")]);
  const b = report("repo", "source", [finding("auth.stdio-only", "info")]);
  const drift = diffReports(a, b);
  assert.equal(drift.entries.length, 0);
  assert.equal(drift.summary.newCount, 0);
  assert.equal(drift.summary.resolvedCount, 0);
  assert.equal(drift.summary.highestNewSeverity, null);
});

test("a newly-appearing finding is classified new", () => {
  const baseline = report("repo", "source", [finding("deps.vuln.lodash", "high")]);
  const current = report("repo", "source", [
    finding("deps.vuln.lodash", "high"),
    finding("deps.vuln.zod", "critical"),
  ]);
  const drift = diffReports(baseline, current);
  assert.equal(drift.summary.newCount, 1);
  assert.equal(drift.summary.resolvedCount, 0);
  assert.equal(drift.summary.highestNewSeverity, "critical");
  assert.equal(drift.entries[0].status, "new");
  assert.equal(drift.entries[0].finding.id, "deps.vuln.zod");
});

test("a finding that disappears is classified resolved", () => {
  const baseline = report("repo", "source", [
    finding("deps.vuln.lodash", "high"),
    finding("deps.vuln.zod", "critical"),
  ]);
  const current = report("repo", "source", [finding("deps.vuln.lodash", "high")]);
  const drift = diffReports(baseline, current);
  assert.equal(drift.summary.newCount, 0);
  assert.equal(drift.summary.resolvedCount, 1);
  assert.equal(drift.summary.highestNewSeverity, null);
  assert.equal(drift.entries[0].status, "resolved");
  assert.equal(drift.entries[0].finding.id, "deps.vuln.zod");
});

test("auth posture worsening shows as a loud new HIGH plus a quiet resolved INFO", () => {
  const baseline = report("repo", "source", [finding("auth.http-auth-pattern-found", "info")]);
  const current = report("repo", "source", [finding("auth.http-no-auth-pattern", "high")]);
  const drift = diffReports(baseline, current);
  assert.equal(drift.summary.newCount, 1);
  assert.equal(drift.summary.resolvedCount, 1);
  assert.equal(drift.summary.highestNewSeverity, "high");
  // sorted worst-first: the new HIGH finding leads, not the resolved info one
  assert.equal(drift.entries[0].status, "new");
  assert.equal(drift.entries[0].finding.severity, "high");
});

test("a baseline scanned from a different target is still diffed, not rejected", () => {
  const baseline = report("./old-path", "source", [finding("auth.stdio-only", "info")]);
  const current = report("./new-path", "source", [finding("auth.stdio-only", "info")]);
  const drift = diffReports(baseline, current);
  assert.equal(drift.baselineTarget, "./old-path");
  assert.equal(drift.target, "./new-path");
  assert.equal(drift.entries.length, 0);
});

test("printDrift and driftToJson don't throw on empty or populated drift", () => {
  const empty = diffReports(report("r", "source", []), report("r", "source", []));
  const populated = diffReports(
    report("r", "source", [finding("x", "low")]),
    report("r", "source", [finding("y", "critical")])
  );
  assert.doesNotThrow(() => printDrift(empty));
  assert.doesNotThrow(() => printDrift(populated));
  assert.doesNotThrow(() => JSON.parse(driftToJson(populated)));
});
