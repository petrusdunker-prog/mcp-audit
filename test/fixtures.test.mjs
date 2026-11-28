// Codifies the manual fixture checks run by hand during development into a
// real regression suite. Run with `npm test` (builds first, then runs this
// against dist/). Requires network access for the dependency-check tests
// (they hit OSV.dev for real).
import { test } from "node:test";
import assert from "node:assert/strict";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { auditSource, auditLive } from "../dist/index.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const fixture = (name) => path.join(__dirname, "..", "test-fixtures", name);

function severities(report) {
  return report.findings.map((f) => f.severity);
}

test("auth: stdio-only is info-only (not applicable, not a false positive)", async () => {
  const report = await auditSource(fixture("stdio-only"));
  assert.ok(severities(report).every((s) => s === "info"));
});

test("auth: HTTP with no auth or restriction pattern is flagged high", async () => {
  const report = await auditSource(fixture("http-no-auth"));
  assert.ok(severities(report).includes("high"));
});

test("auth: HTTP with a real auth pattern is not flagged high", async () => {
  const report = await auditSource(fixture("http-with-auth"));
  assert.ok(!severities(report).includes("high"));
});

test("deps: a pinned known-vulnerable package is caught", async () => {
  const report = await auditSource(fixture("vulnerable-deps"));
  assert.ok(report.findings.some((f) => f.id === "deps.vuln.lodash"));
});

test("deps: a clean pinned package produces no vuln finding", async () => {
  const report = await auditSource(fixture("clean-deps"));
  assert.ok(!report.findings.some((f) => f.id.startsWith("deps.vuln.")));
});

test("secrets: a known-format credential is flagged critical", async () => {
  const report = await auditSource(fixture("secret-known"));
  const criticals = report.findings.filter((f) => f.severity === "critical");
  // AWS, GitHub, and private-key — one real-shaped example of each. Slack
  // is tested separately (test/secret-stability.test.mjs), built at
  // runtime rather than committed, since a committed real-shaped Slack
  // token trips GitHub's own push protection.
  assert.equal(criticals.length, 3, "expected all three committed known-format patterns to fire");
});

test("secrets: known-format placeholders/examples are NOT flagged (regression for the AgentValet false positives)", async () => {
  const report = await auditSource(fixture("secret-known-placeholder"));
  const secretFindings = report.findings.filter((f) => f.id.startsWith("secret.") && f.id !== "secret.summary");
  assert.equal(
    secretFindings.length,
    0,
    `expected zero secret findings on pure placeholders/examples, got: ${secretFindings.map((f) => f.title).join(", ")}`
  );
});

test("secrets: a generic credential-sounding literal is flagged medium, not critical", async () => {
  const report = await auditSource(fixture("secret-generic"));
  assert.ok(severities(report).includes("medium"));
  assert.ok(!severities(report).includes("critical"));
});

test("secrets: env-var-only config has no secret findings above info", async () => {
  const report = await auditSource(fixture("secret-clean"));
  const secretFindings = report.findings.filter((f) => f.id.startsWith("secret.") && f.id !== "secret.summary");
  assert.equal(secretFindings.length, 0);
});

test("permissions (live): a narrow name with a mutating description is flagged", async () => {
  const report = await auditLive({
    command: "npx",
    args: ["tsx", fixture("live-permission-mismatch/server.ts")],
  });
  assert.ok(report.findings.some((f) => f.id === "perm.scope-mismatch.get_user_profile"));
  assert.ok(!report.findings.some((f) => f.id === "perm.scope-mismatch.get_status"));
});
